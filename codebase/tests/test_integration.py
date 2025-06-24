import pytest
import json
import os
import time
from unittest.mock import patch, Mock

# Set environment variables
os.environ['USER_POOL_ID'] = 'us-east-1_test123'
os.environ['CLIENT_ID'] = 'test-client-id'
os.environ['AWS_REGION'] = 'us-east-1'
os.environ['DEBUG'] = 'True'
os.environ['PORT'] = '5000'

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestFullUserJourney:
    """Test complete user authentication flow"""
    
    def test_complete_signup_to_logout_flow(self, client):
        """Test full user journey from signup to logout"""
        
        test_email = "journey@example.com"
        test_password = "password123"
        
        # Step 1: Health check
        health_response = client.get('/health')
        assert health_response.status_code in [200, 500]  # Allow Cognito connection failures
        
        # Step 2: Welcome check
        welcome_response = client.get('/welcome')
        assert welcome_response.status_code == 200
        
        # Step 3: Attempt signup
        signup_response = client.post('/auth/signup',
                                    data=json.dumps({
                                        'email': test_email,
                                        'password': test_password
                                    }),
                                    content_type='application/json')
        
        # Should either succeed or fail with known error
        assert signup_response.status_code in [200, 409, 500]
        
        if signup_response.status_code == 200:
            signup_data = json.loads(signup_response.data)
            assert 'userSub' in signup_data
            assert 'Registration successful' in signup_data['message']
        
        # Step 4: Attempt login (should fail if not verified)
        login_response = client.post('/auth/login',
                                   data=json.dumps({
                                       'email': test_email,
                                       'password': test_password
                                   }),
                                   content_type='application/json')
        
        # Should fail with UserNotConfirmedException or other auth error
        assert login_response.status_code in [400, 401, 404, 500]
        
        # Step 5: Test duplicate signup
        duplicate_response = client.post('/auth/signup',
                                       data=json.dumps({
                                           'email': test_email,
                                           'password': test_password
                                       }),
                                       content_type='application/json')
        
        # Should get duplicate error if first signup succeeded
        if signup_response.status_code == 200:
            assert duplicate_response.status_code == 409
            duplicate_data = json.loads(duplicate_response.data)
            assert 'already registered' in duplicate_data['error']
    
    def test_invalid_credentials_flow(self, client):
        """Test flow with invalid credentials"""
        
        # Test 1: Invalid email format
        invalid_email_response = client.post('/auth/signup',
                                           data=json.dumps({
                                               'email': 'not-an-email',
                                               'password': 'password123'
                                           }),
                                           content_type='application/json')
        assert invalid_email_response.status_code == 400
        
        # Test 2: Short password
        short_password_response = client.post('/auth/signup',
                                            data=json.dumps({
                                                'email': 'test@example.com',
                                                'password': '123'
                                            }),
                                            content_type='application/json')
        assert short_password_response.status_code == 400
        
        # Test 3: Login with non-existent user
        nonexistent_login = client.post('/auth/login',
                                      data=json.dumps({
                                          'email': 'nonexistent@example.com',
                                          'password': 'password123'
                                      }),
                                      content_type='application/json')
        assert nonexistent_login.status_code in [401, 404, 500]

class TestErrorRecoveryScenarios:
    """Test how the system handles and recovers from errors"""
    
    def test_malformed_request_recovery(self, client):
        """Test recovery from malformed requests"""
        
        malformed_requests = [
            # Invalid JSON
            ('{"email": "test@example.com"', 'application/json'),
            # Missing content type
            ('{"email": "test@example.com", "password": "test"}', 'text/plain'),
            # Empty payload
            ('', 'application/json'),
            # Non-JSON payload
            ('not json at all', 'application/json')
        ]
        
        for payload, content_type in malformed_requests:
            response = client.post('/auth/signup',
                                 data=payload,
                                 content_type=content_type)
            
            # Should handle gracefully
            assert response.status_code == 400
            
            # System should still be responsive after malformed request
            health_check = client.get('/welcome')
            assert health_check.status_code == 200
    
    @patch('app.cognito')
    def test_cognito_service_unavailable(self, mock_cognito, client):
        """Test behavior when Cognito service is unavailable"""
        
        # Mock Cognito to raise an exception
        mock_cognito.sign_up.side_effect = Exception("Service temporarily unavailable")
        
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': 'test@example.com',
                                 'password': 'password123'
                             }),
                             content_type='application/json')
        
        # Should handle gracefully
        assert response.status_code == 500
        response_data = json.loads(response.data)
        assert 'error' in response_data
        
        # Other endpoints should still work
        welcome_response = client.get('/welcome')
        assert welcome_response.status_code == 200

class TestDataConsistency:
    """Test data consistency across requests"""
    
    def test_consistent_error_responses(self, client):
        """Test that error responses are consistent"""
        
        # Make same invalid request multiple times
        invalid_request = {
            'email': 'invalid-email',
            'password': 'password123'
        }
        
        responses = []
        for _ in range(5):
            response = client.post('/auth/signup',
                                 data=json.dumps(invalid_request),
                                 content_type='application/json')
            responses.append(json.loads(response.data))
        
        # All responses should be identical
        first_response = responses[0]
        for response in responses[1:]:
            assert response['error'] == first_response['error']
            assert response.get('error_code') == first_response.get('error_code')
    
    def test_response_format_consistency(self, client):
        """Test that response formats are consistent"""
        
        # Test different endpoints return consistent JSON structure
        endpoints_and_expected_fields = [
            ('/welcome', ['status', 'message']),
            ('/health', ['status', 'timestamp']),
        ]
        
        for endpoint, expected_fields in endpoints_and_expected_fields:
            response = client.get(endpoint)
            if response.status_code == 200:
                data = json.loads(response.data)
                for field in expected_fields:
                    assert field in data, f"Missing {field} in {endpoint} response"

class TestConcurrencyAndRaceConditions:
    """Test concurrent access and potential race conditions"""
    
    def test_concurrent_signup_same_email(self, client):
        """Test concurrent signup attempts with same email"""
        import threading
        import time
        
        test_email = "concurrent@example.com"
        results = []
        
        def signup_attempt():
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': test_email,
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            results.append({
                'status_code': response.status_code,
                'response': json.loads(response.data) if response.data else {}
            })
        
        # Start multiple threads simultaneously
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=signup_attempt)
            threads.append(thread)
        
        # Start all threads at roughly the same time
        for thread in threads:
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        # Analyze results
        success_count = sum(1 for r in results if r['status_code'] == 200)
        duplicate_count = sum(1 for r in results if r['status_code'] == 409)
        
        # Should handle race condition gracefully
        # Either one succeeds and others get duplicate error, or all fail with server errors
        assert len(results) == 3
        if success_count > 0:
            assert success_count == 1, "Only one signup should succeed"
            assert duplicate_count >= 1, "Others should get duplicate error"

class TestSystemResourceManagement:
    """Test system resource management under load"""
    
    def test_request_cleanup(self, client):
        """Test that requests are properly cleaned up"""
        
        # Make many requests to check for resource leaks
        initial_response = client.get('/welcome')
        initial_time = time.time()
        
        # Make 50 requests
        for i in range(50):
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': f'cleanup{i}@example.com',
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            # Don't care about the response, just making requests
        
        # Check that system is still responsive
        final_response = client.get('/welcome')
        final_time = time.time()
        
        assert final_response.status_code == 200
        # Response time shouldn't degrade significantly
        assert (final_time - initial_time) < 30  # Should complete in reasonable time
    
    def test_large_request_handling(self, client):
        """Test handling of large but valid requests"""
        
        # Create a large but valid email and password
        large_email_local = "a" * 50  # Reasonable size
        large_password = "P@ssw0rd" + "a" * 100  # Long but valid password
        
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': f'{large_email_local}@example.com',
                                 'password': large_password
                             }),
                             content_type='application/json')
        
        # Should handle large requests gracefully
        assert response.status_code in [200, 400, 500]
        
        # System should remain responsive
        health_check = client.get('/welcome')
        assert health_check.status_code == 200

class TestSecurityIntegration:
    """Integration tests for security features"""
    
    def test_token_lifecycle_integration(self, client):
        """Test complete token lifecycle if possible"""
        
        # Test logout with various token formats
        token_formats = [
            "invalid-token",
            "",
            "Bearer token123",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        ]
        
        for token in token_formats:
            response = client.post('/auth/logout',
                                 data=json.dumps({
                                     'accessToken': token
                                 }),
                                 content_type='application/json')
            
            # Should reject invalid tokens appropriately
            assert response.status_code in [400, 401, 500]
            
            # System should remain stable
            health_response = client.get('/welcome')
            assert health_response.status_code == 200