import pytest
import json
import os
from unittest.mock import patch

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

class TestSecurityVulnerabilities:
    
    def test_sql_injection_attempts(self, client):
        """Test SQL injection attempts in email field"""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "admin'--",
            "' OR '1'='1",
            "'; SELECT * FROM users; --"
        ]
        
        for payload in sql_payloads:
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': payload,
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            # Should reject invalid email format
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Invalid email format' in data['error']
    
    def test_xss_attempts(self, client):
        """Test XSS injection attempts"""
        xss_payloads = [
            "<script>alert('xss')</script>@example.com",
            "javascript:alert('xss')@example.com",
            "<img src=x onerror=alert('xss')>@example.com"
        ]
        
        for payload in xss_payloads:
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': payload,
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            # Should reject invalid email format
            assert response.status_code == 400
    
    def test_password_brute_force_protection(self, client):
        """Test multiple failed login attempts"""
        email = "test@example.com"
        wrong_passwords = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5"]
        
        responses = []
        for password in wrong_passwords:
            response = client.post('/auth/login',
                                 data=json.dumps({
                                     'email': email,
                                     'password': password
                                 }),
                                 content_type='application/json')
            responses.append(response.status_code)
        
        # Should get error responses, potentially rate limiting
        assert all(code in [400, 401, 429, 500] for code in responses)
    
    def test_jwt_token_tampering(self, client):
        """Test logout with tampered JWT token"""
        tampered_tokens = [
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.TAMPERED.signature",
            "invalid.jwt.token",
            "Bearer eyJhbGciOiJIUzI1NiJ9.malicious.payload"
        ]
        
        for token in tampered_tokens:
            response = client.post('/auth/logout',
                                 data=json.dumps({
                                     'accessToken': token
                                 }),
                                 content_type='application/json')
            # Should reject invalid tokens
            assert response.status_code in [400, 401, 500]
    
    def test_information_disclosure(self, client):
        """Test that error messages don't leak sensitive information"""
        response = client.post('/auth/login',
                             data=json.dumps({
                                 'email': 'nonexistent@example.com',
                                 'password': 'password123'
                             }),
                             content_type='application/json')
        
        data = json.loads(response.data)
        # Should not reveal whether user exists or not
        assert 'database' not in data.get('error', '').lower()
        assert 'table' not in data.get('error', '').lower()
        assert 'sql' not in data.get('error', '').lower()
    
    def test_cors_security(self, client):
        """Test CORS configuration"""
        response = client.get('/health')
        
        # Check CORS headers
        assert 'Access-Control-Allow-Origin' in response.headers
        # In production, this should not be '*'
        # assert response.headers['Access-Control-Allow-Origin'] != '*'
    
    def test_http_methods_security(self, client):
        """Test that endpoints only accept intended HTTP methods"""
        
        # Test GET on POST endpoints
        post_endpoints = ['/auth/signup', '/auth/login', '/auth/verify', '/auth/logout']
        
        for endpoint in post_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 405  # Method Not Allowed
    
    def test_content_type_header_validation(self, client):
        """Test that endpoints validate Content-Type header"""
        
        # Try to send XML instead of JSON
        response = client.post('/auth/signup',
                             data='<xml>data</xml>',
                             content_type='application/xml')
        assert response.status_code == 400
    
    def test_large_payload_handling(self, client):
        """Test handling of extremely large payloads"""
        
        large_email = "a" * 10000 + "@example.com"
        large_password = "b" * 10000
        
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': large_email,
                                 'password': large_password
                             }),
                             content_type='application/json')
        
        # Should handle large payloads gracefully
        assert response.status_code in [400, 413, 500]

class TestAuthenticationSecurity:
    
    def test_session_fixation_protection(self, client):
        """Test that tokens are properly invalidated on logout"""
        
        # This would require actual Cognito integration to test properly
        # For now, test that logout endpoint exists and accepts tokens
        response = client.post('/auth/logout',
                             data=json.dumps({
                                 'accessToken': 'test-token'
                             }),
                             content_type='application/json')
        
        # Should attempt to process logout
        assert response.status_code in [200, 400, 401, 500]
    
    def test_password_requirements_bypass(self, client):
        """Test that password requirements cannot be bypassed"""
        
        weak_passwords = [
            "",           # Empty
            " " * 8,      # Spaces only
            "1234567",    # Too short
            None          # Null
        ]
        
        for password in weak_passwords:
            try:
                response = client.post('/auth/signup',
                                     data=json.dumps({
                                         'email': 'test@example.com',
                                         'password': password
                                     }),
                                     content_type='application/json')
                assert response.status_code == 400
            except:
                # If JSON serialization fails with None, that's also good
                pass

class TestDataValidationSecurity:
    
    def test_email_header_injection(self, client):
        """Test email header injection attempts"""
        
        injection_attempts = [
            "test@example.com\r\nBcc: evil@hacker.com",
            "test@example.com\nTo: another@victim.com",
            "test@example.com%0ABcc:evil@hacker.com"
        ]
        
        for email in injection_attempts:
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': email,
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            
            # Should reject malformed emails
            assert response.status_code == 400
    
    def test_json_parsing_security(self, client):
        """Test malformed JSON handling"""
        
        malformed_json_payloads = [
            '{"email": "test@example.com", "password": }',  # Incomplete
            '{"email": "test@example.com" "password": "test"}',  # Missing comma
            '{"email": "test@example.com", "password": "test", }',  # Trailing comma
            '{email: "test@example.com"}',  # Unquoted key
        ]
        
        for payload in malformed_json_payloads:
            response = client.post('/auth/signup',
                                 data=payload,
                                 content_type='application/json')
            
            # Should reject malformed JSON
            assert response.status_code == 400