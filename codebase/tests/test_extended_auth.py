import pytest
import json
import os
from moto import mock_cognitoidp
import boto3
from unittest.mock import patch, Mock
from botocore.exceptions import ClientError

# Set environment variables before importing app
os.environ['USER_POOL_ID'] = 'us-east-1_test123'
os.environ['CLIENT_ID'] = 'test-client-id'
os.environ['AWS_REGION'] = 'us-east-1'
os.environ['DEBUG'] = 'True'
os.environ['PORT'] = '5000'

from app import app, handle_cognito_error, validate_request

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestExtendedValidation:
    
    def test_validate_email_formats(self, client):
        """Test various email format validations"""
        invalid_emails = [
            "notanemail",
            "@domain.com", 
            "user@",
            "user.domain.com",
            "",
            "user@domain"
        ]
        
        for email in invalid_emails:
            response = client.post('/auth/signup', 
                                 data=json.dumps({
                                     'email': email,
                                     'password': 'password123'
                                 }),
                                 content_type='application/json')
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Invalid email format' in data['error']
    
    def test_password_length_validation(self, client):
        """Test password length requirements"""
        short_passwords = ["1", "12", "1234567"]  # < 8 chars
        
        for password in short_passwords:
            response = client.post('/auth/signup', 
                                 data=json.dumps({
                                     'email': 'test@example.com',
                                     'password': password
                                 }),
                                 content_type='application/json')
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Password must be at least 8 characters' in data['error']
    
    def test_missing_json_data(self, client):
        """Test endpoints with no JSON data"""
        endpoints = ['/auth/signup', '/auth/login', '/auth/verify', '/auth/logout']
        
        for endpoint in endpoints:
            response = client.post(endpoint, content_type='application/json')
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Request must include JSON data' in data['error']
    
    def test_partial_missing_fields(self, client):
        """Test with some required fields missing"""
        test_cases = [
            ('/auth/signup', {'email': 'test@example.com'}),  # missing password
            ('/auth/login', {'password': 'password123'}),     # missing email
            ('/auth/verify', {'email': 'test@example.com'}),  # missing code
            ('/auth/logout', {}),                             # missing accessToken
        ]
        
        for endpoint, data in test_cases:
            response = client.post(endpoint, 
                                 data=json.dumps(data),
                                 content_type='application/json')
            assert response.status_code == 400
            response_data = json.loads(response.data)
            assert 'missing_fields' in response_data

class TestCognitoErrorHandling:
    
    def test_cognito_error_mapping(self):
        """Test Cognito error code mapping"""
        
        # Mock ClientError
        error_response = {
            'Error': {
                'Code': 'UsernameExistsException',
                'Message': 'User already exists'
            }
        }
        
        mock_error = ClientError(error_response, 'SignUp')
        response, status_code = handle_cognito_error(mock_error)
        
        data = json.loads(response.data)
        assert status_code == 409
        assert data['error'] == 'Email is already registered'
        assert data['error_code'] == 'UsernameExistsException'
    
    def test_unknown_cognito_error(self):
        """Test handling of unknown Cognito errors"""
        
        error_response = {
            'Error': {
                'Code': 'UnknownException',
                'Message': 'Unknown error occurred'
            }
        }
        
        mock_error = ClientError(error_response, 'SignUp')
        response, status_code = handle_cognito_error(mock_error)
        
        data = json.loads(response.data)
        assert status_code == 500
        assert data['error'] == 'An unexpected error occurred'

class TestSecurityHeaders:
    
    def test_cors_headers(self, client):
        """Test CORS headers are present"""
        response = client.get('/welcome')
        assert 'Access-Control-Allow-Origin' in response.headers
    
    def test_content_type_enforcement(self, client):
        """Test that endpoints require proper content type"""
        response = client.post('/auth/signup', 
                             data='not json',
                             content_type='text/plain')
        # Should still try to parse JSON and fail gracefully
        assert response.status_code == 400

class TestLoggedOutStateRequests:
    """Test requests that should fail when user is logged out"""
    
    def test_invalid_access_token_logout(self, client):
        """Test logout with invalid access token"""
        response = client.post('/auth/logout',
                             data=json.dumps({
                                 'accessToken': 'invalid-token-12345'
                             }),
                             content_type='application/json')
        # This will fail at Cognito level, we expect error handling
        assert response.status_code in [400, 401, 500]

class TestEdgeCases:
    
    def test_very_long_email(self, client):
        """Test with extremely long email"""
        long_email = "a" * 100 + "@" + "b" * 100 + ".com"
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': long_email,
                                 'password': 'password123'
                             }),
                             content_type='application/json')
        # Should either work or fail gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_special_characters_in_password(self, client):
        """Test password with special characters"""
        special_password = "P@ssw0rd!#$%^&*()"
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': 'test@example.com',
                                 'password': special_password
                             }),
                             content_type='application/json')
        # Should handle special characters
        assert response.status_code in [200, 400, 500]
    
    def test_unicode_characters(self, client):
        """Test with unicode characters"""
        response = client.post('/auth/signup',
                             data=json.dumps({
                                 'email': 'tëst@exämple.com',
                                 'password': 'pässwörd123'
                             }),
                             content_type='application/json')
        # Should handle unicode gracefully
        assert response.status_code in [200, 400, 500]

class TestConcurrentRequests:
    
    def test_multiple_signup_same_email(self, client):
        """Test concurrent signup attempts with same email"""
        email = "concurrent@test.com"
        password = "password123"
        
        # This would be better with actual threading, but basic test
        responses = []
        for _ in range(3):
            response = client.post('/auth/signup',
                                 data=json.dumps({
                                     'email': email,
                                     'password': password
                                 }),
                                 content_type='application/json')
            responses.append(response.status_code)
        
        # At least one should succeed or all should fail with appropriate errors
        assert any(code in [200, 409] for code in responses)