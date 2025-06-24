import pytest
from unittest.mock import patch
from app import app

@pytest.fixture
def client():
    app.testing = True
    return app.test_client()


### ────────────── SIGNUP TESTS ──────────────

@patch("app.cognito.sign_up")
def test_signup_success(mock_signup, client):
    mock_signup.return_value = {"UserSub": "abc123"}

    response = client.post("/auth/signup", json={
        "email": "test@example.com",
        "password": "StrongPass123"
    })

    assert response.status_code == 200
    assert response.json["userSub"] == "abc123"


@patch("app.cognito.sign_up")
def test_signup_existing_user(mock_signup, client):
    class CustomException(Exception):
        def __init__(self):
            self.response = {
                "Error": {
                    "Code": "UsernameExistsException",
                    "Message": "User already exists"
                }
            }

    mock_signup.side_effect = CustomException()

    response = client.post("/auth/signup", json={
        "email": "exists@example.com",
        "password": "StrongPass123"
    })

    assert response.status_code == 409
    assert response.json["error"] == "Email is already registered"


### ────────────── LOGIN TESTS ──────────────

@patch("app.cognito.initiate_auth")
def test_login_success(mock_auth, client):
    mock_auth.return_value = {
        "AuthenticationResult": {
            "AccessToken": "dummy-token"
        }
    }

    response = client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "StrongPass123"
    })

    assert response.status_code == 200
    assert response.json["tokens"]["AccessToken"] == "dummy-token"


@patch("app.cognito.initiate_auth")
def test_login_failure(mock_auth, client):
    class CustomException(Exception):
        def __init__(self):
            self.response = {
                "Error": {
                    "Code": "UserNotFoundException",
                    "Message": "No such user"
                }
            }

    mock_auth.side_effect = CustomException()

    response = client.post("/auth/login", json={
        "email": "wrong@example.com",
        "password": "WrongPassword123"
    })

    assert response.status_code == 404
    assert response.json["error"] == "Email is not registered"


### ────────────── HEALTH & WELCOME ──────────────

@patch("app.cognito.describe_user_pool")
def test_health_check(mock_describe, client):
    mock_describe.return_value = {}

    response = client.get('/health')
    assert response.status_code == 200
    assert response.json["status"] == "healthy"


def test_welcome(client):
    response = client.get('/welcome')
    assert response.status_code == 200
    assert response.json["message"] == "Welcome"
