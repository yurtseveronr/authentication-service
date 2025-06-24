#!/usr/bin/env python3
"""
Security audit script for Flask Auth Service
Tests various security aspects and vulnerabilities
"""

import requests
import json
import time
import sys
from urllib.parse import urljoin

class SecurityAuditor:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
    
    def log_result(self, test_name, passed, details=""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
        if details:
            print(f"    {details}")
        
        self.results.append({
            'test': test_name,
            'passed': passed,
            'details': details
        })
    
    def test_ssl_redirect(self):
        """Test if HTTP redirects to HTTPS (if applicable)"""
        try:
            if self.base_url.startswith('https://'):
                http_url = self.base_url.replace('https://', 'http://')
                response = requests.get(http_url, allow_redirects=False, timeout=5)
                
                # Should redirect to HTTPS
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if location.startswith('https://'):
                        self.log_result("SSL Redirect", True, "HTTP properly redirects to HTTPS")
                    else:
                        self.log_result("SSL Redirect", False, "HTTP doesn't redirect to HTTPS")
                else:
                    self.log_result("SSL Redirect", False, f"No redirect, status: {response.status_code}")
            else:
                self.log_result("SSL Redirect", False, "Service not using HTTPS")
        except Exception as e:
            self.log_result("SSL Redirect", False, f"Error: {str(e)}")
    
    def test_security_headers(self):
        """Test for important security headers"""
        try:
            url = urljoin(self.base_url, '/welcome')
            response = self.session.get(url)
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,  # Any value is good
                'Content-Security-Policy': None
            }
            
            missing_headers = []
            
            for header, expected_values in security_headers.items():
                header_value = response.headers.get(header)
                
                if header_value is None:
                    missing_headers.append(header)
                elif expected_values and isinstance(expected_values, list):
                    if header_value not in expected_values:
                        missing_headers.append(f"{header} (incorrect value)")
                elif expected_values and header_value != expected_values:
                    missing_headers.append(f"{header} (incorrect value)")
            
            if missing_headers:
                self.log_result("Security Headers", False, f"Missing: {', '.join(missing_headers)}")
            else:
                self.log_result("Security Headers", True, "All important security headers present")
                
        except Exception as e:
            self.log_result("Security Headers", False, f"Error: {str(e)}")
    
    def test_cors_configuration(self):
        """Test CORS configuration"""
        try:
            url = urljoin(self.base_url, '/welcome')
            
            # Test preflight request
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            
            response = self.session.options(url, headers=headers)
            
            cors_origin = response.headers.get('Access-Control-Allow-Origin')
            
            if cors_origin == '*':
                self.log_result("CORS Configuration", False, "Allows all origins (*) - security risk")
            elif cors_origin:
                self.log_result("CORS Configuration", True, f"Restricted CORS: {cors_origin}")
            else:
                self.log_result("CORS Configuration", True, "No CORS headers (restrictive)")
                
        except Exception as e:
            self.log_result("CORS Configuration", False, f"Error: {str(e)}")
    
    def test_information_disclosure(self):
        """Test for information disclosure in error messages"""
        try:
            # Test with malformed JSON
            url = urljoin(self.base_url, '/auth/signup')
            
            response = self.session.post(url, 
                                       data='{"malformed": json}',
                                       headers={'Content-Type': 'application/json'})
            
            response_text = response.text.lower()
            
            # Check for sensitive information in error messages
            sensitive_keywords = [
                'traceback', 'stack trace', 'file "/', 'line ',
                'database', 'sql', 'table', 'column',
                'aws_access_key', 'secret', 'password', 'token'
            ]
            
            found_sensitive = [kw for kw in sensitive_keywords if kw in response_text]
            
            if found_sensitive:
                self.log_result("Information Disclosure", False, 
                              f"Sensitive info in errors: {', '.join(found_sensitive)}")
            else:
                self.log_result("Information Disclosure", True, "No sensitive info in error messages")
                
        except Exception as e:
            self.log_result("Information Disclosure", False, f"Error: {str(e)}")
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        try:
            url = urljoin(self.base_url, '/auth/signup')
            
            sql_payloads = [
                "'; DROP TABLE users; --",
                "admin'--",
                "' OR '1'='1",
                "'; SELECT * FROM users; --"
            ]
            
            all_protected = True
            
            for payload in sql_payloads:
                data = {
                    'email': payload,
                    'password': 'password123'
                }
                
                response = self.session.post(url, 
                                           json=data,
                                           headers={'Content-Type': 'application/json'})
                
                # Should reject with 400 (validation error)
                if response.status_code != 400:
                    all_protected = False
                    break
                
                # Should not contain SQL error messages
                if any(term in response.text.lower() for term in ['sql', 'syntax', 'table']):
                    all_protected = False
                    break
            
            if all_protected:
                self.log_result("SQL Injection Protection", True, "All SQL injection attempts blocked")
            else:
                self.log_result("SQL Injection Protection", False, "Potential SQL injection vulnerability")
                
        except Exception as e:
            self.log_result("SQL Injection Protection", False, f"Error: {str(e)}")
    
    def test_xss_protection(self):
        """Test XSS protection"""
        try:
            url = urljoin(self.base_url, '/auth/signup')
            
            xss_payloads = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "';alert('xss');//"
            ]
            
            all_protected = True
            
            for payload in xss_payloads:
                data = {
                    'email': f'{payload}@example.com',
                    'password': 'password123'
                }
                
                response = self.session.post(url, json=data)
                
                # Check if payload is reflected unescaped
                if payload in response.text and '<script>' in response.text:
                    all_protected = False
                    break
            
            if all_protected:
                self.log_result("XSS Protection", True, "XSS payloads properly handled")
            else:
                self.log_result("XSS Protection", False, "Potential XSS vulnerability")
                
        except Exception as e:
            self.log_result("XSS Protection", False, f"Error: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting implementation"""
        try:
            url = urljoin(self.base_url, '/auth/login')
            
            # Make rapid requests
            rate_limited = False
            
            for i in range(15):  # Try 15 rapid requests
                data = {
                    'email': f'ratetest{i}@example.com',
                    'password': 'wrongpassword'
                }
                
                response = self.session.post(url, json=data)
                
                if response.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    break
                
                time.sleep(0.1)  # Small delay
            
            if rate_limited:
                self.log_result("Rate Limiting", True, "Rate limiting is active")
            else:
                self.log_result("Rate Limiting", False, "No rate limiting detected")
                
        except Exception as e:
            self.log_result("Rate Limiting", False, f"Error: {str(e)}")
    
    def test_jwt_token_security(self):
        """Test JWT token handling"""
        try:
            url = urljoin(self.base_url, '/auth/logout')
            
            # Test with malformed JWT tokens
            malformed_tokens = [
                "malformed.jwt.token",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.TAMPERED.signature",
                "",
                "Bearer malformed"
            ]
            
            all_rejected = True
            
            for token in malformed_tokens:
                data = {'accessToken': token}
                
                response = self.session.post(url, json=data)
                
                # Should reject invalid tokens
                if response.status_code not in [400, 401, 500]:
                    all_rejected = False
                    break
            
            if all_rejected:
                self.log_result("JWT Token Security", True, "Invalid tokens properly rejected")
            else:
                self.log_result("JWT Token Security", False, "JWT token validation issue")
                
        except Exception as e:
            self.log_result("JWT Token Security", False, f"Error: {str(e)}")
    
    def run_full_audit(self):
        """Run complete security audit"""
        print("🔒 Security Audit - Flask Auth Service")
        print("=====================================\n")
        
        tests = [
            self.test_ssl_redirect,
            self.test_security_headers,
            self.test_cors_configuration,
            self.test_information_disclosure,
            self.test_sql_injection_protection,
            self.test_xss_protection,
            self.test_rate_limiting,
            self.test_jwt_token_security
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"❌ Error running {test.__name__}: {e}")
        
        # Summary
        print(f"\n{'='*50}")
        print("🔒 SECURITY AUDIT SUMMARY")
        print(f"{'='*50}")
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['passed'])
        
        print(f"📊 Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {total_tests - passed_tests}")
        print(f"📈 Security Score: {(passed_tests/total_tests)*100:.1f}%")
        
        if passed_tests == total_tests:
            print("\n🎉 All security tests passed!")
        else:
            print(f"\n⚠️  {total_tests - passed_tests} security issues found. Please review and fix.")
        
        return passed_tests == total_tests

def main():
    if len(sys.argv) != 2:
        print("Usage: python security_audit.py <base_url>")
        print("Example: python security_audit.py http://98.81.148.178:5001")
        sys.exit(1)
    
    base_url = sys.argv[1]
    auditor = SecurityAuditor(base_url)
    
    success = auditor.run_full_audit()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()