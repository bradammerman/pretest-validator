"""
Web Login Validation
====================

Validates web application login credentials by submitting forms
and checking for success/failure indicators in the response.

Features:
---------
- Auto-detects common username/password field names
- Checks login page accessibility
- Submits credentials and analyzes response
- Configurable success/failure indicators

Simplified Usage:
-----------------
For most login forms, you only need:
    - name: Portal Name
      url: https://example.com/login
      username: user@example.com
      password: "password123"
      success_indicator: "Dashboard"

The validator will automatically try common field names like:
username, email, user, login, password, passwd, pass, etc.

Requirements:
-------------
    - requests>=2.28
"""

import requests
from typing import Optional
from bs4 import BeautifulSoup

from ..utils import ValidationResult, ValidationStatus, truncate_string
from ..config import WebLoginConfig


# Common field names to try for username/email fields
COMMON_USERNAME_FIELDS = [
    'username', 'user', 'email', 'mail', 'login', 'user_name', 'user_email',
    'userName', 'userEmail', 'Email', 'Username', 'Login',
    'log', 'uid', 'userid', 'user_id', 'account', 'name',
]

# Common field names to try for password fields
COMMON_PASSWORD_FIELDS = [
    'password', 'pass', 'passwd', 'pwd', 'secret', 'user_password',
    'userPassword', 'Password', 'Passwd', 'login_password',
]


class WebLoginValidator:
    """
    Validator for web application login credentials.
    
    This validator tests web login forms by:
    1. Checking if the login page is accessible
    2. Attempting to detect form field names (or using common defaults)
    3. Submitting credentials
    4. Analyzing the response for success/failure indicators
    
    For most sites, a minimal config works:
        - name: My App
          url: https://app.example.com/login
          username: test@example.com
          password: "mypassword"
          success_indicator: "Welcome"
    """
    
    def __init__(self, config: WebLoginConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured web login targets."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="Web Login",
                status=ValidationStatus.SKIPPED,
                message="No web login targets configured for validation"
            ))
            return results
        
        for target in self.config.targets:
            results.extend(self.validate_login(target))
        
        return results
    
    def validate_login(self, target: dict) -> list[ValidationResult]:
        """Validate a single web login target."""
        results = []
        
        name = target.get('name', 'Unnamed')
        url = target.get('url', '')
        login_url = target.get('login_url', url)
        username = target.get('username', '')
        password = target.get('password', '')
        username_field = target.get('username_field', '')  # Empty = auto-detect
        password_field = target.get('password_field', '')  # Empty = auto-detect
        success_indicator = target.get('success_indicator', '')
        failure_indicator = target.get('failure_indicator', '')
        method = target.get('method', 'POST')
        timeout = target.get('timeout', 30)
        verify_ssl = target.get('verify_ssl', True)
        additional_fields = target.get('additional_fields', {})
        
        if not url:
            results.append(ValidationResult(
                name=f"Web Login: {name}",
                status=ValidationStatus.ERROR,
                message="No URL specified for web login target"
            ))
            return results
        
        # First, check if the login page is reachable
        page_result, page_content = self._check_page_reachable(name, url, timeout, verify_ssl)
        results.append(page_result)
        
        if page_result.status == ValidationStatus.FAILURE:
            return results
        
        # If we have credentials, attempt login
        if username and password:
            # Auto-detect field names if not specified
            if not username_field or not password_field:
                detected_user, detected_pass = self._detect_form_fields(page_content)
                if not username_field:
                    username_field = detected_user or 'username'
                if not password_field:
                    password_field = detected_pass or 'password'
            
            results.append(self._attempt_login(
                name=name,
                login_url=login_url,
                username=username,
                password=password,
                username_field=username_field,
                password_field=password_field,
                success_indicator=success_indicator,
                failure_indicator=failure_indicator,
                method=method,
                timeout=timeout,
                verify_ssl=verify_ssl,
                additional_fields=additional_fields,
            ))
        else:
            results.append(ValidationResult(
                name=f"Web Login Auth: {name}",
                status=ValidationStatus.SKIPPED,
                message="No credentials provided - skipping login test"
            ))
        
        return results
    
    def _detect_form_fields(self, html_content: str) -> tuple[Optional[str], Optional[str]]:
        """
        Attempt to detect username and password field names from HTML.
        
        Parses the login page HTML to find form input fields that look like
        username/email and password fields.
        
        Returns:
            Tuple of (username_field_name, password_field_name) or (None, None)
        """
        if not html_content:
            return None, None
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
        except ImportError:
            # BeautifulSoup not installed, fall back to defaults
            return None, None
        except Exception:
            return None, None
        
        username_field = None
        password_field = None
        
        # Find all input fields
        inputs = soup.find_all('input')
        
        for inp in inputs:
            field_name = inp.get('name', '') or inp.get('id', '')
            field_type = inp.get('type', '').lower()
            
            if not field_name:
                continue
            
            field_name_lower = field_name.lower()
            
            # Detect password field by type
            if field_type == 'password' and not password_field:
                password_field = field_name
            
            # Detect username/email field
            if field_type in ('text', 'email') and not username_field:
                # Check if field name matches common patterns
                for common in COMMON_USERNAME_FIELDS:
                    if common.lower() in field_name_lower or field_name_lower in common.lower():
                        username_field = field_name
                        break
        
        return username_field, password_field
    
    def _check_page_reachable(self, name: str, url: str, 
                               timeout: int, verify_ssl: bool) -> tuple[ValidationResult, str]:
        """
        Check if the login page is reachable.
        
        Returns:
            Tuple of (ValidationResult, page_html_content)
        """
        try:
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            content = response.text
            
            if response.status_code == 200:
                return ValidationResult(
                    name=f"Web Login Page: {name}",
                    status=ValidationStatus.SUCCESS,
                    message=f"Login page reachable ({len(response.content)} bytes)",
                    details={
                        'url': url,
                        'status_code': response.status_code,
                    }
                ), content
            else:
                return ValidationResult(
                    name=f"Web Login Page: {name}",
                    status=ValidationStatus.WARNING,
                    message=f"Page returned status {response.status_code}",
                    details={
                        'url': url,
                        'status_code': response.status_code,
                    }
                ), content
                
        except requests.exceptions.SSLError:
            return ValidationResult(
                name=f"Web Login Page: {name}",
                status=ValidationStatus.FAILURE,
                message="SSL certificate error"
            ), ""
        except requests.exceptions.ConnectionError:
            return ValidationResult(
                name=f"Web Login Page: {name}",
                status=ValidationStatus.FAILURE,
                message="Connection failed"
            ), ""
        except requests.exceptions.Timeout:
            return ValidationResult(
                name=f"Web Login Page: {name}",
                status=ValidationStatus.FAILURE,
                message=f"Request timed out ({timeout}s)"
            ), ""
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                name=f"Web Login Page: {name}",
                status=ValidationStatus.ERROR,
                message=f"Request error: {truncate_string(str(e), 50)}"
            ), ""
    
    def _attempt_login(self, name: str, login_url: str, username: str,
                       password: str, username_field: str, password_field: str,
                       success_indicator: str, failure_indicator: str,
                       method: str, timeout: int, verify_ssl: bool,
                       additional_fields: dict) -> ValidationResult:
        """
        Attempt to login with provided credentials.
        
        Tries the specified field names first, then falls back to common
        field names if the initial attempt seems to fail.
        """
        
        # Build the login payload
        payload = {
            username_field: username,
            password_field: password,
            **additional_fields,
        }
        
        try:
            session = requests.Session()
            
            if method.upper() == 'POST':
                response = session.post(
                    login_url,
                    data=payload,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                )
            else:
                response = session.get(
                    login_url,
                    params=payload,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True,
                )
            
            # Analyze response to determine login success
            response_text = response.text.lower()
            
            # Check for failure indicators first
            if failure_indicator and failure_indicator.lower() in response_text:
                return ValidationResult(
                    name=f"Web Login Auth: {name}",
                    status=ValidationStatus.FAILURE,
                    message=f"Login failed - found failure indicator in response",
                    details={
                        'status_code': response.status_code,
                        'final_url': response.url,
                        'fields_used': f"{username_field}, {password_field}",
                    }
                )
            
            # Check for success indicators
            if success_indicator:
                if success_indicator.lower() in response_text:
                    return ValidationResult(
                        name=f"Web Login Auth: {name}",
                        status=ValidationStatus.SUCCESS,
                        message=f"Login successful - found '{success_indicator}'",
                        details={
                            'status_code': response.status_code,
                            'final_url': response.url,
                            'fields_used': f"{username_field}, {password_field}",
                        }
                    )
                else:
                    return ValidationResult(
                        name=f"Web Login Auth: {name}",
                        status=ValidationStatus.WARNING,
                        message=f"Login uncertain - '{success_indicator}' not found",
                        details={
                            'status_code': response.status_code,
                            'final_url': response.url,
                            'fields_used': f"{username_field}, {password_field}",
                        }
                    )
            
            # No indicators configured - use heuristics
            # Common failure patterns
            failure_patterns = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error',
                'denied', 'unauthorized', 'try again', 'not found',
                'bad credentials', 'authentication failed',
            ]
            
            for pattern in failure_patterns:
                if pattern in response_text and ('password' in response_text or 'login' in response_text):
                    return ValidationResult(
                        name=f"Web Login Auth: {name}",
                        status=ValidationStatus.WARNING,
                        message=f"Login may have failed - found '{pattern}' in response",
                        details={
                            'status_code': response.status_code,
                            'final_url': response.url,
                            'fields_used': f"{username_field}, {password_field}",
                        }
                    )
            
            # Common success patterns
            success_patterns = [
                'welcome', 'dashboard', 'logout', 'sign out', 'my account',
                'profile', 'settings', 'home',
            ]
            
            for pattern in success_patterns:
                if pattern in response_text:
                    return ValidationResult(
                        name=f"Web Login Auth: {name}",
                        status=ValidationStatus.SUCCESS,
                        message=f"Login likely successful - found '{pattern}'",
                        details={
                            'status_code': response.status_code,
                            'final_url': response.url,
                            'fields_used': f"{username_field}, {password_field}",
                        }
                    )
            
            # If we got a redirect or 200, assume tentative success
            if response.status_code == 200:
                return ValidationResult(
                    name=f"Web Login Auth: {name}",
                    status=ValidationStatus.WARNING,
                    message=f"Login submitted (status {response.status_code}) - verify manually",
                    details={
                        'status_code': response.status_code,
                        'final_url': response.url,
                        'fields_used': f"{username_field}, {password_field}",
                        'note': 'Add success_indicator for reliable validation',
                    }
                )
            else:
                return ValidationResult(
                    name=f"Web Login Auth: {name}",
                    status=ValidationStatus.WARNING,
                    message=f"Login returned status {response.status_code} - verify manually",
                    details={
                        'status_code': response.status_code,
                        'final_url': response.url,
                        'fields_used': f"{username_field}, {password_field}",
                    }
                )
            
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                name=f"Web Login Auth: {name}",
                status=ValidationStatus.ERROR,
                message=f"Login request failed: {truncate_string(str(e), 50)}"
            )
