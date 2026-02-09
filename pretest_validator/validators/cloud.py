"""
Cloud Provider Validation
=========================

Validates cloud provider credentials and connectivity for AWS, Azure, and GCP.

Features:
---------
- AWS: Validates credentials using STS GetCallerIdentity
- Azure: Validates service principal or CLI credentials
- GCP: Validates service account or application default credentials

Simplified Usage:
-----------------
    cloud:
      targets:
        - name: AWS Production
          provider: aws
          access_key_id: AKIA...
          secret_access_key: ...
          region: us-east-1

        - name: Azure Subscription
          provider: azure
          tenant_id: ...
          client_id: ...
          client_secret: ...

        - name: GCP Project
          provider: gcp
          service_account_file: ~/keys/gcp-sa.json

Requirements:
-------------
    - boto3 (for AWS)
    - azure-identity, azure-mgmt-resource (for Azure)
    - google-auth, google-cloud-storage (for GCP)
    
Note: Cloud SDK packages are optional - the validator will skip
providers whose SDKs are not installed.
"""

import os
from typing import Optional

from ..utils import ValidationResult, ValidationStatus, truncate_string
from ..config import CloudConfig


class CloudValidator:
    """
    Validator for cloud provider credentials.
    
    Supports AWS, Azure, and GCP credential validation.
    Cloud SDKs are optional - missing SDKs result in skipped checks.
    """
    
    def __init__(self, config: CloudConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured cloud targets."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="Cloud",
                status=ValidationStatus.SKIPPED,
                message="No cloud targets configured for validation"
            ))
            return results
        
        for target in self.config.targets:
            provider = target.get('provider', '').lower()
            
            if provider == 'aws':
                results.append(self._validate_aws(target))
            elif provider == 'azure':
                results.append(self._validate_azure(target))
            elif provider == 'gcp':
                results.append(self._validate_gcp(target))
            else:
                results.append(ValidationResult(
                    name=f"Cloud: {target.get('name', 'Unknown')}",
                    status=ValidationStatus.ERROR,
                    message=f"Unknown cloud provider: {provider}. Use 'aws', 'azure', or 'gcp'"
                ))
        
        return results
    
    def _validate_aws(self, target: dict) -> ValidationResult:
        """
        Validate AWS credentials using STS GetCallerIdentity.
        
        Supports:
        - Explicit access key + secret
        - Profile name
        - Environment variables (default)
        """
        name = target.get('name', 'AWS')
        
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            return ValidationResult(
                name=f"Cloud AWS: {name}",
                status=ValidationStatus.SKIPPED,
                message="boto3 not installed - run: pip install boto3"
            )
        
        try:
            # Build session with provided credentials
            session_kwargs = {}
            
            access_key = target.get('access_key_id')
            secret_key = target.get('secret_access_key')
            session_token = target.get('session_token')
            profile = target.get('profile')
            region = target.get('region', 'us-east-1')
            
            if access_key and secret_key:
                session_kwargs['aws_access_key_id'] = access_key
                session_kwargs['aws_secret_access_key'] = secret_key
                if session_token:
                    session_kwargs['aws_session_token'] = session_token
            
            if profile:
                session_kwargs['profile_name'] = profile
            
            if region:
                session_kwargs['region_name'] = region
            
            session = boto3.Session(**session_kwargs)
            sts = session.client('sts')
            
            # Call GetCallerIdentity to verify credentials
            identity = sts.get_caller_identity()
            
            account_id = identity.get('Account', 'Unknown')
            arn = identity.get('Arn', 'Unknown')
            user_id = identity.get('UserId', 'Unknown')
            
            return ValidationResult(
                name=f"Cloud AWS: {name}",
                status=ValidationStatus.SUCCESS,
                message=f"Authenticated - Account: {account_id}",
                details={
                    'account_id': account_id,
                    'arn': arn,
                    'user_id': user_id,
                    'region': region,
                }
            )
            
        except NoCredentialsError:
            return ValidationResult(
                name=f"Cloud AWS: {name}",
                status=ValidationStatus.FAILURE,
                message="No AWS credentials found"
            )
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            return ValidationResult(
                name=f"Cloud AWS: {name}",
                status=ValidationStatus.FAILURE,
                message=f"AWS error ({error_code}): {truncate_string(error_msg, 50)}"
            )
        except Exception as e:
            return ValidationResult(
                name=f"Cloud AWS: {name}",
                status=ValidationStatus.ERROR,
                message=f"AWS validation error: {truncate_string(str(e), 50)}"
            )
    
    def _validate_azure(self, target: dict) -> ValidationResult:
        """
        Validate Azure credentials.
        
        Supports:
        - Service principal (client_id, client_secret, tenant_id)
        - CLI credentials (default)
        """
        name = target.get('name', 'Azure')
        
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.mgmt.resource import SubscriptionClient
        except ImportError:
            return ValidationResult(
                name=f"Cloud Azure: {name}",
                status=ValidationStatus.SKIPPED,
                message="Azure SDK not installed - run: pip install azure-identity azure-mgmt-resource"
            )
        
        try:
            tenant_id = target.get('tenant_id')
            client_id = target.get('client_id')
            client_secret = target.get('client_secret')
            subscription_id = target.get('subscription_id')
            
            # Use service principal if provided, otherwise default credentials
            if tenant_id and client_id and client_secret:
                credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
            else:
                credential = DefaultAzureCredential()
            
            # List subscriptions to verify credentials
            sub_client = SubscriptionClient(credential)
            subscriptions = list(sub_client.subscriptions.list())
            
            if subscriptions:
                sub_names = [s.display_name for s in subscriptions[:3]]
                sub_ids = [s.subscription_id for s in subscriptions[:3]]
                
                return ValidationResult(
                    name=f"Cloud Azure: {name}",
                    status=ValidationStatus.SUCCESS,
                    message=f"Authenticated - {len(subscriptions)} subscription(s) accessible",
                    details={
                        'subscription_count': len(subscriptions),
                        'subscriptions': sub_names,
                        'subscription_ids': sub_ids,
                    }
                )
            else:
                return ValidationResult(
                    name=f"Cloud Azure: {name}",
                    status=ValidationStatus.WARNING,
                    message="Authenticated but no subscriptions accessible"
                )
                
        except Exception as e:
            error_msg = str(e)
            if 'AADSTS' in error_msg:
                return ValidationResult(
                    name=f"Cloud Azure: {name}",
                    status=ValidationStatus.FAILURE,
                    message=f"Azure auth failed: {truncate_string(error_msg, 60)}"
                )
            return ValidationResult(
                name=f"Cloud Azure: {name}",
                status=ValidationStatus.ERROR,
                message=f"Azure validation error: {truncate_string(error_msg, 50)}"
            )
    
    def _validate_gcp(self, target: dict) -> ValidationResult:
        """
        Validate GCP credentials.
        
        Supports:
        - Service account JSON file
        - Application default credentials
        """
        name = target.get('name', 'GCP')
        
        try:
            from google.oauth2 import service_account
            from google.auth import default as google_default
            from google.auth.transport.requests import Request
            import google.auth
        except ImportError:
            return ValidationResult(
                name=f"Cloud GCP: {name}",
                status=ValidationStatus.SKIPPED,
                message="GCP SDK not installed - run: pip install google-auth google-cloud-storage"
            )
        
        try:
            service_account_file = target.get('service_account_file')
            project_id = target.get('project_id')
            
            if service_account_file:
                # Expand path and load service account
                sa_path = os.path.expanduser(service_account_file)
                
                if not os.path.exists(sa_path):
                    return ValidationResult(
                        name=f"Cloud GCP: {name}",
                        status=ValidationStatus.FAILURE,
                        message=f"Service account file not found: {service_account_file}"
                    )
                
                credentials = service_account.Credentials.from_service_account_file(
                    sa_path,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
                
                # Get project from service account if not specified
                if not project_id:
                    project_id = credentials.project_id
            else:
                # Use application default credentials
                credentials, default_project = google_default(
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
                if not project_id:
                    project_id = default_project
            
            # Refresh credentials to verify they work
            credentials.refresh(Request())
            
            # Get service account email if available
            sa_email = getattr(credentials, 'service_account_email', None)
            
            return ValidationResult(
                name=f"Cloud GCP: {name}",
                status=ValidationStatus.SUCCESS,
                message=f"Authenticated - Project: {project_id or 'default'}",
                details={
                    'project_id': project_id,
                    'service_account': sa_email,
                    'credential_type': type(credentials).__name__,
                }
            )
            
        except google.auth.exceptions.RefreshError as e:
            return ValidationResult(
                name=f"Cloud GCP: {name}",
                status=ValidationStatus.FAILURE,
                message=f"GCP credential refresh failed: {truncate_string(str(e), 50)}"
            )
        except Exception as e:
            return ValidationResult(
                name=f"Cloud GCP: {name}",
                status=ValidationStatus.ERROR,
                message=f"GCP validation error: {truncate_string(str(e), 50)}"
            )
