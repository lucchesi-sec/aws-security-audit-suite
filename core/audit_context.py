"""
Audit context for AWS Security Suite.
Provides unified AWS credential and session management across all plugins.
"""

import boto3
from typing import Optional, List, Dict, Any
from botocore.client import BaseClient
from botocore.exceptions import ClientError, NoCredentialsError
import logging


class AuditContext:
    """
    Unified context for AWS security auditing across all plugins.
    
    Provides standardized AWS session management, credential handling,
    and region/service configuration for consistent scanning operations.
    """
    
    def __init__(
        self,
        profile_name: Optional[str] = None,
        region: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ):
        """
        Initialize audit context with AWS configuration.
        
        Args:
            profile_name: AWS CLI profile name for authentication
            region: Primary AWS region for operations
            role_arn: IAM role ARN for cross-account access
            external_id: External ID for role assumption
            regions: List of regions to scan (defaults to current region)
            services: List of services to include in scanning
        """
        self.profile_name = profile_name
        self.region = region or 'us-east-1'
        self.role_arn = role_arn
        self.external_id = external_id
        self.regions = regions or [self.region]
        self.services = services or []
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize session and retrieve account information
        self._session = None
        self._account_id = None
        self._initialize_session()
    
    def _initialize_session(self) -> None:
        """
        Initialize AWS session with provided credentials.
        
        Raises:
            NoCredentialsError: If AWS credentials cannot be found
            ClientError: If AWS API calls fail during initialization
        """
        try:
            # Create session with optional profile
            if self.profile_name:
                self._session = boto3.Session(
                    profile_name=self.profile_name,
                    region_name=self.region
                )
            else:
                self._session = boto3.Session(region_name=self.region)
            
            # Test credentials and get account ID
            sts_client = self._session.client('sts')
            
            # If role assumption is required
            if self.role_arn:
                assume_role_kwargs = {
                    'RoleArn': self.role_arn,
                    'RoleSessionName': 'aws-security-suite-scan'
                }
                
                if self.external_id:
                    assume_role_kwargs['ExternalId'] = self.external_id
                
                response = sts_client.assume_role(**assume_role_kwargs)
                credentials = response['Credentials']
                
                # Create new session with assumed role credentials
                self._session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=self.region
                )
                
                # Get account ID from assumed role
                sts_client = self._session.client('sts')
            
            # Get account identity
            identity = sts_client.get_caller_identity()
            self._account_id = identity['Account']
            
            self.logger.info(f"Initialized AWS session for account {self._account_id} in region {self.region}")
            
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Please configure AWS CLI or set environment variables.")
            raise
        except ClientError as e:
            self.logger.error(f"Failed to initialize AWS session: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during session initialization: {e}")
            raise
    
    @property
    def session(self) -> boto3.Session:
        """Get the current AWS session."""
        return self._session
    
    @property
    def account_id(self) -> str:
        """Get the current AWS account ID."""
        return self._account_id
    
    def get_client(self, service_name: str, region: Optional[str] = None) -> BaseClient:
        """
        Get a boto3 client for the specified service.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3', 'iam')
            region: Optional region override
            
        Returns:
            Configured boto3 client for the service
            
        Raises:
            ClientError: If client creation fails
        """
        try:
            client_region = region or self.region
            return self._session.client(service_name, region_name=client_region)
        except Exception as e:
            self.logger.error(f"Failed to create {service_name} client: {e}")
            raise
    
    def get_resource(self, service_name: str, region: Optional[str] = None):
        """
        Get a boto3 resource for the specified service.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3')
            region: Optional region override
            
        Returns:
            Configured boto3 resource for the service
        """
        try:
            resource_region = region or self.region
            return self._session.resource(service_name, region_name=resource_region)
        except Exception as e:
            self.logger.error(f"Failed to create {service_name} resource: {e}")
            raise
    
    def get_available_regions(self, service_name: str) -> List[str]:
        """
        Get list of available regions for a service.
        
        Args:
            service_name: AWS service name
            
        Returns:
            List of region names where the service is available
        """
        try:
            return self._session.get_available_regions(service_name)
        except Exception as e:
            self.logger.warning(f"Could not get available regions for {service_name}: {e}")
            return self.regions
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary for serialization.
        
        Returns:
            Dictionary representation of the audit context
        """
        return {
            'profile_name': self.profile_name,
            'region': self.region,
            'account_id': self.account_id,
            'regions': self.regions,
            'services': self.services,
            'role_arn': self.role_arn,
            'external_id': self.external_id
        }