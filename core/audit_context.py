"""
AWS audit context for managing credentials and sessions.
Enhanced for enterprise environments with cross-account support.
"""

import boto3
import asyncio
import re
import os
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, field
import logging
from .rate_limiter import get_rate_limiter
from .async_client import AsyncClientManager, ClientConfig, configure_default_client

logger = logging.getLogger(__name__)


# SECURITY: Define validation patterns for AWS resources
ARN_PATTERN = re.compile(r'^arn:(aws|aws-cn|aws-us-gov):.*')
ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d{1}$')
PARTITION_PATTERN = re.compile(r'^(aws|aws-cn|aws-us-gov)$')


@dataclass
class AuditContext:
    """Manages AWS credentials, sessions, and audit metadata for enterprise environments."""
    
    # AWS Configuration
    profile_name: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    partition: str = "aws"  # Support for aws-gov, aws-cn
    
    # Enterprise features
    delegated_admin_account: Optional[str] = None
    organization_role_name: Optional[str] = None
    max_concurrent_regions: int = 5
    
    # Scan Configuration
    regions: List[str] = None
    services: List[str] = None
    
    # Rate limiting
    enable_rate_limiting: bool = True
    custom_rate_limits: Dict[str, float] = field(default_factory=dict)
    
    # Audit trail
    audit_enabled: bool = True
    audit_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Internal state
    _session: Optional[boto3.Session] = field(default=None, init=False)
    _account_id: Optional[str] = field(default=None, init=False)
    _async_client_manager: Optional[AsyncClientManager] = field(default=None, init=False)
    _initialized: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Initialize the audit context after dataclass creation."""
        if self.regions is None:
            self.regions = [self.region]
        
        if self.services is None:
            self.services = []
        
        # Validate inputs
        self._validate_configuration()
        
        # Initialize session and async clients
        self._initialize_session()
        self._initialize_async_clients()
        
        self._initialized = True
        logger.info(f"AuditContext initialized for account {self.account_id} in regions {self.regions}")
    
    def _validate_configuration(self):
        """Validate configuration parameters for security."""
        # Validate partition
        if not PARTITION_PATTERN.match(self.partition):
            raise ValueError(f"Invalid partition: {self.partition}")
        
        # Validate role ARN if provided
        if self.role_arn and not ARN_PATTERN.match(self.role_arn):
            raise ValueError(f"Invalid role ARN: {self.role_arn}")
        
        # Validate delegated admin account if provided
        if self.delegated_admin_account and not ACCOUNT_ID_PATTERN.match(self.delegated_admin_account):
            raise ValueError(f"Invalid delegated admin account: {self.delegated_admin_account}")
        
        # Validate regions
        for region in self.regions:
            if not REGION_PATTERN.match(region):
                raise ValueError(f"Invalid region format: {region}")
    
    def _initialize_session(self):
        """Initialize boto3 session with appropriate credentials."""
        try:
            if self.profile_name:
                self._session = boto3.Session(profile_name=self.profile_name)
                logger.info(f"Using AWS profile: {self.profile_name}")
            else:
                self._session = boto3.Session()
                logger.info("Using default AWS credentials")
            
            # Get account ID
            sts_client = self._session.client('sts', region_name=self.region)
            response = sts_client.get_caller_identity()
            self._account_id = response['Account']
            
            # Store audit metadata
            if self.audit_enabled:
                self.audit_metadata.update({
                    'caller_arn': response.get('Arn'),
                    'user_id': response.get('UserId'),
                    'partition': self.partition,
                    'session_initialized': True
                })
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {str(e)}")
            raise
    
    def _initialize_async_clients(self):
        """Initialize async client manager."""
        try:
            # Configure default client settings
            client_config = ClientConfig(
                region_name=self.region,
                retries={'max_attempts': 3, 'mode': 'adaptive'},
                max_pool_connections=50
            )
            
            # Apply custom rate limits
            if self.custom_rate_limits:
                for service, limit in self.custom_rate_limits.items():
                    get_rate_limiter(service, limit)
            
            # Initialize async client manager
            credentials = self._session.get_credentials()
            self._async_client_manager = AsyncClientManager(
                aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key,
                aws_session_token=credentials.token,
                region_name=self.region,
                config=client_config
            )
            
            logger.info("Async client manager initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize async clients: {str(e)}")
            raise
    
    @property
    def session(self) -> boto3.Session:
        """Get the boto3 session."""
        if not self._initialized:
            raise RuntimeError("AuditContext not initialized")
        return self._session
    
    @property
    def account_id(self) -> str:
        """Get the AWS account ID."""
        if not self._initialized:
            raise RuntimeError("AuditContext not initialized")
        return self._account_id
    
    @property
    def async_client_manager(self) -> AsyncClientManager:
        """Get the async client manager."""
        if not self._initialized:
            raise RuntimeError("AuditContext not initialized")
        return self._async_client_manager
    
    def get_client(self, service_name: str, region_name: Optional[str] = None):
        """Get a boto3 client for the specified service."""
        region = region_name or self.region
        return self._session.client(service_name, region_name=region)
    
    async def get_async_client(self, service_name: str, region_name: Optional[str] = None):
        """Get an async client for the specified service."""
        region = region_name or self.region
        return await self._async_client_manager.get_client(service_name, region)
    
    def assume_role(self, role_arn: str, session_name: Optional[str] = None) -> 'AuditContext':
        """Create new audit context with assumed role."""
        if not ARN_PATTERN.match(role_arn):
            raise ValueError(f"Invalid role ARN: {role_arn}")
        
        session_name = session_name or f"aws-security-suite-{self._account_id}"
        
        # Create new context with assumed role
        new_context = AuditContext(
            role_arn=role_arn,
            region=self.region,
            regions=self.regions.copy(),
            services=self.services.copy(),
            partition=self.partition,
            enable_rate_limiting=self.enable_rate_limiting,
            custom_rate_limits=self.custom_rate_limits.copy(),
            audit_enabled=self.audit_enabled
        )
        
        return new_context
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._async_client_manager:
            await self._async_client_manager.close()
