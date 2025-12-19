#!/usr/bin/env python3
"""JWT Authentication for Multi-Tenant Dashboard

Provides JWT token generation and validation with client_id claims
for secure multi-tenant access control.

Usage:
    from jwt_auth import JWTAuth, TokenClaims
    
    # Initialize
    auth = JWTAuth(secret_key="your-secret")
    
    # Generate token for a client
    token = auth.create_token(client_id="acme_corp", role="client")
    
    # Validate and extract claims
    claims = auth.validate_token(token)
    if claims:
        print(f"Client: {claims.client_id}, Role: {claims.role}")
"""

import os
import jwt
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List
from functools import wraps

# Flask imports are optional - only needed when used as decorators
try:
    from flask import request, jsonify, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    request = None
    jsonify = None
    g = None


@dataclass
class TokenClaims:
    """Validated JWT token claims."""
    client_id: str
    role: str  # 'admin', 'client', 'viewer'
    exp: datetime
    iat: datetime
    jti: Optional[str] = None  # JWT ID for revocation
    permissions: List[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
    
    @property
    def is_admin(self) -> bool:
        return self.role == 'admin'
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.exp
    
    def has_permission(self, permission: str) -> bool:
        return self.is_admin or permission in self.permissions


class JWTAuth:
    """JWT authentication manager for the dashboard."""
    
    # Default token expiry times by role
    TOKEN_EXPIRY = {
        'admin': timedelta(hours=24),
        'client': timedelta(hours=8),
        'viewer': timedelta(hours=4),
        'api': timedelta(days=30),  # Long-lived API tokens
    }
    
    # Role-based default permissions
    ROLE_PERMISSIONS = {
        'admin': ['view_all', 'manage_scans', 'kill_scans', 'view_findings', 'export'],
        'client': ['view_own', 'manage_scans', 'kill_scans', 'view_findings'],
        'viewer': ['view_own', 'view_findings'],
    }
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = 'HS256'):
        """Initialize JWT auth.
        
        Args:
            secret_key: Secret for signing tokens. Uses JWT_SECRET env var if not provided.
            algorithm: JWT algorithm (default HS256)
        """
        self.secret_key = secret_key or os.getenv('JWT_SECRET') or os.getenv('SECRET_KEY')
        if not self.secret_key:
            raise ValueError("JWT_SECRET or SECRET_KEY environment variable required")
        self.algorithm = algorithm
        
        # Token revocation list (in production, use Redis)
        self._revoked_tokens: set = set()
    
    def create_token(
        self,
        client_id: str,
        role: str = 'client',
        expires_in: Optional[timedelta] = None,
        permissions: Optional[List[str]] = None,
        jti: Optional[str] = None,
    ) -> str:
        """Create a JWT token with client claims.
        
        Args:
            client_id: Client identifier
            role: User role (admin, client, viewer)
            expires_in: Custom expiry time (uses role default if not provided)
            permissions: Custom permissions (uses role defaults if not provided)
            jti: Optional JWT ID for revocation tracking
        
        Returns:
            Encoded JWT token string
        """
        now = datetime.utcnow()
        expiry = expires_in or self.TOKEN_EXPIRY.get(role, timedelta(hours=8))
        
        payload = {
            'client_id': client_id,
            'role': role,
            'iat': now,
            'exp': now + expiry,
            'permissions': permissions or self.ROLE_PERMISSIONS.get(role, []),
        }
        
        if jti:
            payload['jti'] = jti
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> Optional[TokenClaims]:
        """Validate a JWT token and return claims.
        
        Args:
            token: JWT token string
        
        Returns:
            TokenClaims if valid, None if invalid/expired
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check revocation
            jti = payload.get('jti')
            if jti and jti in self._revoked_tokens:
                return None
            
            return TokenClaims(
                client_id=payload['client_id'],
                role=payload['role'],
                exp=datetime.fromtimestamp(payload['exp']),
                iat=datetime.fromtimestamp(payload['iat']),
                jti=jti,
                permissions=payload.get('permissions', []),
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, jti: str) -> None:
        """Revoke a token by its JTI."""
        self._revoked_tokens.add(jti)
    
    def extract_token_from_request(self) -> Optional[str]:
        """Extract JWT token from Flask request.
        
        Checks in order:
        1. Authorization: Bearer <token> header
        2. ?token=<token> query parameter
        3. WebSocket auth dict
        """
        if not FLASK_AVAILABLE or request is None:
            return None
        
        # Check Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        
        # Check query parameter
        token = request.args.get('token')
        if token:
            return token
        
        return None
    
    def get_current_claims(self) -> Optional[TokenClaims]:
        """Get claims from current request context."""
        return getattr(g, 'jwt_claims', None)


# Global auth instance (initialized lazily)
_auth_instance: Optional[JWTAuth] = None


def get_jwt_auth() -> JWTAuth:
    """Get or create the global JWTAuth instance."""
    global _auth_instance
    if _auth_instance is None:
        _auth_instance = JWTAuth()
    return _auth_instance


def jwt_required(f):
    """Decorator to require valid JWT for endpoint access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = get_jwt_auth()
        token = auth.extract_token_from_request()
        
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        claims = auth.validate_token(token)
        if not claims:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Store claims in request context
        g.jwt_claims = claims
        
        return f(*args, **kwargs)
    return decorated


def jwt_optional(f):
    """Decorator for optional JWT auth (validates if present)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = get_jwt_auth()
        token = auth.extract_token_from_request()
        
        if token:
            claims = auth.validate_token(token)
            if claims:
                g.jwt_claims = claims
        
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = get_jwt_auth()
        token = auth.extract_token_from_request()
        
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        claims = auth.validate_token(token)
        if not claims:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if not claims.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        g.jwt_claims = claims
        return f(*args, **kwargs)
    return decorated


def client_required(client_id: str):
    """Decorator to require specific client_id or admin."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = get_jwt_auth()
            token = auth.extract_token_from_request()
            
            if not token:
                return jsonify({'error': 'Missing authentication token'}), 401
            
            claims = auth.validate_token(token)
            if not claims:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Admins can access any client
            if not claims.is_admin and claims.client_id != client_id:
                return jsonify({'error': 'Access denied for this client'}), 403
            
            g.jwt_claims = claims
            return f(*args, **kwargs)
        return decorated
    return decorator


if __name__ == "__main__":
    # Demo/test
    import os
    os.environ['JWT_SECRET'] = 'test-secret-key-for-demo'
    
    auth = JWTAuth()
    
    # Create tokens for different roles
    admin_token = auth.create_token(client_id="internal", role="admin")
    client_token = auth.create_token(client_id="acme_corp", role="client")
    viewer_token = auth.create_token(client_id="acme_corp", role="viewer")
    
    print("JWT Auth Demo")
    print("=" * 50)
    
    print(f"\nAdmin token: {admin_token[:50]}...")
    claims = auth.validate_token(admin_token)
    print(f"  Client: {claims.client_id}, Role: {claims.role}")
    print(f"  Is admin: {claims.is_admin}")
    print(f"  Permissions: {claims.permissions}")
    
    print(f"\nClient token: {client_token[:50]}...")
    claims = auth.validate_token(client_token)
    print(f"  Client: {claims.client_id}, Role: {claims.role}")
    print(f"  Is admin: {claims.is_admin}")
    print(f"  Permissions: {claims.permissions}")
    
    print(f"\nViewer token: {viewer_token[:50]}...")
    claims = auth.validate_token(viewer_token)
    print(f"  Client: {claims.client_id}, Role: {claims.role}")
    print(f"  Permissions: {claims.permissions}")
    
    print("\n✅ JWT Auth module ready!")

