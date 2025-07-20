# JADE Ultimate Security Platform - Security Utilities
# Enterprise security functions and helpers

import secrets
import hashlib
import hmac
import base64
from typing import List, Optional
import ipaddress
from datetime import datetime
import structlog

logger = structlog.get_logger()

def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)

def generate_api_key() -> tuple[str, str]:
    """Generate API key and return (key, hash) tuple"""
    # Generate a random key
    key = f"jade_{secrets.token_urlsafe(32)}"
    
    # Create hash for storage
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    
    return key, key_hash

def verify_api_key(key: str, stored_hash: str) -> bool:
    """Verify API key against stored hash"""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return hmac.compare_digest(key_hash, stored_hash)

def generate_backup_codes(count: int = 8) -> List[str]:
    """Generate MFA backup codes"""
    codes = []
    for _ in range(count):
        code = secrets.randbelow(10**8)  # 8-digit code
        codes.append(f"{code:08d}")
    return codes

def verify_ip_whitelist(ip_address: str, allowed_ips: List[str]) -> bool:
    """Verify if IP address is in whitelist"""
    if not allowed_ips:
        return True  # No restrictions
    
    try:
        client_ip = ipaddress.ip_address(ip_address)
        
        for allowed_ip in allowed_ips:
            if "/" in allowed_ip:  # CIDR notation
                if client_ip in ipaddress.ip_network(allowed_ip, strict=False):
                    return True
            else:  # Single IP
                if client_ip == ipaddress.ip_address(allowed_ip):
                    return True
        
        return False
    except ValueError:
        logger.warning("invalid_ip_format", ip_address=ip_address)
        return False

def generate_device_fingerprint(user_agent: str, accept_language: str = "", 
                              screen_resolution: str = "") -> str:
    """Generate device fingerprint for additional security"""
    fingerprint_data = f"{user_agent}|{accept_language}|{screen_resolution}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

def check_password_strength(password: str) -> dict:
    """Check password strength and return analysis"""
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Character variety checks
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password should contain numbers")
    
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 2
    else:
        feedback.append("Password should contain special characters")
    
    # Common pattern checks
    common_passwords = ["password", "123456", "qwerty", "admin", "letmein"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("Password is too common")
    
    # Determine strength level
    if score >= 6:
        strength = "strong"
    elif score >= 4:
        strength = "medium"
    elif score >= 2:
        strength = "weak"
    else:
        strength = "very_weak"
    
    return {
        "score": score,
        "strength": strength,
        "feedback": feedback
    }

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    import re
    # Remove dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    # Limit length
    if len(sanitized) > 255:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        max_name_len = 255 - len(ext) - 1 if ext else 255
        sanitized = name[:max_name_len] + ('.' + ext if ext else '')
    
    return sanitized or "unnamed_file"

def create_csrf_token(session_id: str, secret_key: str) -> str:
    """Create CSRF token for session"""
    timestamp = str(int(datetime.utcnow().timestamp()))
    message = f"{session_id}:{timestamp}"
    signature = hmac.new(
        secret_key.encode(), 
        message.encode(), 
        hashlib.sha256
    ).hexdigest()
    token = base64.b64encode(f"{message}:{signature}".encode()).decode()
    return token

def verify_csrf_token(token: str, session_id: str, secret_key: str, 
                     max_age_seconds: int = 3600) -> bool:
    """Verify CSRF token"""
    try:
        decoded = base64.b64decode(token).decode()
        parts = decoded.split(':')
        if len(parts) != 3:
            return False
        
        token_session_id, timestamp, signature = parts
        
        # Verify session ID matches
        if token_session_id != session_id:
            return False
        
        # Check age
        token_time = int(timestamp)
        current_time = int(datetime.utcnow().timestamp())
        if current_time - token_time > max_age_seconds:
            return False
        
        # Verify signature
        message = f"{token_session_id}:{timestamp}"
        expected_signature = hmac.new(
            secret_key.encode(), 
            message.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    except Exception:
        return False