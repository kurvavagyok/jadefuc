# JADE Ultimate Security Platform - Configuration
# Enhanced with 2025 state-of-the-art settings

import os
from typing import List, Optional, Dict, Any
from pydantic_settings import BaseSettings
from pydantic import Field, validator
import secrets

class Settings(BaseSettings):
    APP_NAME: str = "JADE Ultimate Security Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:password@localhost:5432/jade_security",
        env="DATABASE_URL"
    )
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 3600
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    ALLOWED_HOSTS: List[str] = Field(default=["*"], env="ALLOWED_HOSTS")
    CORS_ORIGINS: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    # AI Service API Keys
    OPENAI_API_KEY: str = Field(default="", env="OPENAI_API_KEY")
    OPENAI_ORG_ID: str = Field(default="", env="OPENAI_ORG_ID")
    OPENAI_ADMIN_KEY: str = Field(default="", env="OPENAI_ADMIN_KEY")
    GEMINI_API_KEY: str = Field(default="", env="GEMINI_API_KEY")
    GOOGLE_AI_API_KEY: str = Field(default="", env="GOOGLE_AI_API_KEY")
    CEREBRAS_API_KEY: str = Field(default="", env="CEREBRAS_API_KEY")
    GITHUB_TOKEN: str = Field(default="", env="GITHUB_TOKEN")
    ALPHAGENOME_API_KEY: str = Field(default="", env="ALPHAGENOME_API_KEY")
    NASA_API_KEY: str = Field(default="", env="NASA_API_KEY")
    VIRUSTOTAL_API_KEY: str = Field(default="", env="VIRUSTOTAL_API_KEY")
    SHODAN_API_KEY: str = Field(default="", env="SHODAN_API_KEY")
    CENSYS_API_ID: str = Field(default="", env="CENSYS_API_ID")
    CENSYS_API_SECRET: str = Field(default="", env="CENSYS_API_SECRET")
    SMTP_SERVER: str = Field(default="smtp.gmail.com", env="SMTP_SERVER")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USERNAME: str = Field(default="", env="SMTP_USERNAME")
    SMTP_PASSWORD: str = Field(default="", env="SMTP_PASSWORD")
    EMAIL_FROM: str = Field(default="noreply@jade-security.com", env="EMAIL_FROM")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    AWS_REGION: str = Field(default="us-east-1", env="AWS_REGION")
    S3_BUCKET: Optional[str] = Field(default=None, env="S3_BUCKET")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    SENTRY_DSN: Optional[str] = Field(default=None, env="SENTRY_DSN")
    MAX_CONCURRENT_SCANS: int = Field(default=10, env="MAX_CONCURRENT_SCANS")
    SCAN_TIMEOUT: int = Field(default=3600, env="SCAN_TIMEOUT")
    MAX_SCAN_TARGETS: int = Field(default=1000, env="MAX_SCAN_TARGETS")
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    DEFAULT_LLM_MODEL: str = Field(default="gpt-4", env="DEFAULT_LLM_MODEL")
    LLM_MAX_TOKENS: int = Field(default=4000, env="LLM_MAX_TOKENS")
    LLM_TEMPERATURE: float = Field(default=0.1, env="LLM_TEMPERATURE")
    ENABLE_VULNERABILITY_SCANNING: bool = Field(default=True, env="ENABLE_VULNERABILITY_SCANNING")
    ENABLE_PORT_SCANNING: bool = Field(default=True, env="ENABLE_PORT_SCANNING")
    ENABLE_WEB_SCANNING: bool = Field(default=True, env="ENABLE_WEB_SCANNING")
    ENABLE_NETWORK_SCANNING: bool = Field(default=True, env="ENABLE_NETWORK_SCANNING")
    MAX_FILE_SIZE: int = Field(default=100 * 1024 * 1024, env="MAX_FILE_SIZE")
    ALLOWED_FILE_TYPES: List[str] = Field(
        default=[".txt", ".log", ".json", ".xml", ".csv", ".pdf"],
        env="ALLOWED_FILE_TYPES"
    )
    CREATOR_SIGNATURE: str = "SmFkZSBtYWRlIGJ5IEtvbGzDoXIgU8OhbmRvcg=="
    CREATOR_HASH: str = "a7b4c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5"

    @validator("ALLOWED_HOSTS", pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v

    @validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @validator("ALLOWED_FILE_TYPES", pre=True)
    def parse_file_types(cls, v):
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",")]
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

AI_MODELS = {
    "gpt-4": {
        "provider": "openai",
        "model": "gpt-4",
        "max_tokens": 4000,
        "temperature": 0.1,
        "use_case": "general_analysis"
    },
    "gpt-4-turbo": {
        "provider": "openai", 
        "model": "gpt-4-turbo-preview",
        "max_tokens": 4000,
        "temperature": 0.1,
        "use_case": "detailed_analysis"
    },
    "claude-3-opus": {
        "provider": "anthropic",
        "model": "claude-3-opus-20240229",
        "max_tokens": 4000,
        "temperature": 0.1,
        "use_case": "security_analysis"
    },
    "gemini-pro": {
        "provider": "google",
        "model": "gemini-pro",
        "max_tokens": 4000,
        "temperature": 0.1,
        "use_case": "threat_intelligence"
    },
    "mixtral-8x7b": {
        "provider": "together",
        "model": "mistralai/Mixtral-8x7B-Instruct-v0.1",
        "max_tokens": 4000,
        "temperature": 0.1,
        "use_case": "code_analysis"
    }
}

SEVERITY_LEVELS = {
    "CRITICAL": {"score": 9.0, "color": "#dc3545", "priority": 1},
    "HIGH": {"score": 7.0, "color": "#fd7e14", "priority": 2}, 
    "MEDIUM": {"score": 5.0, "color": "#ffc107", "priority": 3},
    "LOW": {"score": 3.0, "color": "#28a745", "priority": 4},
    "INFO": {"score": 1.0, "color": "#17a2b8", "priority": 5}
}

SCAN_TYPES = {
    "network": {
        "name": "Network Scan",
        "description": "Comprehensive network infrastructure scanning",
        "timeout": 1800,
        "tools": ["nmap", "masscan", "zmap"]
    },
    "vulnerability": {
        "name": "Vulnerability Scan", 
        "description": "Vulnerability assessment and analysis",
        "timeout": 3600,
        "tools": ["openvas", "nessus", "nuclei"]
    },
    "web": {
        "name": "Web Application Scan",
        "description": "Web application security testing",
        "timeout": 2400,
        "tools": ["nikto", "dirb", "sqlmap", "xssstrike"]
    },
    "port": {
        "name": "Port Scan",
        "description": "Port scanning and service detection",
        "timeout": 900,
        "tools": ["nmap", "masscan"]
    },
    "comprehensive": {
        "name": "Comprehensive Scan",
        "description": "Full security assessment including all scan types",
        "timeout": 7200,
        "tools": ["all"]
    }
}