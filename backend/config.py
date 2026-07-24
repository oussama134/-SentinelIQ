"""
SentinelIQ — Central Configuration
All settings loaded from .env — never hardcode values
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SentinelIQ"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "sentineliq"
    DB_USER: str = "sentinel"
    DB_PASSWORD: str = "sentinel123"

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @property
    def DATABASE_URL_SYNC(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}"

    # Security
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ADMIN_PASSWORD_HASH: str = "$2b$12$E37ut6Q29GXrtOmXfyRi9.qzWDUKpI3JUNQId/E4VBS/j0a/Mrpg."
    FORWARDER_API_KEY: str = "sentineliq-forwarder-default-key"

    # ML Model paths
    MODEL_PATH: str = "./ml/models/lstm_model.pkl"
    SCALER_PATH: str = "./ml/models/scaler.pkl"
    LABEL_ENCODER_PATH: str = "./ml/models/label_encoder.pkl"

    # Threat Intel APIs
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Network capture
    NETWORK_INTERFACE: str = "eth0"
    CAPTURE_ENABLED: bool = True

    # Notifications
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    # Remote response (Ubuntu victim firewall)
    REMOTE_RESPONSE_ENABLED: bool = False
    REMOTE_RESPONSE_HOST: str = ""
    REMOTE_RESPONSE_PORT: int = 22
    REMOTE_RESPONSE_USER: str = ""
    REMOTE_RESPONSE_IDENTITY_FILE: str = ""
    REMOTE_RESPONSE_BACKEND: str = "iptables"   # iptables | ufw
    REMOTE_RESPONSE_USE_SUDO: bool = True

    # Kill Switch — radical remediation on confirmed ransomware
    KILL_SWITCH_ENABLED: bool = False          # set True in .env to arm it
    KILL_SWITCH_ACTION: str = "isolate"        # "isolate" (network drop) | "shutdown"
    # Reuses REMOTE_RESPONSE_* for SSH creds — no extra config needed

    # AI Agent
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    class Config:
        import os
        env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance — call this everywhere"""
    return Settings()


settings = get_settings()
