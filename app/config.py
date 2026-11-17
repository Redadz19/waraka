from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "WARAKA Licensing API"
    environment: str = "development"
    database_url: str = "sqlite:///./waraka.db"
    license_private_key_b64: str = ""
    license_public_key_b64: str = ""
    admin_api_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "licenses@example.com"
    otp_ttl_seconds: int = 600
    otp_resend_seconds: int = 60
    otp_max_attempts: int = 5
    max_devices_per_license: int = 3
    cors_origins: str = "*"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
