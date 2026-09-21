from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    supabase_url: str
    supabase_service_role_key: str
    crypto_service_url: str

    class Config:
        env_file = ".env"

settings = Settings()
