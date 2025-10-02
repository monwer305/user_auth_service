import os
import threading

import yaml
from pydantic import BaseModel


class Settings(BaseModel):
    MYSQL_USER: str
    MYSQL_PASSWORD: str
    MYSQL_HOST: str
    MYSQL_PORT: int
    MYSQL_DB: str

    JWT_SECRET: str
    ACCESS_TOKEN_EXPIRES_MIN: int
    REFRESH_TOKEN_EXPIRES_DAYS: int

    APP_HOST: str
    APP_PORT: int

    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: str
    SMTP_FROM: str

    SUPER_ADMIN_EMAIL: str
    SUPER_ADMIN_PASSWORD: str

    @property
    def database_uri(self) -> str:
        """Return full SQLAlchemy database URI."""
        return (
            f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}"
        )


def get_settings(config_path: str) -> Settings:

    if config_path.endswith(".yml") or config_path.endswith(".yaml"):
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
                return Settings(**config_data)
        except Exception as e:
            raise RuntimeError(f"Error loading config file: {e}")
    else:
        raise ValueError("Unsupported config file format. Use .yml or .yaml")


class ConfigMapper:
    """Singleton config manager.

    Loads and stores app settings once. Supports reloading safely.
    Thread-safe initialization.
    """

    _instance: "ConfigMapper" | None = None
    _lock = threading.Lock()

    def __new__(cls):
        """Create or return singleton.

        Args:
            config_path (Optional[str]): Config file path. Defaults to
                CONFIG_FILE env var or "config.yml".

        Returns:
            ConfigMapper: Singleton instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    config_path = os.getenv("CONFIG_FILE", "config.yml")
                    settings_obj = get_settings(config_path)
                    cls._instance = super().__new__(cls)
                    cls._instance._settings = settings_obj
        return cls._instance

    @classmethod
    def get(cls) -> Settings:
        """Return current settings.

        Returns:
            Settings: The settings object.

        Raises:
            RuntimeError: If not initialized.
        """
        if cls._instance is None:
            raise RuntimeError("ConfigMapper not initialized.")
        return cls._instance._settings

    @classmethod
    def set(cls, config_path: str | None = None) -> None:
        """Reload settings.

        Args:
            config_path str|None: Config file path. Defaults to
                CONFIG_FILE env var or "config.yml".
        """
        if not config_path:
            config_path = os.getenv("CONFIG_FILE", "config.yml")

        settings_obj = get_settings(config_path)

        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            cls._instance._settings = settings_obj
