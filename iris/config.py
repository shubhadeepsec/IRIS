import json
import os
from pathlib import Path
from typing import Dict, Optional

# Default config directory: ~/.iris
CONFIG_DIR = Path.home() / ".iris"
CONFIG_FILE = CONFIG_DIR / "config.json"

def _ensure_config_dir():
    """Ensure the configuration directory exists."""
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def load_config() -> Dict[str, str]:
    """Load the configuration from disk."""
    if not CONFIG_FILE.exists():
        return {}
    
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_config(config: Dict[str, str]) -> None:
    """Save the configuration to disk."""
    _ensure_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    # Ensure config file is only readable by the owner
    os.chmod(CONFIG_FILE, 0o600)

def get_api_key(service_name: str) -> Optional[str]:
    """
    Get an API key. 
    Checks the local config file first, then falls back to environment variables.
    """
    config = load_config()
    key = config.get(service_name)
    if not key:
        key = os.environ.get(service_name)
    return key

def set_api_key(service_name: str, key_value: str) -> None:
    """Set an API key in the local configuration."""
    config = load_config()
    config[service_name] = key_value
    save_config(config)

def delete_api_key(service_name: str) -> bool:
    """Delete an API key from the local configuration."""
    config = load_config()
    if service_name in config:
        del config[service_name]
        save_config(config)
        return True
    return False
