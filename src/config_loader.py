"""
Utility function to load configuration from a YAML file.
"""
import yaml
import logging
import os

CONFIG_PATH = 'config/config.yaml'

def load_config():
    """
    Loads the application configuration from the YAML file.

    Returns:
        dict: A dictionary containing the configuration, or None if loading fails.
    """
    config_abs_path = os.path.abspath(CONFIG_PATH)
    if not os.path.exists(config_abs_path):
        logging.error(f"Configuration file not found at: {config_abs_path}")
        return None
        
    try:
        with open(config_abs_path, 'r') as f:
            config = yaml.safe_load(f)
        logging.info(f"Configuration loaded successfully from {config_abs_path}")
        return config
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file {config_abs_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error loading configuration file {config_abs_path}: {e}")
        return None

# Example usage (optional, for testing)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    config = load_config()
    if config:
        print("Config loaded:")
        import json
        print(json.dumps(config, indent=2))
    else:
        print("Failed to load config.")
