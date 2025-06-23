import yaml
import streamlit_authenticator as stauth

def load_auth_config(config_path="config.yaml"):
    """Loads authentication configuration from a YAML file."""
    with open(config_path) as file:
        config = yaml.safe_load(file)
    return config

def get_authenticator(config):
    """Creates and returns an authentication object using the provided config."""
    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days']
    )
    return authenticator