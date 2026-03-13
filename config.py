"""
config.py - Global Settings & Stealth Profiles
================================================
Central configuration for AutoVulnScan. All modules read
their defaults from here. The interactive CLI can modify
these settings at runtime.

STEALTH PROFILES:
  normal → Fast scan, no delays, max threads (noisy)
  quiet  → Small delays + jitter, fewer threads
  ghost  → Max stealth, slow but nearly undetectable
"""

import os       # For file path operations
import json     # For reading API key and settings

# Load .env file if python-dotenv is installed
# This is the preferred way to manage secrets
try:
    from dotenv import load_dotenv
    # Look for .env in the project root (same directory as config.py)
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv not installed, fall back to api.txt


# ============================================================
# STEALTH PROFILES
# ============================================================
# Each profile defines timing and threading parameters
# that control how "loud" the scanner is on the network.

STEALTH_PROFILES = {
    "normal": {
        "delay": 0.0,       # No delay between probes
        "jitter": 0.0,      # No random jitter
        "threads": 50,      # Maximum threads
        "timeout": 0.5,     # Short timeout
        "label": "Normal",
        "description": "Fast scan, no delays. Easily detected by IDS.",
        "icon": "⚡",
    },
    "quiet": {
        "delay": 0.05,      # 50ms base delay
        "jitter": 0.05,     # 0-50ms random extra delay
        "threads": 25,      # Half the threads
        "timeout": 1.0,     # Longer timeout
        "label": "Quiet",
        "description": "Small delays + jitter. Moderate stealth.",
        "icon": "🤫",
    },
    "ghost": {
        "delay": 0.2,       # 200ms base delay
        "jitter": 0.15,     # 0-150ms random extra delay
        "threads": 10,      # Very few threads
        "timeout": 1.5,     # Long timeout
        "label": "Ghost",
        "description": "Maximum stealth. Slow but nearly invisible.",
        "icon": "👻",
    },
}


# ============================================================
# DEFAULT SETTINGS
# ============================================================

class Settings:
    """
    Holds all scan settings. Modified at runtime by the CLI.
    Other modules import this and read the current values.
    """
    # Target configuration
    target_ip = ""                  # Target IP address
    subnet = ""                     # Subnet CIDR for discovery
    port_start = 1                  # First port to scan
    port_end = 1024                 # Last port to scan

    # Scan behavior
    max_threads = 50                # Max concurrent threads
    timeout = 0.5                   # Socket timeout in seconds
    stealth_level = "quiet"         # Default to quiet mode

    # Output
    output_dir = "."                # Where to save reports

    # API
    api_key = None                  # NVD API key (loaded from file)

    # File paths (relative to project root)
    api_key_file = "api.txt"
    cache_file = "cve_cache.json"

    @classmethod
    def get_stealth_profile(cls):
        """Return the current stealth profile dict."""
        return STEALTH_PROFILES.get(cls.stealth_level,
                                     STEALTH_PROFILES["quiet"])

    @classmethod
    def load_api_key(cls):
        """
        Load the NVD API key using this priority order:
          1. NVD_API_KEY environment variable (set by .env via python-dotenv)
          2. api.txt file in the project root (legacy fallback)

        Never hardcode the key in source code.
        """
        # Priority 1: environment variable (from .env or system environment)
        env_key = os.environ.get("NVD_API_KEY", "").strip()
        if env_key:
            cls.api_key = env_key
            return env_key

        # Priority 2: api.txt file (legacy fallback for backward compatibility)
        possible_paths = [
            cls.api_key_file,
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         cls.api_key_file),
        ]
        for path in possible_paths:
            try:
                full_path = os.path.abspath(path)
                if os.path.exists(full_path):
                    with open(full_path, "r") as f:
                        key = f.read().strip()
                    if key:
                        cls.api_key = key
                        return key
            except Exception:
                continue
        return None

    @classmethod
    def apply_stealth(cls):
        """Apply stealth profile settings to scan parameters."""
        profile = cls.get_stealth_profile()
        cls.max_threads = profile["threads"]
        cls.timeout = profile["timeout"]
