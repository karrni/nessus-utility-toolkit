import configparser
import shutil
from argparse import Namespace
from pathlib import Path

LOCATION = Path(__file__).parent.resolve()

CONFIG_DIR = Path.home() / ".config" / "nut"
CONFIG_FILE = CONFIG_DIR / "nut.conf"


CONFIG_DIR.mkdir(exist_ok=True)
if not CONFIG_FILE.exists():
    shutil.copy(LOCATION / "nut.conf", CONFIG_FILE)


class Settings:
    """Stores settings from the config and command-line arguments."""

    def __init__(self):
        self.args = Namespace()
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)

        # Stores the resolved scan IDs
        self.scan_ids = None


# Instance that stores the settings
settings = Settings()

args = settings.args
config = settings.config
scan_ids = settings.scan_ids
