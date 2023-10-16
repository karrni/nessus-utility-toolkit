import configparser
import shutil
from argparse import Namespace
from pathlib import Path

LOCATION = Path(__file__).parent.resolve()

CONFIG_DIR = Path.home() / ".config" / "nut"
CONFIG_FILE = CONFIG_DIR / "nut.conf"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
if not CONFIG_FILE.exists():
    shutil.copy(LOCATION / "nut.conf", CONFIG_FILE)


# Stores settings from the config file
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Stores command line arguments
args = Namespace()
