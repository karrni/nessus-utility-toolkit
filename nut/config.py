import configparser
import shutil
from argparse import Namespace
from pathlib import Path

# path to the nut location
location = Path(__file__).resolve().parent

# the nut.conf is stored under ~/.config
config_dir = Path.home() / ".config"
config_file = config_dir / "nut.conf"


class Settings:
    """This stores settings from the config file as well as command-line arguments."""

    def __init__(self):
        self.args = Namespace()
        self.config = configparser.ConfigParser()
        self.config.read(config_file)


# create ~/.config if it doesn't exist
if not config_dir.exists():
    config_dir.mkdir()

# copy and use example config if it doesn't exist
if not config_file.exists():
    shutil.copy(location / "nut.conf.example", config_file)

# instance that stores the settings
settings = Settings()
