import shutil
import configparser
from pathlib import Path

# the nessus-utility-toolkit folder that contains the example config
location = Path(__file__).resolve().parent

config_dir = Path.home() / ".config"
config_file = config_dir / "nut.conf"

# create the .config dir if it doesn't exist
if not config_dir.exists():
    config_dir.mkdir()

# create the base config if it doesn't exist yet
if not config_file.exists():
    shutil.copy(location / "nut.conf.example", config_dir / "nut.conf")

# the actual variable that stores the config
settings = configparser.ConfigParser()
settings.read(config_dir / "nut.conf")
