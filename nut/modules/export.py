import logging
from datetime import datetime

from nut.config import settings
from nut.utils import nessus

from .base import Module

logger = logging.getLogger(__name__)


class ExportModule(Module):
    def handle(self):
        pass
