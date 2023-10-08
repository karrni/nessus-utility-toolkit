from abc import ABC, abstractmethod


class Module(ABC):
    @abstractmethod
    def handle(self):
        ...
