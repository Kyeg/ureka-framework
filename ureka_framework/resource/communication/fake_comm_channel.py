from dataclasses import dataclass
from queue import Queue
from typing import TYPE_CHECKING

# Prevent circular import by TYPE_CHECKING (mypy's recommanded trick through forward declarations)
if TYPE_CHECKING:  # pragma: no cover
    from ureka_framework.logic.device_controller import DeviceController


@dataclass
class FakeCommChannel:
    # "Mutable default values" are problematic in Python because they are shared among all instances of the class.
    end: "DeviceController" = None
    # put/get str in Queue
    sender_queue: None | Queue = None
    reciever_queue: None | Queue = None
