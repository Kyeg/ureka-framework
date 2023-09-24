from dataclasses import dataclass, field
from typing import TYPE_CHECKING

# Prevent circular import by TYPE_CHECKING (mypy's recommanded trick through forward declarations)
if TYPE_CHECKING:  # pragma: no cover
    from ureka_framework.logic.device_controller import DeviceController


@dataclass
class FakeCommChannel:
    # "Mutable default values" are problematic in Python because they are shared among all instances of the class.
    ends: list["DeviceController"] = field(default_factory=list)
    message_in_channel: str = None
