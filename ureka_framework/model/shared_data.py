from dataclasses import dataclass, field
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice


@dataclass
class SharedData:
    # Data Model (Persistent)
    this_device: None | ThisDevice = None
    current_session: None | CurrentSession = None
    # Data Model (Persistent: User Agent or Cloud Server only)
    this_person: None | ThisPerson = None
    device_table: None | dict[str, OtherDevice] = field(default_factory=dict)
    # Data Model (RAM-only)
    state: None | str = None
