from typing import Optional
from dataclasses import dataclass, field
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice


@dataclass
class SharedData:
    # Data Model (Persistent)
    this_device: Optional[ThisDevice] = None
    current_session: Optional[CurrentSession] = None
    # Data Model (Persistent: User Agent or Cloud Server only)
    this_person: Optional[ThisPerson] = None
    device_table: Optional[dict[str, OtherDevice]] = field(default_factory=dict)
    # Data Model (RAM-only)
    state: Optional[str] = None

    # [Simulation Comm]
    comm_done_flag: Optional[bool] = None
    received_message_json: Optional[str] = None
    result_message: Optional[str] = None
