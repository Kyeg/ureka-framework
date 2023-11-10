from typing import Optional
from dataclasses import dataclass, field

# Data Model (RAM)
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice

# Resource (Simulated Comm)
from ureka_framework.resource.communication.simulated_comm.simulated_comm_channel import (
    SimulatedCommChannel,
)

# Resource (Bluetooth Comm)
from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
    AcceptSocket,
    ConnectingWorker,
    ConnectionSocket,
)


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

    # Resource (Simulated Comm)
    simulated_comm_channel: Optional[SimulatedCommChannel] = None
    comm_done_flag: Optional[bool] = None
    received_message_json: Optional[str] = None
    result_message: Optional[str] = None

    # Resource (Bluetooth Comm)
    accept_socket: Optional[AcceptSocket] = None
    connecting_worker: Optional[ConnectingWorker] = None
    connection_socket: Optional[ConnectionSocket] = None
