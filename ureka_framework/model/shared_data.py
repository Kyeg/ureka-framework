from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice


class SharedData:
    def __init__(self) -> None:
        # Data Model (Persistent)
        self.this_device: ThisDevice = ThisDevice()
        self.current_session: CurrentSession = CurrentSession()
        # Data Model (Persistent: User Agent or Cloud Server only)
        self.this_person: ThisPerson = ThisPerson()
        self.device_table: dict[str, OtherDevice] = {}
        # Data Model (RAM-only)
        self.state: str = None
