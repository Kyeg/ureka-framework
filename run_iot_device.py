# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model
from typing import Optional
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device


class IoTDevice:
    def __init__(self, device_name: str) -> None:
        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name=device_name,
        )

        # THEN: Uninitialized IoTD
        assert self.iot_device.shared_data.this_device.ticket_order == 0
        assert self.iot_device.shared_data.this_device.device_priv_key_str == None

    def receive_u_ticket_through_bluetooth(self) -> None:
        # WHEN: Environment
        Environment.DEPLOYMENT_ENV = "PRODUCTION"

        # WHEN: Accept connection from UA or CS
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: Receive/Send Message in Connection
        self.iot_device.msg_receiver._recv_xxx_message()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert self.iot_device.shared_data.this_device.ticket_order == 1
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None

        # RE-GIVEN: Close Connection with IoTD
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New Connections from IoTD
        self.iot_device.msg_receiver.close_bluetooth_acception()


if __name__ == "__main__":
    try:
        # RE-GIVEN:
        SimpleStorage.delete_storage_in_test()

        # WHEN: Production Case
        iot_device = IoTDevice(device_name="iot_device")
        iot_device.receive_u_ticket_through_bluetooth()

    except RuntimeError as error:
        simple_log("error", f"{error}")
