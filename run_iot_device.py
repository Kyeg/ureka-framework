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


class MenuIoTDevice:
    def __init__(self, device_name: str) -> None:
        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name=device_name,
        )

    def get_iot_device(self) -> DeviceController:
        return self.iot_device

    def receive_u_ticket_through_bluetooth(self) -> DeviceController:
        # WHEN: Accept connection from UA or CS
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: Receive/Send Message in Connection
        self.iot_device.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close Connection with IoTD
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New Connections from IoTD
        self.iot_device.msg_receiver.close_bluetooth_acception()

        return self.iot_device


if __name__ == "__main__":
    try:
        # ENVIRONMENT
        Environment.DEPLOYMENT_ENV = "PRODUCTION"

        ######################################################

        # RE-GIVEN:
        SimpleStorage.delete_storage_in_test()

        ######################################################

        # GIVEN: Uninitialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")

        # WHEN: Holder: DM's CS apply the initialization_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.ticket_order == 1
        assert iot_device.shared_data.this_device.device_priv_key_str != None

        ######################################################

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.owner_pub_key_str != None

        ######################################################

    except RuntimeError as error:
        simple_log("error", f"{error}")
