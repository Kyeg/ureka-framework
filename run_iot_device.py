# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device


######################################################
# Test Fixtures
######################################################
def setup_production_environment():
    # RE-GIVEN: Reset the production environment
    SimpleStorage.delete_storage_in_test()


if __name__ == "__main__":
    Environment.DEPLOYMENT_ENV = "PRODUCTION"
    # Environment.DEPLOYMENT_ENV = "DEMO"

    setup_production_environment()

    try:
        # GIVEN: Uninitialized IoTD
        iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )
        assert iot_device.shared_data.this_device.ticket_order == 0
        assert iot_device.shared_data.this_device.device_priv_key_str == None

        # GIVEN: Bluetooth Service Lifecycle: Accept New Connection
        iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: Bluetooth Service Lifecycle: Receive & Send in Connection
        iot_device.msg_receiver._recv_xxx_message()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.ticket_order == 1
        assert iot_device.shared_data.this_device.device_priv_key_str != None

        # RE-GIVEN: Bluetooth Service Lifecycle: Close Connection
        iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Bluetooth Service Lifecycle: Stop Accepting New Connections
        iot_device.msg_receiver.close_bluetooth_acception()

    except RuntimeError as error:
        simple_log("error", f"{error}")
