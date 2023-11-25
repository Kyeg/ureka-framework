# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model (Message)
import json

# Data Model (RAM)
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
        # WHEN: Accept bluetooth connection from UA or CS
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: Receive/Send Message in Connection
        self.iot_device.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth Connection with UA or CS
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New bluetooth Connections from UA or CS
        self.iot_device.msg_receiver.close_bluetooth_acception()

        return self.iot_device

    def receive_insecure_cmd_through_bluetooth(
        self, option: str = "with_device_id"
    ) -> DeviceController:
        # WHEN: Accept bluetooth connection from UA or CS
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.iot_device.msg_receiver.accept_bluetooth_comm()

        # WHEN: IoTD receive the insecure_cmd from UA or CS
        while True:
            try:
                # This will block until message is received
                insecure_cmd_json = (
                    self.iot_device.shared_data.connection_socket.recv_message()
                )

                ########################################################################
                # End Comm Measurement
                ########################################################################
                self.iot_device.executor.measure_message_size(insecure_cmd_json)
                simple_log("cli", f"Received Command: {insecure_cmd_json}")

                ######################################################
                # Start Process Measurement
                ######################################################
                self.iot_device.executor.measure_process_start()

                # WHEN: IoTD do data processing
                if option == "shortest":
                    insecure_data_json = f"Data: {insecure_cmd_json}"
                else:
                    insecure_cmd_dict = json.loads(insecure_cmd_json)
                    insecure_data_dict = {
                        "protocol_verision": insecure_cmd_dict["protocol_verision"],
                        "device_id": insecure_cmd_dict["device_id"],
                        "insecure_data_response": f"Data: {insecure_cmd_dict['insecure_command']}",
                    }
                    insecure_data_json = json.dumps(insecure_data_dict, indent=4)

                # WHEN: IoTD return the insecure_data to UA or CS
                self.iot_device.shared_data.connection_socket.send_message(
                    insecure_data_json
                )
                simple_log("cli", f"Sent Data: {insecure_data_json}")

                ######################################################
                # End Process Measurement
                ######################################################
                self.iot_device.executor.measure_comm_process_time(
                    "_device_recv_insecure_cmd"
                )

                simple_log("debug", f"+ Finish CMD-DATA~~ (device)")
            except OSError:
                simple_log("cli", f"")
                simple_log("cli", f"+ Connection is closed by peer.")
                break

        # RE-GIVEN: Close bluetooth connection with UA or CS
        self.iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Stop Accepting New bluetooth Connections from UA or CS
        self.iot_device.msg_receiver.close_bluetooth_acception()

        return self.iot_device


if __name__ == "__main__":
    try:
        ######################################################
        # ENVIRONMENT
        ######################################################
        Environment.DEPLOYMENT_ENV = "PRODUCTION"
        # Environment.DEBUG_LOG = "OPEN"
        Environment.DEBUG_LOG = "CLOSED"
        # Environment.CLI_LOG = "OPEN"
        Environment.CLI_LOG = "CLOSED"
        Environment.MEASURE_LOG = "OPEN"
        # Environment.MEASURE_LOG = "CLOSED"

        # Omit 1st run (Cold-start)
        for times in range(2):
            if times == 0:
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Cold Start")
                simple_log("measure", "*" * 50)
            else:
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Initialize Agent & Device")
                simple_log("measure", "*" * 50)

            ######################################################
            # Unintialized Device
            ######################################################

            # RE-GIVEN:
            SimpleStorage.delete_storage_in_test()

            ######################################################
            # Intialize Device
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
        # Receive Insecure Command & Send Insecure Data
        ######################################################
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            simple_log("measure", "")
            simple_log("measure", "*" * 50)
            simple_log("measure", f"+ Send Insecure Command ({option})")
            simple_log("measure", "*" * 50)

            # GIVEN: Initialized IoTD
            menu_iot_device = MenuIoTDevice(device_name="iot_device")
            iot_device = menu_iot_device.get_iot_device()

            # WHEN: DM's CS apply the insecure_cmd to IoTD
            iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
                option=option
            )

            # THEN: ...

        ######################################################
        # Transfer Device Ownership
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Transfer Device Ownership")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.owner_pub_key_str != None

        ######################################################
        # Grant Device Access Right (to owner herself)
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Grant Device Access Right (to owner herself)")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: EP's CS apply the self_access_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the access_end_u_token to IoTD
        original_device_order = iot_device.shared_data.this_device.ticket_order
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert (
            iot_device.shared_data.this_device.ticket_order == original_device_order + 1
        )

        ######################################################
        # Grant Device Access Right (to others)
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Grant Device Access Right (to others)")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the access_end_u_token to IoTD
        original_device_order = iot_device.shared_data.this_device.ticket_order
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert (
            iot_device.shared_data.this_device.ticket_order == original_device_order + 1
        )

    except RuntimeError as error:
        simple_log("error", f"{error}")
