# Environment
from ureka_framework.environment import Environment

# Resource (Bluetooth Comm)
from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
    ConnectionSocket,
)

# Resource (Logger)
from ureka_framework.resource.communication.bluetooth.bt_logger import bt_simple_log

# Resource (Measurer)
from ureka_framework.resource.communication.bluetooth.bt_measure_executor import (
    measure_process_start,
    measure_cli_process,
    measure_comm_process,
    measure_comm_start,
    measure_comm_time,
)

# Data Model
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device


def device_event_loop(connection_socket: ConnectionSocket):
    try:
        while True:
            ########################################################################
            # Start Comm Measurement
            ########################################################################
            # measure_comm_start()
            # Connection Socket: Receive
            received_u_ticket_str: str = connection_socket.recv_message()
            bt_simple_log("debug", f"")
            bt_simple_log("debug", f"received_u_ticket_str = {received_u_ticket_str}")
            ########################################################################
            # End Comm Measurement
            ########################################################################
            # measure_comm_time("received_u_ticket_str", received_u_ticket_str)

            ########################################################################
            # Start Process Measurement
            ########################################################################
            measure_process_start()
            # Data Processing: TODO: Contoller, e.g., echo the message
            if received_u_ticket_str == "exit":
                bt_simple_log("info", f"")
                bt_simple_log("info", f"+ Connection is closed by peer.")
                break
            sent_r_ticket_str: str = f"R<<<{received_u_ticket_str}>>>"
            bt_simple_log("debug", f"")
            bt_simple_log("debug", f"sent_r_ticket_str = {sent_r_ticket_str}")
            # Connection Socket: Send
            connection_socket.send_message(sent_r_ticket_str)
            ########################################################################
            # End Process Measurement
            ########################################################################
            measure_comm_process("device_send_r_ticket", sent_r_ticket_str)
    except OSError:
        bt_simple_log("info", f"")
        bt_simple_log("info", f"+ Connection is closed by peer.")


if __name__ == "__main__":
    Environment.DEPLOYMENT_ENV = "PRODUCTION"
    # Environment.DEPLOYMENT_ENV = "DEMO"
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
        # iot_device.msg_receiver._recv_xxx_message()
        device_event_loop(iot_device.shared_data.connection_socket)

        # # THEN: Succeed to initialize DM's IoTD
        # assert "SUCCESS" in iot_device.shared_data.result_message
        # assert iot_device.shared_data.this_device.ticket_order == 1
        # assert iot_device.shared_data.this_device.device_priv_key_str != None

        # RE-GIVEN: Bluetooth Service Lifecycle: Close Connection
        iot_device.msg_receiver.close_bluetooth_connection()

        # RE-GIVEN: Bluetooth Service Lifecycle: Stop Accepting New Connections
        iot_device.msg_receiver.close_bluetooth_acception()

    except RuntimeError as error:
        bt_simple_log("error", f"{error}")
