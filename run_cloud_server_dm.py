# Environment
from ureka_framework.environment import Environment

# Resource (Comm)
import ureka_framework.resource.communication.bluetooth.bluetooth_service as bt_service
from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
    ConnectingWorker,
    ConnectionSocket,
)

# Resource (Logger)
from ureka_framework.resource.communication.bluetooth.bt_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.communication.bluetooth.bt_measure_executor import (
    measure_process_start,
    measure_cli_process,
    measure_comm_process,
    measure_comm_start,
    measure_comm_time,
)

# Data Model
from ureka_framework.resource.communication.bluetooth.bt_u_ticket import (
    generate_arbitrary_u_ticket,
)


######################################################
# JSON Generating
######################################################
def input_next_message() -> str:
    while True:
        simple_log("demo", "")
        data_content: str = input("[    DEMO] : Set Data in U-Ticket: ")
        data_size: str = input("[    DEMO] : Set Data Size (x N): ")

        if data_content == "exit":
            generated_u_ticket_str: str = "exit"
        else:
            try:
                generated_u_ticket_str: str = generate_json_message(
                    data_content, int(data_size)
                )
            except ValueError:  # ERROR: data_size cannot be converted to int
                continue
        break

    return generated_u_ticket_str


def generate_json_message(data_content: str, data_size: int) -> str:
    generated_request: dict = {
        "device_id": f"abcdef",
        "cmd_or_data": f"{data_content}" * data_size,
        "end_tag": f"END",
    }
    generated_u_ticket_str = generate_arbitrary_u_ticket(generated_request)

    return generated_u_ticket_str


def agent_event_loop(connection_socket: ConnectionSocket):
    ########################################################################
    # Start Process Measurement
    ########################################################################
    measure_process_start()
    # Data Processing: TODO: Contoller, e.g., input next message
    sent_u_ticket_str = input_next_message()
    simple_log("debug", f"")
    simple_log("debug", f"sent_u_ticket_str = {sent_u_ticket_str}")
    # Connection Socket: Send
    connection_socket.send_message(sent_u_ticket_str)
    ########################################################################
    # End Process Measurement
    ########################################################################
    measure_cli_process("holder_apply_u_ticket")
    try:
        while True:
            ########################################################################
            # Start Comm Measurement
            ########################################################################
            measure_comm_start()
            # Connection Socket: Receive
            received_r_ticket_str: str = connection_socket.recv_message()
            simple_log("debug", f"")
            simple_log("debug", f"received_r_ticket_str = {received_r_ticket_str}")
            ########################################################################
            # End Comm Measurement
            ########################################################################
            measure_comm_time("holder_recv_r_ticket", received_r_ticket_str)

            ########################################################################
            # Start Process Measurement
            ########################################################################
            measure_process_start()
            # Data Processing: TODO: Contoller, e.g., input next message
            sent_u_ticket_str = input_next_message()
            simple_log("debug", f"")
            simple_log("debug", f"sent_u_ticket_str = {sent_u_ticket_str}")
            # Connection Socket: Send
            connection_socket.send_message(sent_u_ticket_str)
            ########################################################################
            # End Process Measurement
            ########################################################################
            measure_cli_process("holder_apply_u_ticket")
    except OSError:
        simple_log("info", f"")
        simple_log("info", f"+ Connection is closed by peer.")


if __name__ == "__main__":
    # Environment.DEPLOYMENT_ENV = "PRODUCTION"
    Environment.DEPLOYMENT_ENV = "DEMO"
    try:
        ########################################################################
        # Bluetooth Service Lifecycle: Connect New Connection
        ########################################################################
        connecting_socket = ConnectingWorker(
            service_uuid=bt_service.SERVICE_UUID,
            service_name=bt_service.SERVICE_NAME,
            reconnect_times=bt_service.RECONNECT_TIMES,
            reconnect_interval=bt_service.RECONNECT_INTERVAL,
        )
        connection_socket = connecting_socket.connect()

        ########################################################################
        # Bluetooth Service Lifecycle: Receive & Send in Connection
        ########################################################################
        agent_event_loop(connection_socket)

        ########################################################################
        # Bluetooth Service Lifecycle: Close Connection
        ########################################################################
        connection_socket.close()

    except Exception as error:
        simple_log("error", f"{error}")
