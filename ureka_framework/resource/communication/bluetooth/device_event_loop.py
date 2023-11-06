# Resource (Comm)
import bluetooth_service as bt_service
from bluetooth_service import AcceptSocket, ConnectionSocket

# Resource (Logger)
from bt_logger import simple_log

# Resource (Measurer)
from bt_measure_executor import (
    measure_process_start,
    measure_cli_process,
    measure_comm_process,
    measure_comm_start,
    measure_comm_time,
)


def device_event_loop(connection_socket: ConnectionSocket):
    try:
        while True:
            ########################################################################
            # Connection Socket: Receive
            ########################################################################
            received_u_ticket_str: str = connection_socket.recv_message()
            simple_log("debug", f"")
            simple_log("debug", f"received_u_ticket_str = {received_u_ticket_str}")
            if received_u_ticket_str == "exit":
                simple_log("info", f"")
                simple_log("info", f"+ Connection is closed by peer.")
                break

            # TODO: Contoller, e.g., echo the message
            # Start Process Measurement
            measure_process_start()
            ########################################################################
            # Data Processing
            ########################################################################
            generated_r_ticket_str: str = f"R<<<{received_u_ticket_str}>>>"
            # End Process Measurement
            measure_cli_process("device_send_r_ticket")

            ########################################################################
            # Connection Socket: Send
            ########################################################################
            connection_socket.send_message(generated_r_ticket_str)
    except OSError:
        simple_log("info", f"")
        simple_log("info", f"+ Connection is closed by peer.")


if __name__ == "__main__":
    try:
        ########################################################################
        # Bluetooth Service Lifecycle: Accept New Connection
        ########################################################################
        accept_socket = AcceptSocket(
            service_uuid=bt_service.SERVICE_UUID,
            service_name=bt_service.SERVICE_NAME,
        )
        connecting_socket = accept_socket.accept()

        ########################################################################
        # Bluetooth Service Lifecycle: Receive & Send in Connection
        ########################################################################
        device_event_loop(connecting_socket)

        ########################################################################
        # Bluetooth Service Lifecycle: Close Connection
        ########################################################################
        connecting_socket.close()

        ########################################################################
        # Bluetooth Service Lifecycle: Stop Accepting New Connections
        ########################################################################
        accept_socket.close()

    except Exception as error:
        simple_log("error", f"{error}")
