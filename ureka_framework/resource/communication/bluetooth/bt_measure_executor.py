# Resource (Logger)
from ureka_framework.resource.communication.bluetooth.bt_logger import bt_simple_log

# Resource (Measurer)
from ureka_framework.resource.communication.bluetooth.bt_measurer import (
    start_process_timer,
    get_process_time,
    start_comm_timer,
    get_comm_time,
    simple_size_calculator,
)


######################################################
# Measurement Helper:
#   Data Size + Process Response Time
######################################################
def measure_process_start() -> None:
    start_process_timer()


def measure_cli_process(cli_name: str) -> None:
    # Response Time
    process_time_xxx: float = get_process_time()

    # Print
    bt_simple_log("debug", f"")
    bt_simple_log("debug", f"+ Receive UI Input: {cli_name}")
    bt_simple_log("debug", f"process_time_xxx = {process_time_xxx:.4f} seconds")


def measure_comm_process(comm_name: str, sent_r_ticket_str) -> None:
    # Data Size
    message_size_xxx: int = simple_size_calculator(sent_r_ticket_str)

    # Response Time
    process_time_xxx: float = get_process_time()

    # Print
    bt_simple_log("debug", f"")
    bt_simple_log("debug", f"+ Receive Comm Input: {comm_name}")
    # simple_log("debug", f"+ Received Message: {sent_r_ticket_str}")
    bt_simple_log("debug", f"message_size_xxx = {message_size_xxx} bytes")
    bt_simple_log("debug", f"process_time_xxx = {process_time_xxx:.4f} seconds")


######################################################
# Measurement Helper:
#   Comm Response Time
######################################################
def measure_comm_start() -> None:
    start_comm_timer()


def measure_comm_time(comm_name: str, received_message_json) -> None:
    # Data Size
    message_size_xxx: int = simple_size_calculator(received_message_json)

    # Response Time
    comm_time_xxx: float = get_comm_time()

    # Print
    bt_simple_log("debug", f"")
    bt_simple_log("debug", f"+ Receive Comm Input: {comm_name}")
    # simple_log("debug", f"+ Received Message: {received_message_json}")
    bt_simple_log("debug", f"message_size_xxx = {message_size_xxx} bytes")
    bt_simple_log("debug", f"comm_time_xxx = {comm_time_xxx:.4f} seconds")
