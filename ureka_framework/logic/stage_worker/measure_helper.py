# Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import (
    start_process_timer,
    start_perf_timer,
    get_process_time,
    get_perf_time,
    start_comm_timer,
    get_comm_time,
    simple_size_calculator,
)


class MeasureHelper:
    def __init__(self, shared_data: SharedData) -> None:
        self.shared_data = shared_data

    ######################################################
    # Measurement Helper:
    #   Process Response Time
    ######################################################
    @measure_worker_func
    def measure_process_perf_start(self) -> None:
        start_process_timer()
        start_perf_timer()

    @measure_worker_func
    def measure_recv_cli_perf_time(self, cli_name: str) -> None:
        # Response Time
        cli_process_time: float = get_process_time()
        cli_perf_time: float = get_perf_time()
        cli_blocked_time: float = abs(cli_perf_time - cli_process_time)

        # Print
        simple_log("measure", f"")
        simple_log("measure", f"+ Receive CLI Input: {cli_name}")
        simple_log("measure", f"cli_perf_time = {cli_perf_time:.3f} seconds")
        if cli_blocked_time > Environment.IO_BLOCKING_TOLERANCE_TIME:
            simple_log("warning", f"+ I/O MAYBE BLOCKED TOO LONG...")
            simple_log("warning", f"cli_blocked_time = {cli_blocked_time:.3f} seconds")

    @measure_worker_func
    def measure_recv_msg_perf_time(self, comm_name: str) -> None:
        # Response Time
        msg_process_time: float = get_process_time()
        msg_perf_time: float = get_perf_time()
        msg_blocked_time: float = abs(msg_perf_time - msg_process_time)

        # Print
        simple_log("measure", f"msg_perf_time = {msg_perf_time:.3f} seconds")
        if msg_blocked_time > Environment.IO_BLOCKING_TOLERANCE_TIME:
            simple_log("warning", f"+ I/O MAYBE BLOCKED TOO LONG...")
            simple_log("warning", f"msg_blocked_time = {msg_blocked_time:.3f} seconds")
        simple_log("measure", f"+ Receive Message Input: {comm_name}")
        simple_log("measure", f"")

    ######################################################
    # Measurement Helper:
    #   Comm Response Time
    ######################################################
    @measure_worker_func
    def measure_comm_perf_start(self) -> None:
        start_comm_timer()

    @measure_worker_func
    def measure_comm_time(self, comm_name: str) -> None:
        # Response Time
        comm_time: float = get_comm_time()

        # Print
        simple_log("measure", f"")
        simple_log("measure", f"+ Receive Comm Input: {comm_name}")
        simple_log("measure", f"comm_time = {comm_time:.3f} seconds")

    ######################################################
    # Measurement Helper:
    #   Data Size
    ######################################################
    @measure_worker_func
    def measure_message_size(self, received_message_with_header: str) -> None:
        # Data Size
        message_size: int = simple_size_calculator(received_message_with_header)

        # Print
        simple_log("measure", f"message_size = {message_size} bytes")
