# Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

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
    def measure_process_start(self) -> None:
        start_process_timer()
        start_perf_timer()

    def measure_cli_process_time(self, cli_name: str) -> None:
        # Response Time
        cli_process_time: float = get_process_time()
        cli_perf_time: float = get_perf_time()
        cli_blocked_time: float = abs(cli_perf_time - cli_process_time)

        # Print
        simple_log("measure", f"")
        simple_log("measure", f"+ Receive CLI Input: {cli_name}")
        simple_log("measure", f"cli_process_time = {cli_process_time:.3f} seconds")
        simple_log("measure", f"cli_perf_time = {cli_perf_time:.3f} seconds")
        if cli_blocked_time > Environment.IO_BLOCKING_TOLELANCE_TIME:
            simple_log("warning", f"+ I/O MAYBE BLOCKED TOO LONG...")
            simple_log("warning", f"cli_blocked_time = {cli_blocked_time:.3f} seconds")

    def measure_comm_process_time(self, comm_name: str) -> None:
        # Response Time
        comm_process_time: float = get_process_time()
        comm_perf_time: float = get_perf_time()
        comm_blocked_time: float = abs(comm_perf_time - comm_process_time)

        # Print
        simple_log("measure", f"comm_process_time = {comm_process_time:.3f} seconds")
        simple_log("measure", f"comm_perf_time = {comm_perf_time:.3f} seconds")
        if comm_blocked_time > Environment.IO_BLOCKING_TOLELANCE_TIME:
            simple_log("warning", f"+ I/O MAYBE BLOCKED TOO LONG...")
            simple_log(
                "warning", f"comm_blocked_time = {comm_blocked_time:.3f} seconds"
            )
        simple_log("measure", f"+ Receive Comm Input: {comm_name}")
        simple_log("measure", f"")

    ######################################################
    # Measurement Helper:
    #   Comm Response Time
    ######################################################
    def measure_comm_start(self) -> None:
        start_comm_timer()

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
    def measure_message_size(self, received_message_with_header: str) -> None:
        # Data Size
        message_size: int = simple_size_calculator(received_message_with_header)

        # Print
        simple_log("measure", f"message_size = {message_size} bytes")
