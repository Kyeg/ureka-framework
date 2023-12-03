import time
import inspect

######################################################
# Response Time Measurement (Process)
######################################################
# start timer
start_process: float = 0.0
start_perf_counter: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_process: float = 0.0
end_perf_counter: float = 0.0

# elapsed time
elapsed_process_time: float = 0.0
elapsed_perf_time: float = 0.0


def start_process_timer() -> None:
    global start_process

    start_process = time.process_time()


def start_perf_timer() -> None:
    global start_perf_counter

    start_perf_counter = time.perf_counter()


def get_process_time() -> float:
    global start_process
    global elapsed_process_time

    end_process = time.process_time()

    elapsed_process_time = end_process - start_process
    return elapsed_process_time


def get_perf_time() -> float:
    global start_perf_counter
    global elapsed_perf_time

    end_perf_counter = time.perf_counter()

    elapsed_perf_time = end_perf_counter - start_perf_counter
    return elapsed_perf_time


######################################################
# Response Time Measurement (RTT-based Comm.)
######################################################
# start timer
start_comm: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_comm: float = 0.0
elapsed_comm_time: float = 0.0


def start_comm_timer() -> None:
    global start_comm

    # start_comm = time.process_time()
    start_comm = time.perf_counter()


def get_comm_time() -> float:
    global start_comm
    global elapsed_comm_time

    # end_comm = time.process_time()
    end_comm = time.perf_counter()
    elapsed_comm_time = end_comm - start_comm
    return elapsed_comm_time


######################################################
# Data Size Measurement
######################################################
def simple_size_calculator(message: str) -> int:
    return len(message.encode("UTF-8"))
