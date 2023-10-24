import logging
from ureka_framework.environment import Environment
import time

######################################################
# Response Time Measurement
######################################################
# start timer
start_process: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_process: float = 0.0
elapsed_process_time: float = 0.0


def start_simple_timer() -> None:
    global start_process

    start_process = time.process_time()


def get_process_time() -> float:
    global start_process
    global elapsed_process_time

    end_process = time.process_time()
    elapsed_process_time = end_process - start_process
    return elapsed_process_time


######################################################
# Data Size Measurement
######################################################
def simple_size_calculator(message: str) -> int:
    return len(message.encode("utf-8"))
