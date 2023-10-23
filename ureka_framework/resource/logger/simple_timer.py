import logging
from ureka_framework.environment import Environment
import time

# start timer
start_process: float = 0.0

# ...
# time-consuming processing...
# ...

# end timer
end_process: float = 0.0
elapsed_process_time: float = 0.0


def start_simple_timer() -> None:  # pragma: no cover -> PRODUCTION
    global start_process

    start_process = time.process_time()


def get_process_time() -> float:  # pragma: no cover -> PRODUCTION
    global start_process
    global elapsed_process_time

    end_process = time.process_time()
    elapsed_process_time = end_process - start_process
    return elapsed_process_time
