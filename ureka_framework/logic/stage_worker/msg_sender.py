# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Resource (Comm)
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Threading
import time


class MsgSender:
    def __init__(self, shared_data: SharedData, comm_channel: FakeCommChannel) -> None:
        self.shared_data = shared_data
        self.comm_channel = comm_channel

    ######################################################
    # [STAGE: (S)] Send Message
    ######################################################
    def _send_xxx_message(self, sent_message_json: str) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is sending message to {self.comm_channel.end.shared_data.this_device.device_name}...",
        )

        # Simulate Network Delay
        for i in range(3):
            for i in range(3):
                simple_log("info", f"+ network delay")
            if Environment.DEPLOYMENT_ENV == "PRODUCTION":  # pragma: no cover
                time.sleep(0.5)
            elif Environment.DEPLOYMENT_ENV == "DEMO":  # pragma: no cover
                time.sleep(0.5)

        self.comm_channel.sender_queue.put(sent_message_json)
