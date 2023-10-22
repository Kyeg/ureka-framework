# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from pydantic import ValidationError
import ureka_framework.model.message_model.message as message
from ureka_framework.model.message_model.message import Message, message_to_jsonstr
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework.model.message_model.u_ticket as r_ticket

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
    def _send_xxx_message(
        self, message_operation: str, message_type: str, sent_message_json: str
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is sending message to {self.comm_channel.end.shared_data.this_device.device_name}...",
        )

        # Generate Message
        if (
            message_operation == message.MESSAGE_RECV_AND_STORE
            or message.MESSAGE_VERIFY_AND_EXECUTE
        ) and (message_type == u_ticket.MESSAGE_TYPE or r_ticket.MESSAGE_TYPE):
            message_request: dict = {
                "message_operation": f"{message_operation}",
                "message_type": f"{message_type}",
                "message_str": f"{sent_message_json}",
            }
            try:
                new_message = Message(**message_request)
                new_message_json = message_to_jsonstr(new_message)
                # simple_log("debug", f"sent_message_json: {new_message_json}")
            except ValidationError as error:  # pragm: no cover -> Weird M-Request
                raise RuntimeError(f"Weird M-Request: {error}")
        else:  # pragm: no cover -> Weird M-Request
            raise RuntimeError("Weird M-Request")

        # Simulate Network Delay
        for i in range(3):
            for i in range(3):
                simple_log("info", f"+ network delay")
            if Environment.DEPLOYMENT_ENV == "PRODUCTION":  # pragm: no cover
                time.sleep(0.5)
            elif Environment.DEPLOYMENT_ENV == "DEMO":  # pragm: no cover
                time.sleep(0.5)

        # self.comm_channel.sender_queue.put(sent_message_json)
        self.comm_channel.sender_queue.put(new_message_json)
