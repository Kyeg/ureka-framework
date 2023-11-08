# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from pydantic import ValidationError
import ureka_framework.model.message_model.message as message
from ureka_framework.model.message_model.message import Message, message_to_jsonstr
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework.model.message_model.u_ticket as r_ticket

# Resource (Simulated Comm)
from ureka_framework.resource.communication.simulated_comm.simulated_comm_channel import (
    SimulatedCommChannel,
)

# Resource (Bluetooth Comm)
import ureka_framework.resource.communication.bluetooth.bluetooth_service as bt_service
from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
    ConnectingWorker,
    ConnectionSocket,
)

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Threading
import time


class MsgSender:
    def __init__(
        self,
        shared_data: SharedData,
    ) -> None:
        self.shared_data = shared_data

    ######################################################
    # Resource (Simulated Comm)
    ######################################################
    def wait_simulated_comm_completed(self) -> None:
        while not self.shared_data.comm_done_flag:
            time.sleep(Environment.INTERRUPT_CYCLE_TIME)
        # simple_log("info",f"{self.shared_data.this_device.device_name}: this communication is completed")

    def close_simulated_comm(self) -> None:
        self.shared_data.comm_done_flag = True

    def re_open_simulated_comm(self) -> None:
        self.shared_data.comm_done_flag = False

    ######################################################
    # Resource (Bluetooth Comm)
    ######################################################
    def connect_bluetooth_comm(self) -> None:
        self.shared_data.connecting_worker = ConnectingWorker(
            service_uuid=bt_service.SERVICE_UUID,
            service_name=bt_service.SERVICE_NAME,
            reconnect_times=bt_service.RECONNECT_TIMES,
            reconnect_interval=bt_service.RECONNECT_INTERVAL,
        )
        self.shared_data.connection_socket: ConnectionSocket = (
            self.shared_data.connecting_worker.connect()
        )

    def close_bluetooth_connection(self) -> None:
        self.shared_data.connection_socket.close()

    ######################################################
    # [STAGE: (S)] Send Message
    ######################################################
    def _send_xxx_message(
        self, message_operation: str, message_type: str, sent_message_json: str
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is sending message to {self.shared_data.simulated_comm_channel.end.shared_data.this_device.device_name}...",
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
            except ValidationError as error:  # pragma: no cover -> Weird M-Request
                raise RuntimeError(f"Weird M-Request: {error}")
        else:  # pragma: no cover -> Weird M-Request
            raise RuntimeError("Weird M-Request")

        # # Simulate Network Delay
        # for i in range(3):
        #     for i in range(3):
        #         simple_log("info", f"+ network delay")
        #     if (
        #         Environment.DEPLOYMENT_ENV == "PRODUCTION"
        #     ):  # pragma: no cover -> PRODUCTION
        #         time.sleep(Environment.NETWORK_DELAY)
        #     elif Environment.DEPLOYMENT_ENV == "DEMO":  # pragma: no cover -> PRODUCTION
        #         time.sleep(Environment.NETWORK_DELAY)

        # self.shared_data.simulated_comm_channel.sender_queue.put(sent_message_json)
        self.shared_data.simulated_comm_channel.sender_queue.put(new_message_json)
