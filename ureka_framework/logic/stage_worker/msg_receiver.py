# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Resource (Bluetooth Comm)
try:
    HAS_PYBLUEZ = True
    import ureka_framework.resource.communication.bluetooth.bluetooth_service as bt_service
    from ureka_framework.resource.communication.bluetooth.bluetooth_service import (
        AcceptSocket,
        ConnectingWorker,
        ConnectionSocket,
    )
except ImportError:
    HAS_PYBLUEZ = False
    # raise RuntimeError(
    #     "PyBlueZ not found - only support SIMULATED comm but not BLUETOOTH comm"
    # )

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Threading
import threading

# Stage Worker
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier
from ureka_framework.logic.stage_worker.executor import Executor
from ureka_framework.logic.stage_worker.msg_sender import MsgSender
from ureka_framework.model.message_model.u_ticket import UTicket, u_ticket_to_jsonstr
from ureka_framework.model.message_model.r_ticket import RTicket, r_ticket_to_jsonstr

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_issue_u_ticket import FlowIssueUTicket
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket
from ureka_framework.logic.pipeline_flow.flow_open_session import FlowOpenSession
from ureka_framework.logic.pipeline_flow.flow_issue_u_token import FlowIssueUToken

# Prevent circular import by TYPE_CHECKING (mypy's recommanded trick through forward declarations)
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover -> TYPE_CHECKING
    from ureka_framework.logic.device_controller import DeviceController


class MsgReceiver:
    def __init__(
        self,
        shared_data: SharedData,
        msg_verifier: MsgVerifier,
        executor: Executor,
        msg_sender: MsgSender,
        flow_issuer_issue_u_ticket: FlowIssueUTicket,
        flow_apply_u_ticket: FlowApplyUTicket,
        flow_open_session: FlowOpenSession,
        flow_issue_u_token: FlowIssueUToken,
    ) -> None:
        self.shared_data = shared_data
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_sender = msg_sender
        self.flow_issuer_issue_u_ticket = flow_issuer_issue_u_ticket
        self.flow_apply_u_ticket = flow_apply_u_ticket
        self.flow_open_session = flow_open_session
        self.flow_issue_u_token = flow_issue_u_token

    ######################################################
    # Resource (Simulated Comm)
    #   Threading Issue:
    #       Pytest finishes this test when main thread is finished
    #           (& all daemon threads, e.g. all receiver_threads will also be terminated)
    #       In production, we may need Ctrl+C or other shutdown method to stop this loop program
    ######################################################
    def create_simulated_comm_connection(self, end: "DeviceController") -> None:
        # simple_log("info",
        #     f"+ {self.shared_data.this_device.device_name} is connecting with {end.shared_data.this_device.device_name}..."
        # )

        # Set Sender (on Main Thread)
        self.shared_data.simulated_comm_channel.end = end
        self.shared_data.simulated_comm_channel.sender_queue = (
            end.shared_data.simulated_comm_channel.receiver_queue
        )
        # Start Reciever Thread
        receiver_thread = threading.Thread(target=self._recv_xxx_message, daemon=True)
        receiver_thread.start()

    ######################################################
    # Resource (Bluetooth Comm)
    ######################################################
    def accept_bluetooth_comm(self) -> None:
        self.shared_data.accept_socket = AcceptSocket(
            service_uuid=bt_service.SERVICE_UUID,
            service_name=bt_service.SERVICE_NAME,
        )
        self.shared_data.connection_socket: ConnectionSocket = (
            self.shared_data.accept_socket.accept()
        )

    # def start_receiver_thread(self) -> None:
    #     # Start Reciever Thread
    #     receiver_thread = threading.Thread(target=self._recv_xxx_message, daemon=True)
    #     receiver_thread.start()

    def close_bluetooth_connection(self) -> None:
        self.shared_data.connection_socket.close()

    def close_bluetooth_acception(self) -> None:
        self.shared_data.accept_socket.close()

    ######################################################
    # [STAGE: (R)] Receive Message
    ######################################################
    def _recv_xxx_message(self):
        while True:
            try:
                # [STAGE: (R)]
                if Environment.COMMUNICATION_CHANNEL == "SIMULATED":
                    # This will block until message is received
                    message = (
                        self.shared_data.simulated_comm_channel.receiver_queue.get()
                    )

                    simple_log(
                        "info",
                        f"+ {self.shared_data.this_device.device_name} is receiving message "
                        f"from {self.shared_data.simulated_comm_channel.end.shared_data.this_device.device_name}...",
                    )
                else:  # pragma: no cover -> PRODUCTION
                    # This will block until message is received
                    try:
                        ########################################################################
                        # Start Comm Measurement
                        ########################################################################
                        self.executor.measure_comm_start()
                        message = self.shared_data.connection_socket.recv_message()
                        ########################################################################
                        # End Comm Measurement
                        ########################################################################
                        self.executor.measure_comm_time(
                            "holder_or_device_recv_u_or_r_ticket", message
                        )
                        simple_log(
                            "info",
                            f"+ {self.shared_data.this_device.device_name} is receiving message "
                            f"from BT_address or BT_name...",
                        )
                    except OSError:
                        simple_log("info", f"")
                        simple_log("info", f"+ Connection is closed by peer.")
                        break

                ######################################################
                # Start Process Measurement
                ######################################################
                self.executor.measure_process_start()

                # [STAGE: (VR)]
                received_message = self.msg_verifier._classify_message_is_defined_type(
                    message
                )
                if type(received_message) == UTicket:
                    self.shared_data.received_message_json = u_ticket_to_jsonstr(
                        received_message
                    )
                elif type(received_message) == RTicket:
                    self.shared_data.received_message_json = r_ticket_to_jsonstr(
                        received_message
                    )
                simple_log(
                    "cli",
                    f"Received Message: {self.shared_data.received_message_json}",
                )

                # IOT_DEVICE
                if self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_UT:
                    self.flow_apply_u_ticket._device_recv_u_ticket(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_device_recv_u_ticket")
                    # End Simulated Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.msg_sender.close_simulated_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CRKE2:
                    self.flow_open_session._device_recv_cr_ke_2(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_device_recv_cr_ke_2")
                    # End Simulated Comm
                    simple_log(
                        "cli",
                        f"plaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (device)")
                    self.msg_sender.close_simulated_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CMD:
                    # Flow
                    self.flow_issue_u_token._device_recv_cmd(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_device_recv_cmd")
                    # End Simulated Comm
                    simple_log(
                        "cli",
                        f"plaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (device)")
                    self.msg_sender.close_simulated_comm()

                # USER_AGENT_OR_CLOUD_SERVER
                elif (
                    self.shared_data.state
                    == this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                ):
                    if type(received_message) == UTicket:
                        # Flow
                        self.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
                            received_message
                        )
                        ######################################################
                        # End Process Measurement
                        ######################################################
                        self.executor.measure_comm_process(
                            "_holder_recv_u_ticket",
                        )
                        # End Simulated/Bluetooth Comm
                        simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                        self.msg_sender.close_simulated_comm()
                    elif type(received_message) == RTicket:
                        # Flow
                        self.flow_issuer_issue_u_ticket._issuer_recv_r_ticket(
                            received_message
                        )
                        ######################################################
                        # End Process Measurement
                        ######################################################
                        self.executor.measure_comm_process(
                            "_issuer_recv_r_ticket",
                        )
                        # End Simulated Comm
                        simple_log("debug", f"+ Finish RT-RT~~ (issuer)")
                        self.msg_sender.close_simulated_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_RT:
                    # Flow
                    self.flow_apply_u_ticket._holder_recv_r_ticket(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_holder_recv_r_ticket")
                    # End Simulated/Bluetooth Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.msg_sender.close_simulated_comm()
                    if Environment.COMMUNICATION_CHANNEL == "BLUETOOTH":
                        self.msg_sender.close_bluetooth_connection()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE1:
                    # Flow
                    self.flow_open_session._holder_recv_cr_ke_1(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_holder_recv_cr_ke_1")
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE3:
                    # Flow
                    self.flow_open_session._holder_recv_cr_ke_3(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_holder_recv_cr_ke_3")
                    simple_log(
                        "cli",
                        f"plaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log(
                        "cli",
                        f"+++Session is Constucted+++",
                    )
                    # End Simulated/Bluetooth Comm
                    simple_log("debug", f"+ Finish CR-KE~~ (holder)")
                    self.msg_sender.close_simulated_comm()
                    if Environment.COMMUNICATION_CHANNEL == "BLUETOOTH":
                        self.msg_sender.close_bluetooth_connection()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_DATA:
                    # Flow
                    self.flow_issue_u_token._holder_recv_data(received_message)
                    ######################################################
                    # End Process Measurement
                    ######################################################
                    self.executor.measure_comm_process("_holder_recv_data")
                    simple_log(
                        "cli",
                        f"plaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    # End Simulated/Bluetooth Comm
                    simple_log("debug", f"+ Finish PS~~ (holder)")
                    self.msg_sender.close_simulated_comm()
                    if Environment.COMMUNICATION_CHANNEL == "BLUETOOTH":
                        self.msg_sender.close_bluetooth_connection()
                else:  # pragma: no cover -> Shouldn't Reach Here
                    raise RuntimeError(f"Shouldn't Reach Here")

            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
                # TODO: device_send_error_r_ticket (Sterilization)
                self.shared_data.result_message = f"{error}"
                raise RuntimeError(f"{error}")

            except:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
