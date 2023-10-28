# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Resource (Comm)
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Threading
import threading

# Stage Worker
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier
from ureka_framework.logic.stage_worker.executor import Executor
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
        comm_channel: FakeCommChannel,
        msg_verifier: MsgVerifier,
        executor: Executor,
        flow_issuer_issue_u_ticket: FlowIssueUTicket,
        flow_apply_u_ticket: FlowApplyUTicket,
        flow_open_session: FlowOpenSession,
        flow_issue_u_token: FlowIssueUToken,
    ) -> None:
        self.shared_data = shared_data
        self.comm_channel = comm_channel
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.flow_issuer_issue_u_ticket = flow_issuer_issue_u_ticket
        self.flow_apply_u_ticket = flow_apply_u_ticket
        self.flow_open_session = flow_open_session
        self.flow_issue_u_token = flow_issue_u_token

    ######################################################
    # [STAGE: (R)] Receive Message
    ######################################################
    def _connect(self, end: "DeviceController") -> None:
        # simple_log("info",
        #     f"+ {self.shared_data.this_device.device_name} is connecting with {end.shared_data.this_device.device_name}..."
        # )
        # Set Sender (on Main Thread)
        self.comm_channel.end = end
        self.comm_channel.sender_queue = end.comm_channel.receiver_queue
        # Start Reciever Thread
        receiver_thread = threading.Thread(target=self._recv_xxx_message, daemon=True)
        receiver_thread.start()

    def _recv_xxx_message(self):
        while True:
            try:
                # [STAGE: (R)]
                # This will block until message is received
                message = self.comm_channel.receiver_queue.get()

                ######################################################
                # Start Measurement
                ######################################################
                self.executor._start_timer()

                simple_log(
                    "info",
                    f"+ {self.shared_data.this_device.device_name} is receiving message from {self.comm_channel.end.shared_data.this_device.device_name}...",
                )

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
                # simple_log(
                #     "demo",
                #     f"Received Message: {self.shared_data.received_message_json}",
                # )

                # IOT_DEVICE
                if self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_UT:
                    self.flow_apply_u_ticket._device_recv_u_ticket(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CRKE2:
                    self.flow_open_session._device_recv_cr_ke_2(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (device)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CMD:
                    ######################################################
                    # Flow
                    ######################################################
                    self.flow_issue_u_token._device_recv_cmd(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (device)")
                    self.executor.complete_comm()

                # USER_AGENT_OR_CLOUD_SERVER
                elif (
                    self.shared_data.state
                    == this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                ):
                    if type(received_message) == UTicket:
                        ######################################################
                        # Flow
                        ######################################################
                        self.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
                            received_message
                        )
                        ######################################################
                        # End Measurement
                        ######################################################
                        self.executor._measure_comm_input_flow(
                            self.shared_data.received_message_json
                        )
                        ######################################################
                        # End Comm
                        ######################################################
                        simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                        self.executor.complete_comm()
                    elif type(received_message) == RTicket:
                        ######################################################
                        # Flow
                        ######################################################
                        self.flow_issuer_issue_u_ticket._issuer_recv_r_ticket(
                            received_message
                        )
                        ######################################################
                        # End Measurement
                        ######################################################
                        self.executor._measure_comm_input_flow(
                            self.shared_data.received_message_json
                        )
                        ######################################################
                        # End Comm
                        ######################################################
                        simple_log("debug", f"+ Finish RT-RT~~ (issuer)")
                        self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_RT:
                    ######################################################
                    # Flow
                    ######################################################
                    self.flow_apply_u_ticket._holder_recv_r_ticket(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE1:
                    ######################################################
                    # Flow
                    ######################################################
                    self.flow_open_session._holder_recv_cr_ke_1(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE3:
                    ######################################################
                    # Flow
                    ######################################################
                    self.flow_open_session._holder_recv_cr_ke_3(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log(
                        "demo",
                        f"\n+++Session is Constucted+++",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_DATA:
                    ######################################################
                    # Flow
                    ######################################################
                    self.flow_issue_u_token._holder_recv_data(received_message)
                    ######################################################
                    # End Measurement
                    ######################################################
                    self.executor._measure_comm_input_flow(
                        self.shared_data.received_message_json
                    )
                    ######################################################
                    # End Comm
                    ######################################################
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (holder)")
                    self.executor.complete_comm()
                else:  # pragma: no cover -> Shouldn't Reach Here
                    raise RuntimeError(f"Shouldn't Reach Here")

            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
                # TODO: device_send_error_r_ticket (Sterilization)
                self.shared_data.result_message = f"{error}"
                raise RuntimeError(f"{error}")

            except:  # pragma: no cover -> Shouldn't Reach Here
                raise RuntimeError(f"Shouldn't Reach Here")
