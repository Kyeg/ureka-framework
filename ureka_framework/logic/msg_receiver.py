# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Resource (Comm)
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Stage Worker
from ureka_framework.logic.msg_verifier import MsgVerifier
from ureka_framework.logic.executor import Executor

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_issue_u_ticket import FlowIssueUTicket
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket
from ureka_framework.logic.pipeline_flow.flow_open_session import FlowOpenSession
from ureka_framework.logic.pipeline_flow.flow_issue_u_token import FlowIssueUToken


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

    def _recv_xxx_message(self) -> str:
        while True:
            try:
                # [STAGE: (R)]
                # This will block until message is received
                received_message_json = self.comm_channel.receiver_queue.get()
                simple_log(
                    "info",
                    f"+ {self.shared_data.this_device.device_name} is receiving message from {self.comm_channel.end.shared_data.this_device.device_name}...",
                )
                simple_log("demo", f"Received Message: {received_message_json}")

                # [STAGE: (VR)]
                received_message = self.msg_verifier._classify_message_is_defined_type(
                    received_message_json
                )

                # IOT_DEVICE
                if self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_UT:
                    self.flow_apply_u_ticket._device_recv_u_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CRKE2:
                    self.flow_open_session._device_recv_cr_ke_2(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (device)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CMD:
                    self.flow_issue_u_token._device_recv_cmd(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
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
                    self.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
                        received_message
                    )
                    # End Comm
                    simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_RT:
                    self.flow_apply_u_ticket._holder_recv_r_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE1:
                    self.flow_open_session._holder_recv_cr_ke_1(received_message)
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE3:
                    self.flow_open_session._holder_recv_cr_ke_3(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
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
                    self.flow_issue_u_token._holder_recv_data(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (holder)")
                    self.executor.complete_comm()
                else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                    simple_log("error", "weird ticket type")

            except (
                RuntimeError
            ):  # pragma: no cover -> FAILURE: (VR) TODO: device_send_error_r_ticket (Sterilization)
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)

            except:  # pragma: no cover -> Unpredicted Error
                failure_msg = f"FAILURE: UNPREDICTED ERROR"
                simple_log("error", failure_msg)
