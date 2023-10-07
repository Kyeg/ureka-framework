# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message.u_ticket as u_ticket
from ureka_framework.model.message.u_ticket import UTicket
import ureka_framework.model.message.r_ticket as r_ticket
from ureka_framework.model.message.r_ticket import RTicket

# Resource (Crypto)
from ureka_framework.resource.crypto.serialization_util import base64str_backto_byte

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Stage Worker
from ureka_framework.logic.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.msg_verifier import MsgVerifier
from ureka_framework.logic.executor import Executor
from ureka_framework.logic.msg_generator import MsgGenerator
from ureka_framework.logic.generated_msg_storer import GeneratedMsgStorer
from ureka_framework.logic.msg_sender import MsgSender

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket


class FlowIssueUToken:
    def __init__(
        self,
        share_data: SharedData,
        received_msg_storer: ReceivedMsgStorer,
        msg_verifier: MsgVerifier,
        executor: Executor,
        msg_generator: MsgGenerator,
        generated_msg_storer: GeneratedMsgStorer,
        msg_sender: MsgSender,
        flow_apply_u_ticket: FlowApplyUTicket,
    ) -> None:
        self.shared_data = share_data
        self.received_msg_storer = received_msg_storer
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_generator = msg_generator
        self.generated_msg_storer = generated_msg_storer
        self.msg_sender = msg_sender
        self.flow_apply_u_ticket = flow_apply_u_ticket

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (PS):
    #       holder_send_cmd()   -> _device_recv_cmd()
    #       _holder_recv_data() <- _device_send_data()
    #                           ...
    #                       ..repeated..
    #                           ...
    #       holder_send_cmd(tx_end) -> _device_recv_cmd(tx_end)
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    ######################################################
    def holder_send_cmd(self, device_id: str, cmd: str, tx_end: bool = False) -> None:
        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (E)]
                # Update Session: PS
                self.shared_data.current_session.plaintext_cmd = cmd
                self.shared_data.current_session.associated_plaintext_cmd = (
                    "additional unencrypted cmd"
                )
                # Message Encryption (str + key byte)
                self.executor._execute_cmd_encryption(
                    base64str_backto_byte(
                        self.shared_data.current_session.current_session_key_str
                    )
                )

                if tx_end == False:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_DATA)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_CMD_UTOKEN}"
                else:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_RT)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_TX_END_UTOKEN}"

                # [STAGE: (G)]
                generated_request: dict = {
                    "device_id": f"{self.shared_data.current_session.current_device_id}",
                    "u_ticket_type": f"{u_ticket_type}",
                    "associated_plaintext": f"{self.shared_data.current_session.associated_plaintext_cmd}",
                    "iv": f"{self.shared_data.current_session.iv_cmd}",
                    "ciphertext": f"{self.shared_data.current_session.ciphertext_cmd}",
                    "gcm_authentication_tag": f"{self.shared_data.current_session.gcm_authentication_tag_cmd}",
                }
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(generated_request)
                )
                # simple_log("debug", f"Generated UToken: {generated_u_ticket_json}")

                # [STAGE: (S)]
                self.msg_sender._send_xxx_message(generated_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> Weird UTK-Request (ValidationError)
            failure_msg = f"FAILURE: (VUTKREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cmd(self, received_u_token: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (VUT)]
            self.msg_verifier.verify_u_ticket_can_execute(received_u_token)
            result_message = f"Success (verify_u_ticket_can_execute)"

            # [STAGE: (E)]
            self.executor._execute_xxx_u_ticket(received_u_token)
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                pass
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VUT)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (G)(S)]
                self._device_send_data(result_message)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # [STAGE: (G)(S)]
                self.flow_apply_u_ticket._device_send_r_ticket(
                    received_u_token.u_ticket_type,
                    received_u_token.u_ticket_id,
                    result_message,
                )
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

    def _device_send_data(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            generated_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_DATA_RTOKEN}",
                "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "associated_plaintext_data": f"{self.shared_data.current_session.associated_plaintext_data}",
                "iv_data": f"{self.shared_data.current_session.iv_data}",
                "ciphertext_data": f"{self.shared_data.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.shared_data.current_session.gcm_authentication_tag_data}",
            }
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                generated_request
            )
            # simple_log("debug", f"Generated RToken: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_data(self, received_r_token: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # Query Corresponding UTicket
            # [STAGE: (VL)]
            device_id = received_r_token.device_id
            stored_u_ticket_json = self.shared_data.device_table[
                device_id
            ].device_u_ticket
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (VR)]
            stored_u_ticket = self.msg_verifier._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            try:
                # [STAGE: (VRT)]
                self.msg_verifier.verify_u_ticket_has_successfully_executed_through_r_ticket(
                    r_ticket_in=received_r_token,
                    audit_start_ticket=stored_u_ticket,
                    audit_end_ticket=None,
                )
                result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                # [STAGE: (E)]
                self.executor._execute_xxx_r_ticket(received_r_token)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
                result_message = f"{error}"

            simple_log("debug", f"result_message = {result_message}")

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            if error == "NOT VALID JSON or VALID RTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)
            elif error == "NOT VALID JSON or VALID UTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)
