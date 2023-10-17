# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import RTicket

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Stage Worker
from ureka_framework.logic.stage_worker.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.stage_worker.msg_verifier import MsgVerifier
from ureka_framework.logic.stage_worker.executor import Executor
from ureka_framework.logic.stage_worker.msg_generator import MsgGenerator
from ureka_framework.logic.stage_worker.generated_msg_storer import GeneratedMsgStorer
from ureka_framework.logic.stage_worker.msg_sender import MsgSender


class FlowOpenSession:
    def __init__(
        self,
        share_data: SharedData,
        received_msg_storer: ReceivedMsgStorer,
        msg_verifier: MsgVerifier,
        executor: Executor,
        msg_generator: MsgGenerator,
        generated_msg_storer: GeneratedMsgStorer,
        msg_sender: MsgSender,
    ) -> None:
        self.shared_data = share_data
        self.received_msg_storer = received_msg_storer
        self.msg_verifier = msg_verifier
        self.executor = executor
        self.msg_generator = msg_generator
        self.generated_msg_storer = generated_msg_storer
        self.msg_sender = msg_sender

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (CR-KE):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_cr_ke_1() <- _device_send_cr_ke_1()
    #       _holder_send_cr_ke_2() -> _device_recv_cr_ke_2()
    #       _holder_recv_cr_ke_3() <- _device_send_cr_ke_3()
    ######################################################
    def _device_send_cr_ke_1(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE1_RTICKET}",
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.shared_data.current_session.challenge_1}",
                "key_exchange_salt_1": f"{self.shared_data.current_session.key_exchange_salt_1}",
                "iv_cmd": f"{self.shared_data.current_session.iv_cmd}",
            }
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                r_ticket_request
            )
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_1(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]
            # [STAGE: (VRT)]
            self.msg_verifier.verify_u_ticket_has_successfully_executed_through_r_ticket(
                r_ticket_in=received_r_ticket,
                audit_start_ticket=None,
                audit_end_ticket=None,
            )
            result_message = f"-> SUCCESS: VERIFY_UT_HAS_EXECUTED"
            # [STAGE: (E)]
            self.executor._execute_xxx_r_ticket(received_r_ticket)
            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_CRKE3)

            # [STAGE: (G)(S)]
            simple_log("debug", f"result_message = {result_message}")
            self._holder_send_cr_ke_2(result_message)

        except RuntimeError as error:
            result_message = f"{error}"
            # End Comm
            simple_log("debug", f"+ Failed CR-KE~~ (holder)")
            self.executor.complete_comm()

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_send_cr_ke_2(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE2_RTICKET}",
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.shared_data.current_session.challenge_1}",
                "challenge_2": f"{self.shared_data.current_session.challenge_2}",
                "key_exchange_salt_2": f"{self.shared_data.current_session.key_exchange_salt_2}",
                "associated_plaintext_cmd": f"{self.shared_data.current_session.associated_plaintext_cmd}",
                "ciphertext_cmd": f"{self.shared_data.current_session.ciphertext_cmd}",
                "gcm_authentication_tag_cmd": f"{self.shared_data.current_session.gcm_authentication_tag_cmd}",
                "iv_data": f"{self.shared_data.current_session.iv_data}",
            }
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                r_ticket_request
            )
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cr_ke_2(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (VRT)]
            self.msg_verifier.verify_u_ticket_has_successfully_executed_through_r_ticket(
                r_ticket_in=received_r_ticket,
                audit_start_ticket=None,
                audit_end_ticket=None,
            )
            result_message = f"-> SUCCESS: VERIFY_UT_HAS_EXECUTED"
            self.shared_data.result_message = result_message

            # [STAGE: (VTK)(VTS)]
            # [STAGE: (E)]
            self.executor._execute_xxx_r_ticket(received_r_ticket)

            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)

        except RuntimeError as error:
            result_message = f"{error}"
            self.shared_data.result_message = result_message
            # End Comm
            simple_log("debug", f"+ Failed CR-KE~~ (device)")
            self.executor.complete_comm()

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # [STAGE: (G)(S)]
            simple_log("debug", f"result_message = {result_message}")
            self._device_send_cr_ke_3(result_message)

    def _device_send_cr_ke_3(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE3_RTICKET}",
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_2": f"{self.shared_data.current_session.challenge_2}",
                "associated_plaintext_data": f"{self.shared_data.current_session.associated_plaintext_data}",
                "ciphertext_data": f"{self.shared_data.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.shared_data.current_session.gcm_authentication_tag_data}",
                "iv_cmd": f"{self.shared_data.current_session.iv_cmd}",
            }
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                r_ticket_request
            )
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_3(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            try:
                # [STAGE: (VRT)]
                self.msg_verifier.verify_u_ticket_has_successfully_executed_through_r_ticket(
                    r_ticket_in=received_r_ticket,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                )
                result_message = f"-> SUCCESS: VERIFY_UT_HAS_EXECUTED"

                # [STAGE: (VTK)]
                # [STAGE: (E)]
                self.executor._execute_xxx_r_ticket(received_r_ticket)

                # [STAGE: (C)]
                self.executor._change_state(
                    this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                )
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)(VTK)
                result_message = f"{error}"
                # End Comm
                simple_log("debug", f"+ Failed CR-KE~~ (holder)")
                self.executor.complete_comm()

            simple_log("debug", f"result_message = {result_message}")

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)
