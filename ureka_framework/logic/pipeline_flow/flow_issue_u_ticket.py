# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message_model.message as message
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket, jsonstr_to_u_ticket
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


class FlowIssueUTicket:
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
    # CST: issuer_issue_u_ticket_to_herself()
    # TODO: REQ: _issuer_recv_request() <- holder_send_request_to_issuer()
    # CST: issuer_issue_u_ticket_to_holder() -> _holder_recv_u_ticket()
    # TODO: RTN: _issuer_recv_r_ticket() <- holder_send_r_ticket_to_issuer()
    #
    # TODO: More complete Tx (with DID, etc.))
    # TODO: Rollback (e.g., delete the temporary stored state and stored message) if fail
    #         execution only change state after success, but need pay attention to (SR)
    ######################################################
    def issuer_issue_u_ticket_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table or device_id == "no_id":
                # [STAGE: (G)]
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(arbitrary_dict)
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                self.generated_msg_storer._store_generated_xxx_u_ticket(
                    generated_u_ticket_json
                )

                # [STAGE: (O)]
                self.executor._execute_update_ticket_order(
                    "holder-generate-or-receive-uticket",
                    jsonstr_to_u_ticket(generated_u_ticket_json),
                )

        except RuntimeError:  # pragma: no cover -> Weird U-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def issuer_issue_u_ticket_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (G)]
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(arbitrary_dict)
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # TODO: RTN
                # [STAGE: (SG)]
                self.generated_msg_storer._store_generated_xxx_u_ticket(
                    generated_u_ticket_json
                )

                # [STAGE: (S)]
                self.msg_sender._send_xxx_message(
                    message.MESSAGE_RECV_AND_STORE,
                    u_ticket.MESSAGE_TYPE,
                    generated_u_ticket_json,
                )

                # End Comm
                simple_log("debug", f"+ Finish UT-UT~~ (issuer)")
                self.executor.complete_comm()

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> Weird U-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]
            # But the actual device id & ticket order in device is still unknown
            # -> TODO: test_fail_when_double_issuing_or_double_spending

            # [STAGE: (SR)]
            self.received_msg_storer._store_received_xxx_u_ticket(received_u_ticket)

            # [STAGE: (O)]
            self.executor._execute_update_ticket_order(
                "holder-generate-or-receive-uticket", received_u_ticket
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (VR)
            failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # [STAGE: (G)(S)]
            # Can optionally _generate_xxx_r_ticket & _send_xxx_message
            pass

    # TODO: RTN
    def holder_send_r_ticket_to_issuer(self, device_id: str) -> None:
        try:
            # [STAGE: (VL)(L)]
            stored_r_ticket_json: str = self.shared_data.device_table[
                device_id
            ].device_u_ticket_for_owner
            # simple_log("debug",f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(
                message.MESSAGE_RECV_AND_STORE,
                r_ticket.MESSAGE_TYPE,
                stored_r_ticket_json,
            )

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    # TODO: RTN
    def _issuer_recv_r_ticket(self, received_r_ticket: RTicket) -> None:
        pass
