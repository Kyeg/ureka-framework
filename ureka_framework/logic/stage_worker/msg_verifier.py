# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData

# Data Model (Message)
from ureka_framework.model.message_model.u_ticket import UTicket
from ureka_framework.model.message_model.r_ticket import RTicket

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Serialization)
from ureka_framework.resource.crypto.serialization_util import jsonstr_to_dict

# Stage Worker
from ureka_framework.logic.stage_worker.msg_verifier_u_ticket import UTicketVerifier
from ureka_framework.logic.stage_worker.msg_verifier_r_ticket import RTicketVerifier


class MsgVerifier:
    def __init__(self, shared_data: SharedData) -> None:
        self.shared_data = shared_data

    ######################################################
    # [STAGE: (V)] Verify Message & Execute
    #   (VR): classify_message_is_defined_type
    #   (VL): has_u_ticket_in_device_table
    #   (VUT): verify_u_ticket_can_execute
    #   (VRT): verify_u_ticket_has_successfully_executed_through_r_ticket
    #   (VTK): verify_token_through_hmac
    #   (VTS): verify_cmd_is_in_task_scope
    ######################################################
    def _classify_message_is_defined_type(
        self, arbitrary_json: str
    ) -> UTicket | RTicket:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is classifying message...",
        )

        # Notice that Pydantic can classify message type by json schema,
        #   while other implementation may need classify message type by message_type field
        try:
            # [STAGE: (VR: UTicket)]
            u_ticket_verifier = UTicketVerifier(this_device=None)

            u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.has_device_id(u_ticket_in)

            return u_ticket_in
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            try:
                # [STAGE: (VR: RTicket)]
                r_ticket_verifier = RTicketVerifier(
                    this_device=None,
                    device_table=None,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                    current_session=None,
                )

                r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
                r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in)
                r_ticket_in = r_ticket_verifier.has_device_id(r_ticket_in)

                return r_ticket_in
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
                # "NOT VALID JSON or VALID UTICKET/RTICKET SCHEMA"
                failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"
                simple_log("error", f"{failure_msg}: {error}")
                raise RuntimeError(error)
            except:  # pragma: no cover -> Unpredicted Error
                failure_msg = f"FAILURE: UNPREDICTED ERROR"
                simple_log("error", failure_msg)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def verify_u_ticket_can_execute(self, u_ticket_in: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is verifying u_ticket...",
        )

        try:
            u_ticket_verifier = UTicketVerifier(
                this_device=self.shared_data.this_device
            )

            # u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            # u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_device_id(u_ticket_in)

            u_ticket_in = u_ticket_verifier.verify_ticket_order(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_holder_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_task_scope(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_ps(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_issuer_signature(u_ticket_in)
        except RuntimeError as error:
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def verify_u_ticket_has_successfully_executed_through_r_ticket(
        self,
        r_ticket_in: RTicket,
        audit_start_ticket: None | UTicket,
        audit_end_ticket: None | UTicket,
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is verifying r_ticket...",
        )

        try:
            r_ticket_verifier = RTicketVerifier(
                this_device=self.shared_data.this_device,
                device_table=self.shared_data.device_table,
                audit_start_ticket=audit_start_ticket,
                audit_end_ticket=audit_end_ticket,
                current_session=self.shared_data.current_session,
            )

            r_ticket_in = r_ticket_verifier.verify_result(r_ticket_in)

            # r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
            # r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_id(r_ticket_in)

            r_ticket_in = r_ticket_verifier.verify_ticket_order(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_start(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_end(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_result(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_cr_ke(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_ps(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_signature(r_ticket_in)
        except RuntimeError as error:
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def verify_cmd_is_in_task_scope(self, cmd: str) -> bool:
        task_scope = jsonstr_to_dict(
            self.shared_data.current_session.current_task_scope
        )
        # simple_log("debug", f"current_task_scope: {task_scope}")

        # If the key is not found, get() returns a None
        if cmd == "TX_END":
            return True
        elif cmd == "HELLO-1" and (
            task_scope.get("SAY-HELLO-1") == "allow" or task_scope.get("ALL") == "allow"
        ):
            return True
        elif cmd == "HELLO-2" and (
            task_scope.get("SAY-HELLO-2") == "allow" or task_scope.get("ALL") == "allow"
        ):
            return True
        elif cmd == "HELLO-3" and (
            task_scope.get("SAY-HELLO-3") == "allow" or task_scope.get("ALL") == "allow"
        ):
            return True
        else:
            simple_log("error", f"Undefined or Forbidden Command: {cmd}")
            return False
