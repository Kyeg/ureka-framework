import copy
from ureka_framework.resource.logger.simple_logger import simple_log
from returns.result import Result, Success, Failure
from ureka_framework.data_model.current_session import CurrentSession
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.data_model.u_ticket import UTicket
import ureka_framework.data_model.r_ticket as r_ticket
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_base64str,
    str_to_key,
    base64str_backto_byte,
    str_to_byte,
    byte_backto_str,
)
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.exceptions import InvalidTag


class RTicketVerifier:
    def __init__(
        self,
        this_device: ThisDevice,
        audit_start_ticket: UTicket,
        audit_end_ticket: str | UTicket,
        current_session: CurrentSession,
    ) -> None:
        self.this_device = this_device
        self.audit_start_ticket = audit_start_ticket
        self.audit_end_ticket = audit_end_ticket
        self.current_session = current_session

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> Result[RTicket, RuntimeError]:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            r_ticket_in: RTicket = jsonstr_to_r_ticket(arbitrary_json)
            simple_log("info", success_msg)
            return Success(r_ticket_in)
        except RuntimeError as error:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", f"{failure_msg}: {error}")
            return Failure(RuntimeError(f"{failure_msg}: {error}"))

    # Although the U-Ticket Id (in audit_start) will be auditted, we still hope these field won't be maliciously replaced
    def verify_protocol_version(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        success_msg = (
            f"-> SUCCESS: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_verision}"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_verision}"
        )

        if r_ticket_in.protocol_verision == u_ticket.PROTOCOL_VERSION:
            simple_log("info", success_msg)
            return Success(r_ticket_in)
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            return Failure(RuntimeError(failure_msg))

    # Although the U-Ticket Id (in audit_start) will be auditted, we still hope these field won't be maliciously replaced
    def verify_r_ticket_type(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"

        if r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            simple_log("info", success_msg)
            return Success(r_ticket_in)
        else:
            if r_ticket_in.r_ticket_type == self.audit_start_ticket.u_ticket_type:
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))

    # Although the U-Ticket Id (in audit_start) will be auditted, we still hope these field won't be maliciously replaced
    def verify_device_id(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"

        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # # Note that for TYPE_INITIALIZATION:
            # u_ticket_device_id = "no_id"
            # r_ticket_device_id = "newly-created device public key string"
            return Success(r_ticket_in)
        elif r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            if r_ticket_in.device_id == self.audit_start_ticket.device_id:
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.device_id == self.current_session.current_device_id:
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_audit_start(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_START"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_START"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
        ):
            if r_ticket_in.audit_start == self.audit_start_ticket.u_ticket_id:
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.audit_start == self.current_session.current_u_ticket_id:
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_audit_end(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_END"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_END"

        # TODO: Auditted by TXend UToken or Revocation UTicket
        simple_log("info", success_msg)
        return Success(r_ticket_in)

    def verify_result(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_RESULT"
        failure_msg = f"-> FAILURE: VERIFY_RESULT"

        simple_log("info", success_msg)
        return Success(r_ticket_in)

    def verify_cr_ke(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_CR_KE"
        failure_msg = f"-> FAILURE: VERIFY_CR_KE"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
        ):
            return Success(r_ticket_in)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.key_exchange_salt_1 != None
            ):
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.challenge_2 != None
                and r_ticket_in.key_exchange_salt_2 != None
                and r_ticket_in.iv_1 != None
                and r_ticket_in.associated_plaintext_1 != None
                and r_ticket_in.ciphertext_1 != None
                and r_ticket_in.gcm_authentication_tag_1 != None
            ):
                ######################################################
                # Update Session
                ######################################################
                # # Session Key Gereration ("device")
                # salt_1 = base64str_backto_byte(self.current_session.key_exchange_salt_1)
                # salt_2 = base64str_backto_byte(r_ticket_in.key_exchange_salt_2)
                # shared_salt = bytes([salt_1[i] & salt_2[i] for i in range(len(salt_1))])
                # current_session_key: bytes = ecdh.generate_ecdh_key(
                #     server_private_key=self.this_device.device_priv_key,
                #     salt=shared_salt,
                #     info=None,
                #     peer_public_key=str_to_key(self.current_session.current_holder_id),
                # )

                # # Message Decryption (bytes)
                # try:
                #     ciphertext: bytes = base64str_backto_byte(r_ticket_in.ciphertext_1)
                #     associated_plaintext: bytes = str_to_byte(
                #         r_ticket_in.associated_plaintext_1
                #     )
                #     gcm_authentication_tag: bytes = base64str_backto_byte(
                #         r_ticket_in.gcm_authentication_tag_1
                #     )
                #     iv_1: bytes = base64str_backto_byte(r_ticket_in.iv_1)

                #     plaintext = ecdh.gcm_decrypt(
                #         ciphertext,
                #         associated_plaintext,
                #         gcm_authentication_tag,
                #         current_session_key,
                #         iv_1,
                #     )

                #     self.current_session.challenge_2 = r_ticket_in.challenge_2
                #     self.current_session.key_exchange_salt_2 = (
                #         r_ticket_in.key_exchange_salt_2
                #     )
                #     self.current_session.current_session_key_str = byte_to_base64str(
                #         current_session_key
                #     )
                #     self.current_session.plaintext_1 = byte_backto_str(plaintext)
                #     simple_log(
                #         "debug",
                #         "plaintext: " + self.current_session.plaintext_1,
                #     )
                #     self.current_session.associated_plaintext_1 = (
                #         r_ticket_in.associated_plaintext_1
                #     )
                #     self.current_session.iv_1 = r_ticket_in.iv_1
                #     self.current_session.ciphertext_1 = r_ticket_in.ciphertext_1
                #     self.current_session.gcm_authentication_tag_1 = (
                #         r_ticket_in.gcm_authentication_tag_1
                #     )

                #     simple_log("info", f"{success_msg}: {gcm_tag_result}")
                #     return Success(r_ticket_in)
                # except InvalidTag:
                #     gcm_tag_result = "Message does not pass GCM Authentication."
                #     return Failure(RuntimeError(f"{failure_msg}: {gcm_tag_result}"))

                simple_log("info", success_msg)
                return Success(r_ticket_in)

            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_ps(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_PS"
        failure_msg = f"-> FAILURE: VERIFY_PS"

        simple_log("info", success_msg)
        return Success(r_ticket_in)

    def verify_device_signature(
        self,
        r_ticket_in: RTicket,
    ) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"

        # Verify DEVICE_SIGNATURE through device_id
        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
        ):
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(r_ticket_in.device_id),
            ):
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                simple_log("error", "-> FAILURE: WRONG AUDIT")
                return Failure(RuntimeError(failure_msg))
        if r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(self.current_session.current_holder_id),
            ):
                simple_log("info", success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                simple_log("error", "-> FAILURE: WRONG AUDIT")
                return Failure(RuntimeError(failure_msg))
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            return Failure(RuntimeError(failure_msg))

    ######################################################
    # Verify ECC Signature on RTicket
    ######################################################
    def _verify_device_signature_on_r_ticket(
        self, signed_r_ticket: RTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # Get Signature on RTicket
        signature_byte = base64str_backto_byte(signed_r_ticket.device_signature)

        # Verify Signature on Signed RTicket, but Prevent side effect on Signed RTicket
        unsigned_r_ticket = copy.deepcopy(signed_r_ticket)
        unsigned_r_ticket.device_signature = None

        unsigned_r_ticket_str = r_ticket_to_jsonstr(unsigned_r_ticket)
        unsigned_r_ticket_byte = str_to_byte(unsigned_r_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_r_ticket_byte, public_key)
