import copy
from ureka_framework.resource.logger.simple_logger import simple_log

from ureka_framework.model.data_model.current_session import CurrentSession
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.message_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
from ureka_framework.resource.crypto.serialization_util import (
    str_to_key,
    base64str_backto_byte,
    str_to_byte,
)
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec


class RTicketVerifier:
    def __init__(
        self,
        this_device: None | ThisDevice,
        device_table: None | dict[str, OtherDevice],
        audit_start_ticket: None | UTicket,
        audit_end_ticket: None | UTicket,
        current_session: None | CurrentSession,
    ) -> None:
        self.this_device = this_device
        self.device_table = device_table
        self.audit_start_ticket = audit_start_ticket
        self.audit_end_ticket = audit_end_ticket
        self.current_session = current_session

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> RTicket:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            r_ticket_in: RTicket = jsonstr_to_r_ticket(arbitrary_json)
            simple_log("info", success_msg)
            return r_ticket_in
        except RuntimeError as error:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(f"{failure_msg}: {error}")

    def verify_protocol_version(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = (
            f"-> SUCCESS: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_verision}"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_PROTOCOL_VERSION = {r_ticket_in.protocol_verision}"
        )

        if r_ticket_in.protocol_verision == u_ticket.PROTOCOL_VERSION:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_message_type(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_MESSAGE_TYPE"
        failure_msg = f"-> FAILURE: VERIFY_MESSAGE_TYPE"

        if r_ticket_in.message_type != None:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_r_ticket_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_ID"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_ID"

        if r_ticket_in.r_ticket_id != None:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_r_ticket_type(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"

        if r_ticket_in.r_ticket_type in r_ticket.LEGAL_RTICKET_TYPES:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # Because holder do not really know whether this device_id is correct before get RT
    def has_device_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: HAS_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: HAS_DEVICE_ID = {r_ticket_in.device_id}"

        if r_ticket_in.device_id != None:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird U-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    # However, device can verify whether this device_id is correct
    def verify_device_id(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"

        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # # Note that for TYPE_INITIALIZATION:
            # u_ticket_device_id = "no_id"
            # r_ticket_device_id = "newly-created device public key string"

            # NO Device ID
            simple_log("info", success_msg)
            return r_ticket_in
        elif (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            if r_ticket_in.device_id == self.audit_start_ticket.device_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.device_id == self.current_session.current_device_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ticket_order(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_ORDER"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_ORDER"

        # If TX is finished, the ticket_order++
        # "holder"
        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            if r_ticket_in.ticket_order == 1:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            if (
                r_ticket_in.ticket_order
                == self.device_table[r_ticket_in.device_id].ticket_order + 1
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        # If TX is not finished, the ticket_order should be the same
        # "holder"
        elif (
            r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
        ):
            if (
                r_ticket_in.ticket_order
                == self.device_table[r_ticket_in.device_id].ticket_order
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        # "device"
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if r_ticket_in.ticket_order == self.this_device.ticket_order:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_audit_start(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_START"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_START"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            if r_ticket_in.audit_start == self.audit_start_ticket.u_ticket_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type in r_ticket.LEGAL_CRKE_TYPES:
            if r_ticket_in.audit_start == self.current_session.current_u_ticket_id:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_audit_end(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_END"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_END"

        # Auditted by:
        #   Per-Use
        #   TXend UToken
        #   TODO: Revocation UTicket
        if r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
            if r_ticket_in.audit_end == "TX_END":
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("info", success_msg)
            return r_ticket_in

    def verify_result(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_RESULT"
        failure_msg = f"-> FAILURE: VERIFY_RESULT"

        if "SUCCESS" in r_ticket_in.result:
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Weird R-Ticket
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_cr_ke(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_CR_KE"
        failure_msg = f"-> FAILURE: VERIFY_CR_KE"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            # NO CR-KE
            simple_log("info", success_msg)
            return r_ticket_in
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.key_exchange_salt_1 != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if (
                r_ticket_in.challenge_1 != None
                and r_ticket_in.challenge_2 != None
                and r_ticket_in.key_exchange_salt_2 != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            if r_ticket_in.challenge_2 != None:
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_ps(self, r_ticket_in: RTicket) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_PS"
        failure_msg = f"-> FAILURE: VERIFY_PS"

        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            # NO PS
            simple_log("info", success_msg)
            return r_ticket_in
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if (
                r_ticket_in.iv_cmd != None
                and r_ticket_in.associated_plaintext_cmd != None
                and r_ticket_in.ciphertext_cmd != None
                and r_ticket_in.gcm_authentication_tag_cmd != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            if (
                r_ticket_in.iv_data != None
                and r_ticket_in.associated_plaintext_data != None
                and r_ticket_in.ciphertext_data != None
                and r_ticket_in.gcm_authentication_tag_data != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            if (
                r_ticket_in.iv_data != None
                and r_ticket_in.associated_plaintext_data != None
                and r_ticket_in.ciphertext_data != None
                and r_ticket_in.gcm_authentication_tag_data != None
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", failure_msg)
                raise RuntimeError(f"{failure_msg}")
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

    def verify_device_signature(
        self,
        r_ticket_in: RTicket,
    ) -> RTicket:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"

        # Verify DEVICE_SIGNATURE through device_id
        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
            or r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(r_ticket_in.device_id, "ecc-public-key"),
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:  # pragma: no cover -> Weird R-Ticket
                simple_log("error", f"{failure_msg}")
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in,
                str_to_key(self.current_session.current_holder_id, "ecc-public-key"),
            ):
                simple_log("info", success_msg)
                return r_ticket_in
            else:
                simple_log("error", f"{failure_msg}")
                raise RuntimeError(f"{failure_msg}")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            # No ISSUER_SIGNATURE
            simple_log("info", success_msg)
            return r_ticket_in
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", failure_msg)
            raise RuntimeError(f"{failure_msg}")

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
