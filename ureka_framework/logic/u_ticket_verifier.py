import copy
from ureka_framework.resource.logger.simple_logger import simple_log
from returns.result import Result, Success, Failure
from ureka_framework.data_model.u_ticket import (
    UTicket,
    jsonstr_to_u_ticket,
    u_ticket_to_jsonstr,
)
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    str_to_byte,
)
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice


class UTicketVerifier:
    def __init__(self, this_device: ThisDevice) -> None:
        self.this_device = this_device

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> Result[UTicket, RuntimeError]:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            u_ticket_in: UTicket = jsonstr_to_u_ticket(arbitrary_json)
            simple_log("info", success_msg)
            return Success(u_ticket_in)
        except RuntimeError as error:
            simple_log("error", f"{failure_msg}: {error}")
            return Failure(RuntimeError(f"{failure_msg}: {error}"))

    def verify_protocol_version(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        success_msg = (
            f"-> SUCCESS: VERIFY_PROTOCOL_VERSION = {u_ticket_in.protocol_verision}"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_PROTOCOL_VERSION = {u_ticket_in.protocol_verision}"
        )

        if u_ticket_in.protocol_verision == u_ticket.PROTOCOL_VERSION:
            simple_log("info", success_msg)
            return Success(u_ticket_in)
        else:
            simple_log("error", failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_u_ticket_type(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"

        if u_ticket_in.u_ticket_type in u_ticket.LEGAL_UTICKET_TYPES:
            simple_log("info", success_msg)
            return Success(u_ticket_in)
        else:
            simple_log("error", failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_device_id(self, u_ticket_in: UTicket) -> Result[UTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            if u_ticket_in.device_id == "no_id":
                simple_log("info", success_msg)
                return Success(u_ticket_in)
            else:
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))
        # TYPE_OWNERSHIP_UTICKET, TYPE_ACCESS_UTICKET
        else:
            if u_ticket_in.device_id == self.this_device.device_pub_key_str:
                simple_log("info", success_msg)
                return Success(u_ticket_in)
            else:
                simple_log("error", failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_issuer_signature(
        self,
        u_ticket_in: UTicket,
    ) -> Result[UTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_ISSUER_SIGNATURE on {u_ticket_in.u_ticket_type} UTICKET"
        failure_msg = f"-> FAILURE: VERIFY_ISSUER_SIGNATURE on {u_ticket_in.u_ticket_type} UTICKET"

        # Verify ISSUER_SIGNATURE
        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # No need to verify ISSUER_SIGNATURE
            simple_log("info", success_msg)
            return Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.owner_pub_key
            ):
                simple_log("info", success_msg)
                return Success(u_ticket_in)
            else:
                simple_log("error", failure_msg)
                simple_log("error", "-> FAILURE: WRONG AUTHORIZATION")
                return Failure(RuntimeError(failure_msg))
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.owner_pub_key
            ):
                simple_log("info", success_msg)
                return Success(u_ticket_in)
            else:
                simple_log("error", failure_msg)
                simple_log("error", "-> FAILURE: WRONG AUTHORIZATION")
                return Failure(RuntimeError(failure_msg))
        else:  # pragma: no cover -> Never reach here: Because of verify_u_ticket_type()
            simple_log("error", failure_msg)
            return Failure(RuntimeError(failure_msg))

    ######################################################
    # Verify ECC Signature on UTicket
    ######################################################
    def _verify_issuer_signature_on_u_ticket(
        self, signed_u_ticket: UTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # Get Signature on UTicket
        signature_byte = base64str_backto_byte(signed_u_ticket.issuer_signature)

        # Verify Signature on Signed UTicket, but Prevent side effect on Signed UTicket
        unsigned_u_ticket = copy.deepcopy(signed_u_ticket)
        unsigned_u_ticket.issuer_signature = None

        unsigned_u_ticket_str = u_ticket_to_jsonstr(unsigned_u_ticket)
        unsigned_u_ticket_byte = str_to_byte(unsigned_u_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_u_ticket_byte, public_key)
