import copy
import logging
from returns.result import Result, Success, Failure
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.data_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec


class RTicketVerifier:
    def __init__(self, device_public_key_str: str) -> None:
        self.device_public_key_str = device_public_key_str

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_json_schema(self, arbitrary_json: str) -> Result[RTicket, RuntimeError]:
        success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"

        try:
            r_ticket_in: RTicket = jsonstr_to_r_ticket(arbitrary_json)
            logging.info(success_msg)
            return Success(r_ticket_in)
        except RuntimeError as error:
            logging.error(f"{failure_msg}: {error}")
            return Failure(RuntimeError(f"{failure_msg}: {error}"))

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
            logging.info(success_msg)
            return Success(r_ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_r_ticket_type(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"

        if r_ticket_in.r_ticket_type in u_ticket.LEGAL_UTICKET_TYPES:
            logging.info(success_msg)
            return Success(r_ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    # ToDo: Completely verify R-Ticket

    # def verify_audit_start(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
    #     pass

    # def verify_audit_end(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
    #     pass

    # def verify_result(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
    #     pass

    def verify_device_signature(
        self,
        r_ticket_in: RTicket,
    ) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_SIGNATURE on {r_ticket_in.r_ticket_type} RTICKET"

        # Verify DEVICE_SIGNATURE
        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_MANAGEMENT_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET
        ):
            if self._verify_device_signature_on_r_ticket(
                r_ticket_in, serialization_util.str_to_key(self.device_public_key_str)
            ):
                logging.info(success_msg)
                return Success(r_ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUDIT")
                return Failure(RuntimeError(failure_msg))
        else:  # pragma: no cover
            # Never reach here: Because of verify_r_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    ######################################################
    # Verify ECC Signature on RTicket
    ######################################################
    def _verify_device_signature_on_r_ticket(
        self, signed_r_ticket: RTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # Get Signature on RTicket
        signature_byte = serialization_util.base64str_backto_byte(
            signed_r_ticket.device_signature
        )

        # Verify Signature on Signed RTicket, but Prevent side effect on Signed RTicket
        unsigned_r_ticket = copy.deepcopy(signed_r_ticket)
        unsigned_r_ticket.device_signature = ""

        unsigned_r_ticket_str = r_ticket_to_jsonstr(unsigned_r_ticket)
        unsigned_r_ticket_byte = serialization_util.str_to_byte(unsigned_r_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_r_ticket_byte, public_key)
