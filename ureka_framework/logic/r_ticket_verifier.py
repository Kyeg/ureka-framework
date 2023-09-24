import copy
import logging
from returns.result import Result, Success, Failure
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.data_model.u_ticket import UTicket
import ureka_framework.data_model.r_ticket as r_ticket
from ureka_framework.data_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec


class RTicketVerifier:
    def __init__(
        self,
        audit_start_ticket: UTicket,
        audit_end_ticket: str | UTicket,
    ) -> None:
        self.audit_start_ticket = audit_start_ticket
        self.audit_end_ticket = audit_end_ticket

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
        except RuntimeError as error:  # pragma: no cover -> Weird R-Ticket
            logging.error(f"{failure_msg}: {error}")
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

        # if r_ticket_in.protocol_verision == u_ticket.PROTOCOL_VERSION:
        if r_ticket_in.protocol_verision == self.audit_start_ticket.protocol_verision:
            logging.info(success_msg)
            return Success(r_ticket_in)
        else:  # pragma: no cover -> Weird R-Ticket
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    # Although the U-Ticket Id (in audit_start) will be auditted, we still hope these field won't be maliciously replaced
    def verify_r_ticket_type(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_RTICKET_TYPE = {r_ticket_in.r_ticket_type}"

        if r_ticket_in.r_ticket_type in r_ticket.LEGAL_RTICKET_TYPES:
            logging.info(success_msg)
            return Success(r_ticket_in)
        elif r_ticket_in.r_ticket_type == self.audit_start_ticket.u_ticket_type:
            logging.info(success_msg)
            return Success(r_ticket_in)
        else:  # pragma: no cover -> Weird R-Ticket
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    # Although the U-Ticket Id (in audit_start) will be auditted, we still hope these field won't be maliciously replaced
    def verify_device_id(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {r_ticket_in.device_id}"

        # Note that for TYPE_INITIALIZATION:
        #   u_ticket_device_id = "no_id"
        #   r_ticket_device_id = "newly-created device public key string"
        if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            return Success(r_ticket_in)
        else:
            if r_ticket_in.device_id == self.audit_start_ticket.device_id:
                logging.info(success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_audit_start(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_START"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_START"

        if r_ticket_in.audit_start == self.audit_start_ticket.u_ticket_id:
            logging.info(success_msg)
            return Success(r_ticket_in)
        else:  # pragma: no cover -> Weird R-Ticket
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_audit_end(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_AUDIT_END"
        failure_msg = f"-> FAILURE: VERIFY_AUDIT_END"

        # TODO: Auditted by TXend UToken or Revocation UTicket
        logging.info(success_msg)
        return Success(r_ticket_in)

    def verify_result(self, r_ticket_in: RTicket) -> Result[RTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_RESULT"
        failure_msg = f"-> FAILURE: VERIFY_RESULT"

        logging.info(success_msg)
        return Success(r_ticket_in)

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
                r_ticket_in,
                serialization_util.str_to_key(r_ticket_in.device_id),
            ):
                logging.info(success_msg)
                return Success(r_ticket_in)
            else:  # pragma: no cover -> Weird R-Ticket
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUDIT")
                return Failure(RuntimeError(failure_msg))
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
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
