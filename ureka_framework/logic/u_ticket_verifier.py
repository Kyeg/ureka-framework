import copy
import logging
from returns.result import Result, Success, Failure
from ureka_framework.data_model.u_ticket import (
    UTicket,
    jsonstr_to_u_ticket,
    u_ticket_to_jsonstr,
)
import ureka_framework.data_model.u_ticket as u_ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson


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
            logging.info(success_msg)
            return Success(u_ticket_in)
        except RuntimeError as error:
            logging.error(f"{failure_msg}: {error}")
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
            logging.info(success_msg)
            return Success(u_ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_u_ticket_type(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_UTICKET_TYPE = {u_ticket_in.u_ticket_type}"

        if u_ticket_in.u_ticket_type in u_ticket.LEGAL_UTICKET_TYPES:
            logging.info(success_msg)
            return Success(u_ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_device_id(self, u_ticket_in: UTicket) -> Result[UTicket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {u_ticket_in.device_id}"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # To-Do: Return UTicket - to get DEVICE_ID after initialization
            if u_ticket_in.device_id == "no_id":
                logging.info(success_msg)
                return Success(u_ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CHALLENGE_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_KEY_EXCHANGE_UTICKET
        ):
            # No need to verify DEVICE_ID
            logging.info(success_msg)
            return Success(u_ticket_in)
        # TYPE_MANAGEMENT_UTICKET, TYPE_ACCESS_PERMISSION_UTICKET, TYPE_RESPONSE_UTICKET
        else:
            if u_ticket_in.device_id == self.this_device.device_pub_key_str:
                logging.info(success_msg)
                return Success(u_ticket_in)
            else:
                logging.error(failure_msg)
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
            logging.info(success_msg)
            return Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_MANAGEMENT_UTICKET:
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.owner_pub_key
            ):
                logging.info(success_msg)
                return Success(u_ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUTHORIZATION")
                return Failure(RuntimeError(failure_msg))
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET:
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.owner_pub_key
            ):
                logging.info(success_msg)
                return Success(u_ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUTHORIZATION")
                return Failure(RuntimeError(failure_msg))
        # Verify HOLDER_SIGNATURE
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_CHALLENGE_UTICKET:
            # To-Do: Return UTicket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_RESPONSE_UTICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESPONSE_UTICKET is correct

            # Check the u_ticket holder is allowed by owner (in access permission u_ticket)
            if self.this_device.current_holder_pub_key_str != u_ticket_in.holder_id:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG HOLDER_ID")
                return Failure(RuntimeError(failure_msg))

            # To-Do: Authenticate the u_ticket holder
            if self._verify_issuer_signature_on_u_ticket(
                u_ticket_in, self.this_device.current_holder_pub_key
            ):
                logging.info(success_msg)
                return Success(u_ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUTHENTICATION")
                return Failure(RuntimeError(failure_msg))

        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_KEY_EXCHANGE_UTICKET:
            # To-Do: Return UTicket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(u_ticket_in)
        else:  # pragma: no cover
            # Never reach here: Because of verify_u_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    ######################################################
    # Verify ECC Signature on UTicket
    ######################################################
    def _verify_issuer_signature_on_u_ticket(
        self, signed_u_ticket: UTicket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        # Get Signature on UTicket
        signature_byte = serialization_util.base64str_backto_byte(
            signed_u_ticket.issuer_signature
        )

        # Verify Signature on Signed UTicket, but Prevent side effect on Signed UTicket
        unsigned_u_ticket = copy.deepcopy(signed_u_ticket)
        unsigned_u_ticket.issuer_signature = ""

        unsigned_u_ticket_str = u_ticket_to_jsonstr(unsigned_u_ticket)
        unsigned_u_ticket_byte = serialization_util.str_to_byte(unsigned_u_ticket_str)

        # Verify Signature
        return ecc.verify_signature(signature_byte, unsigned_u_ticket_byte, public_key)
