import copy
import logging
from returns.result import Result, Success, Failure
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson


class TicketVerifier:
    def __init__(self, this_device: ThisDevice, this_person: ThisPerson) -> None:
        self.this_device = this_device
        self.this_person = this_person

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_ticket_schema(self, arbitrary_json: str) -> Result[Ticket, RuntimeError]:
        success_msg = "-> SUCCESS: VERIFY_TICKET_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_TICKET_SCHEMA"

        try:
            ticket_in: Ticket = ticket.jsonstr_to_ticket(arbitrary_json)

            logging.info(success_msg)
            return Success(ticket_in)
        except RuntimeError as error:
            logging.error(f"{failure_msg}: {error}")
            return Failure(RuntimeError(f"{failure_msg}: {error}"))

    def verify_ticket_protocol_version(
        self, ticket_in: Ticket
    ) -> Result[Ticket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_PROTOCOL_VERSION = {ticket_in.ticket_protocol_verision}"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_PROTOCOL_VERSION = {ticket_in.ticket_protocol_verision}"

        if ticket_in.ticket_protocol_verision == ticket.TICKET_PROTOCOL_VERSION:
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_ticket_type(self, ticket_in: Ticket) -> Result[Ticket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_TYPE = {ticket_in.ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_TYPE = {ticket_in.ticket_type}"

        if ticket_in.ticket_type in ticket.LEGAL_TICKET_TYPES:
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_device_id(self, ticket_in: Ticket) -> Result[Ticket, RuntimeError]:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {ticket_in.device_id}"

        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # No need to verify DEVICE_ID
            logging.info(success_msg)
            return Success(ticket_in)
        elif (
            ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET
            or ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET
        ):
            # No need to verify DEVICE_ID
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            if ticket_in.device_id == self.this_device.device_pub_key_str:
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_issuer_signature(
        self,
        ticket_in: Ticket,
    ) -> Result[Ticket, RuntimeError]:
        success_msg = (
            f"-> SUCCESS: VERIFY_ISSUER_SIGNATURE on {ticket_in.ticket_type} TICKET"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_ISSUER_SIGNATURE on {ticket_in.ticket_type} TICKET"
        )

        # (Z) Verify ISSUER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # No need to verify ISSUER_SIGNATURE
            logging.info(success_msg)
            return Success(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            if self._verify_issuer_signature_on_ticket(
                ticket_in, self.this_device.owner_pub_key
            ):
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            if self._verify_issuer_signature_on_ticket(
                ticket_in, self.this_device.owner_pub_key
            ):
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))
        # (N) Verify HOLDER_SIGNATURE
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESPONSE_TICKET is correct

            # Check the ticket holder is allowed by owner (in access permission ticket)
            if self.this_device.current_holder_pub_key_str != ticket_in.holder_id:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG HOLDER_ID")
                return Failure(RuntimeError(failure_msg))

            # To-Do: Authenticate the ticket holder
            if self._verify_issuer_signature_on_ticket(
                ticket_in, self.this_device.current_holder_pub_key
            ):
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: WRONG AUTHENTICATION")
                return Failure(RuntimeError(failure_msg))

        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            # Never reach here: Because of verify_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    ######################################################
    # Verify ECC Signature on Ticket
    ######################################################
    def _verify_issuer_signature_on_ticket(
        self, signed_ticket: Ticket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        try:
            # Get Signature on Ticket
            signature_byte = serialization_util.str_to_byte(
                signed_ticket.issuer_signature
            )

            # Verify Signature on Signed Ticket, but Prevent side effect on Signed Ticket
            unsigned_ticket = copy.deepcopy(signed_ticket)
            unsigned_ticket.issuer_signature = ""

            unsigned_ticket_str = ticket.ticket_to_jsonstr(unsigned_ticket)
            unsigned_ticket_byte = serialization_util.str_to_byte(unsigned_ticket_str)

            # Verify Signature
            return ecc.verify_signature(
                signature_byte, unsigned_ticket_byte, public_key
            )

        # Reach here if the public key is wrong
        except AttributeError:
            logging.error("FAILURE: WRONG PUBLIC KEY")
            return False
