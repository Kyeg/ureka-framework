import copy
import logging
import uuid

from returns.result import Result, Success, Failure
from pydantic import ValidationError
from ureka_framework.data_model.ticket import Ticket, ticket_to_jsonstr
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import ecdh
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson


class TicketGenerator:
    def __init__(self, this_device: ThisDevice, this_person: ThisPerson) -> None:
        self.this_device = this_device
        self.this_person = this_person

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_ticket(
        self, arbitrary_dict: dict
    ) -> Result[str, RuntimeError]:
        success_msg = "-> SUCCESS: GENERATE_TICKET"
        failure_msg = "-> FAILURE: GENERATE_TICKET"

        ######################################################
        # Unsigned Ticket
        ######################################################
        # Generate Task Scope (device_id, holder_id, ticket_type, task_scope, etc.)
        try:
            new_ticket = Ticket(**arbitrary_dict)
            logging.info(success_msg)
        except ValidationError as error:
            logging.error(f"{failure_msg}: {error}")
            raise RuntimeError(failure_msg)

        # Generate Ticket Id (UUID-4: Random, Unique, and Unpredictable)
        new_ticket.ticket_id = str(uuid.uuid4())

        ######################################################
        # Signed Ticket
        ######################################################
        # Generate Random Salt for Challenge-response or Key-exchange
        if new_ticket.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            random_salt_byte = ecdh.generate_random_byte(32)
            new_ticket.task_scope = serialization_util.byte_to_base64str(
                random_salt_byte
            )
        elif new_ticket.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            random_salt_byte = ecdh.generate_random_byte(32)
            new_ticket.task_scope = serialization_util.byte_to_base64str(
                random_salt_byte
            )

        # Generate Signature
        if new_ticket.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            new_ticket = self._add_issuer_signature_on_ticket(
                new_ticket, self.this_device.device_priv_key
            )
        elif new_ticket.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            new_ticket = self._add_issuer_signature_on_ticket(
                new_ticket, self.this_person.person_priv_key
            )
        elif new_ticket.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            new_ticket = self._add_issuer_signature_on_ticket(
                new_ticket, self.this_device.device_priv_key
            )
        elif new_ticket.ticket_type != ticket.TYPE_INITIALIZATION_TICKET:
            new_ticket = self._add_issuer_signature_on_ticket(
                new_ticket, self.this_person.person_priv_key
            )

        new_ticket_json = ticket_to_jsonstr(new_ticket)

        return new_ticket_json

    ######################################################
    # Add ECC Signature on Ticket
    ######################################################
    def _add_issuer_signature_on_ticket(
        self, unsigned_ticket: Ticket, private_key: ec.EllipticCurvePrivateKey
    ) -> Ticket:
        # Message
        unsigned_ticket_str = ticket_to_jsonstr(unsigned_ticket)
        unsigned_ticket_byte = serialization_util.str_to_byte(unsigned_ticket_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(unsigned_ticket_byte, private_key)

        # Add Signature on New Signed Ticket, but Prevent side effect on Unsigned Ticket
        signed_ticket = copy.deepcopy(unsigned_ticket)
        signed_ticket.issuer_signature = serialization_util.byte_to_base64str(
            signature_byte
        )

        return signed_ticket
