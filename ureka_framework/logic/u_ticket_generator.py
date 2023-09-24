import copy
import logging
import uuid

from returns.result import Result, Success, Failure
from pydantic import ValidationError
from ureka_framework.data_model.u_ticket import UTicket, u_ticket_to_jsonstr
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.resource.crypto import ecdh
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson


class UTicketGenerator:
    def __init__(self, this_device: ThisDevice, this_person: ThisPerson) -> None:
        self.this_device = this_device
        self.this_person = this_person

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_u_ticket(self, arbitrary_dict: dict) -> UTicket:
        success_msg = "-> SUCCESS: GENERATE_UTICKET"
        failure_msg = "-> FAILURE: GENERATE_UTICKET"

        ######################################################
        # Unsigned UTicket
        ######################################################
        # Generate Task Scope (device_id, holder_id, u_ticket_type, task_scope, etc.)
        try:
            new_u_ticket = UTicket(**arbitrary_dict)
            logging.info(success_msg)
        except ValidationError as error:
            logging.error(f"{failure_msg}: {error}")
            raise RuntimeError(failure_msg)

        # Generate UTicket Id (UUID-4: Random, Unique, and Unpredictable)
        new_u_ticket.u_ticket_id = str(uuid.uuid4())

        ######################################################
        # Signed UTicket
        ######################################################
        # Generate Signature
        if new_u_ticket.u_ticket_type != u_ticket.TYPE_INITIALIZATION_UTICKET:
            new_u_ticket = self._add_issuer_signature_on_u_ticket(
                new_u_ticket, self.this_person.person_priv_key
            )

        return new_u_ticket

    ######################################################
    # Add ECC Signature on UTicket
    ######################################################
    def _add_issuer_signature_on_u_ticket(
        self, unsigned_u_ticket: UTicket, private_key: ec.EllipticCurvePrivateKey
    ) -> UTicket:
        # Message
        unsigned_u_ticket_str = u_ticket_to_jsonstr(unsigned_u_ticket)
        unsigned_u_ticket_byte = serialization_util.str_to_byte(unsigned_u_ticket_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(unsigned_u_ticket_byte, private_key)

        # Add Signature on New Signed UTicket, but Prevent side effect on Unsigned UTicket
        signed_u_ticket = copy.deepcopy(unsigned_u_ticket)
        signed_u_ticket.issuer_signature = serialization_util.byte_to_base64str(
            signature_byte
        )

        return signed_u_ticket
