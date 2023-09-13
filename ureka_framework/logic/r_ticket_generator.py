import copy
import logging
import uuid

from pydantic import ValidationError
from ureka_framework.data_model.r_ticket import RTicket, r_ticket_to_jsonstr
import ureka_framework.data_model.u_ticket as u_ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson


class RTicketGenerator:
    def __init__(self, this_device: ThisDevice, this_person: ThisPerson) -> None:
        self.this_device = this_device
        self.this_person = this_person

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_r_ticket(self, arbitrary_dict: dict) -> RTicket:
        success_msg = "-> SUCCESS: GENERATE_RTICKET"
        failure_msg = "-> FAILURE: GENERATE_RTICKET"

        ######################################################
        # Unsigned RTicket
        ######################################################
        # Generate Audit Info (r_ticket_type, audit_start, audit_end, result, return_value, etc.)
        try:
            new_r_ticket = RTicket(**arbitrary_dict)
            logging.info(success_msg)
        except ValidationError as error:
            logging.error(f"{failure_msg}: {error}")
            raise RuntimeError(failure_msg)

        # Generate RTicket Id (UUID-4: Random, Unique, and Unpredictable)
        new_r_ticket.r_ticket_id = str(uuid.uuid4())

        ######################################################
        # Signed RTicket
        ######################################################
        # Generate Return Value
        # # No use for TYPE_INITIALIZATION_UTICKET:
        # #   because r_ticket_device_id also = "newly-created device public key string"
        # if new_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
        #     new_r_ticket.return_value = self.this_device.device_pub_key_str

        # Generate Signature
        if new_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            new_r_ticket = self._add_device_signature_on_r_ticket(
                new_r_ticket, self.this_device.device_priv_key
            )
        elif new_r_ticket.r_ticket_type == u_ticket.TYPE_MANAGEMENT_UTICKET:
            new_r_ticket = self._add_device_signature_on_r_ticket(
                new_r_ticket, self.this_device.device_priv_key
            )
        elif new_r_ticket.r_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET:
            new_r_ticket = self._add_device_signature_on_r_ticket(
                new_r_ticket, self.this_device.device_priv_key
            )

        return new_r_ticket

    ######################################################
    # Add ECC Signature on RTicket
    ######################################################
    def _add_device_signature_on_r_ticket(
        self, unsigned_r_ticket: RTicket, private_key: ec.EllipticCurvePrivateKey
    ) -> RTicket:
        # Message
        unsigned_r_ticket_str = r_ticket_to_jsonstr(unsigned_r_ticket)
        unsigned_r_ticket_byte = serialization_util.str_to_byte(unsigned_r_ticket_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(unsigned_r_ticket_byte, private_key)

        # Add Signature on New Signed RTicket, but Prevent side effect on Unsigned RTicket
        signed_r_ticket = copy.deepcopy(unsigned_r_ticket)
        signed_r_ticket.device_signature = serialization_util.byte_to_base64str(
            signature_byte
        )

        return signed_r_ticket
