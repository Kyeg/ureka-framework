# Data Model (RAM)
import copy
from pydantic import ValidationError
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.this_person import ThisPerson
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.message_model.u_ticket import UTicket, u_ticket_to_jsonstr
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_base64str,
    str_to_byte,
)

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Resource (Measurer)
from ureka_framework.resource.logger.simple_measurer import measure_worker_func

# Resource (Crypto)
from cryptography.hazmat.primitives.asymmetric import ec
import ureka_framework.resource.crypto.ecc as ecc
from ureka_framework.resource.crypto import ecdh


class UTicketGenerator:
    def __init__(
        self,
        this_device: ThisDevice,
        this_person: ThisPerson,
        device_table: dict[str, OtherDevice],
    ) -> None:
        self.this_device = this_device
        self.this_person = this_person
        self.device_table = device_table

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_u_ticket(self, arbitrary_dict: dict) -> UTicket:
        success_msg = "-> SUCCESS: GENERATE_UTICKET"
        failure_msg = "-> FAILURE: GENERATE_UTICKET"

        ######################################################
        # Unsigned UTicket
        ######################################################
        try:
            new_u_ticket = UTicket(**arbitrary_dict)
        except ValidationError as error:  # pragma: no cover -> Weird Ticket-Request
            simple_log("error", f"{failure_msg}: {error}")
            raise RuntimeError(failure_msg)

        # Generate Ticket Order
        if new_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            new_u_ticket.ticket_order = 0
        else:
            new_u_ticket.ticket_order = self.device_table[
                new_u_ticket.device_id
            ].ticket_order

        # Generate UTicket Id (Hash-based)
        new_u_ticket.u_ticket_id = ecdh.generate_sha256_hash_str(
            u_ticket_to_jsonstr(new_u_ticket)
        )

        ######################################################
        # Signed UTicket
        ######################################################
        # Generate ISSUER_SIGNATURE
        if (
            new_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or new_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            or new_u_ticket.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or new_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_END_UTOKEN
        ):
            # No ISSUER_SIGNATURE
            simple_log("info", success_msg)
        elif (
            new_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or new_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ):
            new_u_ticket = self._add_issuer_signature_on_u_ticket(
                new_u_ticket, self.this_person.person_priv_key
            )
            simple_log("info", success_msg)
        else:  # pragma: no cover -> Shouldn't Reach Here
            raise RuntimeError(f"Shouldn't Reach Here")

        return new_u_ticket

    ######################################################
    # Add ECC Signature on UTicket
    ######################################################
    def _add_issuer_signature_on_u_ticket(
        self, unsigned_u_ticket: UTicket, private_key: ec.EllipticCurvePrivateKey
    ) -> UTicket:
        # Message
        unsigned_u_ticket_str = u_ticket_to_jsonstr(unsigned_u_ticket)
        unsigned_u_ticket_byte = str_to_byte(unsigned_u_ticket_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(unsigned_u_ticket_byte, private_key)

        # Add Signature on New Signed UTicket, but Prevent side effect on Unsigned UTicket
        signed_u_ticket = copy.deepcopy(unsigned_u_ticket)
        signed_u_ticket.issuer_signature = byte_to_base64str(signature_byte)

        return signed_u_ticket
