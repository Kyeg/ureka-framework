import copy
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import ecdh
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec


class GenerationFlow:
    # Better not have side effect on device_controller
    def __init__(self, device_controller) -> None:
        self.device_controller = device_controller

    ######################################################
    # Message Generation Flow
    ######################################################
    def generate_arbitrary_ticket(self, arbitrary_dict: dict) -> str:
        ######################################################
        # Unsigned Ticket
        ######################################################
        new_ticket = ticket.Ticket(**arbitrary_dict)

        ######################################################
        # Signed Ticket
        ######################################################
        # Generate Random Salt for Challenge-response or Key-exchange
        if new_ticket.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            random_salt = ecdh.generate_random_byte(32)
            new_ticket.task_scope = serialization_util.byte_to_str(random_salt)
        elif new_ticket.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            random_salt = ecdh.generate_random_byte(32)
            new_ticket.task_scope = serialization_util.byte_to_str(random_salt)

        # Add Signature
        if new_ticket.ticket_type != ticket.TYPE_INITIALIZATION_TICKET:
            new_ticket = self._add_issuer_signature_on_ticket(
                new_ticket, self.device_controller.this_device.device_priv_key
            )

        ######################################################
        # Side Effect
        ######################################################
        # Generate session_key (Side Effect)
        if new_ticket.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            self.device_controller.execute_update_current_session_key_byte(
                server_private_key_obj=self.device_controller.this_device.device_priv_key,
                salt_byte=random_salt,
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    new_ticket.holder_id, key_type="ecc-public-key"
                ),
            )

        return serialization_util.ticket_to_jsonstr(new_ticket)

    ######################################################
    # Add ECC Signature on Ticket
    ######################################################
    def _add_issuer_signature_on_ticket(
        self, unsigned_ticket: Ticket, private_key: ec.EllipticCurvePrivateKey
    ) -> Ticket:
        # Message
        unsigned_ticket_str = serialization_util.ticket_to_jsonstr(unsigned_ticket)
        unsigned_ticket_byte = serialization_util.str_to_byte(unsigned_ticket_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(unsigned_ticket_byte, private_key)

        # Add Signature on New Signed Ticket, but Prevent Side Effect on Unsigned Ticket
        signed_ticket = copy.deepcopy(unsigned_ticket)
        signed_ticket.issuer_signature = serialization_util.byte_to_str(signature_byte)

        return signed_ticket
