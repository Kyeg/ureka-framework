import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
import ureka_framework.resource.crypto.key_serialization as key_serialization
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class TicketGenerator:
    @classmethod
    def generate_ticket(cls, ticket_type: str):
        return getattr(
            cls, f"_generate_{ticket_type}_ticket", "_generate_default_ticket"
        )

    ######################################################
    # Add ECC Signature on Ticket
    #   ticket_in: Ticket
    #
    #   return: Ticket
    ######################################################
    def add_issuer_signature_on_ticket(
        ticket_in: Ticket, private_key: ec.EllipticCurvePrivateKey
    ) -> Ticket:
        # Message
        message_str = key_serialization.ticket_to_jsonstr(ticket_in)
        message_byte = key_serialization.str_to_byte(message_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(message_byte, private_key)

        # Add Signature on Ticket
        ticket_with_signature = ticket_in
        ticket_with_signature.issuer_signature = key_serialization.byte_to_str(
            signature_byte
        )

        return ticket_with_signature

    ######################################################
    # Ticket Handshake
    #   +++ Execute Command Ticket (E-N) +++
    ######################################################
    def generate_session_key(
        server_private_key_obj: ec.EllipticCurvePrivateKey,
        salt_byte: bytes,
        info_byte: bytes,
        peer_public_key_obj: ec.EllipticCurvePublicKey,
    ) -> bytes:
        return ecdh.generate_ecdh_key(
            server_private_key=server_private_key_obj,
            salt=salt_byte,
            info=info_byte,
            peer_public_key=peer_public_key_obj,
        )

    ######################################################
    # Generate Different Ticket Types (pure functions)
    ######################################################
    @classmethod
    def _generate_initialization_ticket(cls, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_INITIALIZATION_TICKET
        # no device_id
        new_ticket.holder_id = holder_id

        return new_ticket

    @classmethod
    def _generate_query_ticket(cls):
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_QUERY_TICKET

        return new_ticket

    @classmethod
    def _generate_management_ticket(
        cls,
        device_id: str,
        holder_id: str,
        task_scope: str,
        device_priv_key: ec.EllipticCurvePrivateKey,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_MANAGEMENT_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = getattr(cls, f"add_issuer_signature_on_ticket")(
            new_ticket, device_priv_key
        )

        return new_ticket

    @classmethod
    def _generate_access_permission_ticket(
        cls,
        device_id: str,
        holder_id: str,
        task_scope: str,
        device_priv_key: ec.EllipticCurvePrivateKey,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_ACCESS_PERMISSION_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = getattr(cls, f"add_issuer_signature_on_ticket")(
            new_ticket, device_priv_key
        )

        return new_ticket

    @classmethod
    def _generate_challenge_ticket(
        cls,
        device_id: str,
        holder_id: str,
        device_priv_key: ec.EllipticCurvePrivateKey,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_CHALLENGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Challenge
        random_challenge = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_challenge)

        new_ticket = getattr(cls, f"add_issuer_signature_on_ticket")(
            new_ticket, device_priv_key
        )

        return new_ticket

    @classmethod
    def _generate_response_ticket(
        cls,
        device_id: str,
        holder_id: str,
        device_priv_key: ec.EllipticCurvePrivateKey,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_RESPONSE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        new_ticket = getattr(cls, f"add_issuer_signature_on_ticket")(
            new_ticket, device_priv_key
        )

        return new_ticket

    @classmethod
    def _generate_key_exchange_ticket(
        cls,
        device_id: str,
        holder_id: str,
        device_priv_key: ec.EllipticCurvePrivateKey,
    ) -> (Ticket, bytes):
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_KEY_EXCHANGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Salt
        random_salt = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_salt)

        new_ticket = getattr(cls, f"add_issuer_signature_on_ticket")(
            new_ticket, device_priv_key
        )

        # Generate (temp) session_key (Side Effect)
        current_session_key_byte = getattr(cls, f"generate_session_key")(
            server_private_key_obj=device_priv_key,
            salt_byte=random_salt,
            info_byte=b"",
            peer_public_key_obj=key_serialization.str_backto_key(
                holder_id, key_type="ecc-public-key"
            ),
        )
        logging.debug("current_session_key_byte: " + str(current_session_key_byte))

        return (new_ticket, current_session_key_byte)

    @classmethod
    def _generate_command_ticket(cls, device_id, holder_id, task_scope):
        pass

    @classmethod
    def _generate_return_ticket(cls):
        # Query Ticket: Return Device_ID
        # Initialization Ticket: Return Device_ID

        # Command Ticket: Return Data

        pass

    @classmethod
    def _generate_default_ticket(cls) -> str:
        return "default_ticket"
