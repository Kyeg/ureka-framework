from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import ec


# Interface for the Command Object
class GenerateXXXTicket(ABC):
    # Better not have side effect on device_controller
    def __init__(self, device_controller) -> None:
        self.device_controller = device_controller

    @abstractmethod
    def execute(self, *args, **kwargs):
        pass

    ######################################################
    # Add ECC Signature on Ticket
    ######################################################
    def _add_issuer_signature_on_ticket(
        self, ticket_in: Ticket, private_key: ec.EllipticCurvePrivateKey
    ) -> Ticket:
        # Message
        message_str = serialization_util.ticket_to_jsonstr(ticket_in)
        message_byte = serialization_util.str_to_byte(message_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(message_byte, private_key)

        # Add Signature on Ticket
        ticket_with_signature = ticket_in
        ticket_with_signature.issuer_signature = serialization_util.byte_to_str(
            signature_byte
        )

        return ticket_with_signature


# Interface for the Invoker/Router
class TicketGenerationRouter:
    def __init__(self) -> None:
        self.ticket_types: dict = {}

    # Set Route-Command
    def add_ticket_type(self, ticket_type: str, command: GenerateXXXTicket) -> None:
        self.ticket_types[ticket_type] = command

    # Execute Command
    def generate_xxx_ticket(self, ticket_type: str, *args, **kwargs) -> Ticket:
        if ticket_type in self.ticket_types:
            command = self.ticket_types[ticket_type]
            return command.execute(*args, **kwargs)
        else:
            print(f"Ticket type '{ticket_type}' not found.")
            return None


class GenerateInitializationTicket(GenerateXXXTicket):
    def execute(self, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_INITIALIZATION_TICKET
        # no device_id
        new_ticket.holder_id = holder_id

        return new_ticket


class GenerateManagementTicket(GenerateXXXTicket):
    def execute(
        self,
        device_priv_key: ec.EllipticCurvePublicKey,
        device_id: str,
        holder_id: str,
        task_scope: str,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_MANAGEMENT_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

        return new_ticket


class GenerateAccessPermissionTicket(GenerateXXXTicket):
    def execute(
        self,
        device_priv_key: ec.EllipticCurvePublicKey,
        device_id: str,
        holder_id: str,
        task_scope: str,
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_ACCESS_PERMISSION_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

        return new_ticket


class GenerateChallengeTicket(GenerateXXXTicket):
    def execute(
        self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_CHALLENGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Challenge
        random_challenge = ecdh.generate_random_byte(32)
        new_ticket.task_scope = serialization_util.byte_to_str(random_challenge)

        new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

        return new_ticket


class GenerateResponseTicket(GenerateXXXTicket):
    def execute(
        self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_RESPONSE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

        return new_ticket


class GenerateKeyExchangeTicket(GenerateXXXTicket):
    def execute(
        self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_KEY_EXCHANGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Salt
        random_salt = ecdh.generate_random_byte(32)
        new_ticket.task_scope = serialization_util.byte_to_str(random_salt)

        new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

        # Generate (temp) session_key (Side Effect)
        self.device_controller.execute_update_current_session_key_byte(
            server_private_key_obj=device_priv_key,
            salt_byte=random_salt,
            info_byte=b"",
            peer_public_key_obj=serialization_util.str_to_key(
                holder_id, key_type="ecc-public-key"
            ),
        )

        return new_ticket
