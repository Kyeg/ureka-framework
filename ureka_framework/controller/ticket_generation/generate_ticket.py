from ureka_framework.controller.ticket_execution import ExecutionFlow
import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
import ureka_framework.resource.crypto.key_serialization as key_serialization
from cryptography.hazmat.primitives.asymmetric import ec
import logging


# Interface for the Command Object
class GenerateXXXTicket:
    # Better not have side effect on device_controller
    def __init__(self, device_controller) -> None:
        self.device_controller = device_controller

    def execute(self, *args, **kwargs):
        pass

    ######################################################
    # Add ECC Signature on Ticket
    ######################################################
    def _add_issuer_signature_on_ticket(
        self, ticket_in: Ticket, private_key: ec.EllipticCurvePrivateKey
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


class GenerateInitializationTicket(GenerateXXXTicket):
    def execute(self, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_INITIALIZATION_TICKET
        # no device_id
        new_ticket.holder_id = holder_id

        return new_ticket


class GenerateQueryTicket(GenerateXXXTicket):
    def execute(self) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_QUERY_TICKET

        return new_ticket


class GenerateManagementTicket(GenerateXXXTicket):
    def execute(self, device_id: str, holder_id: str, task_scope: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_MANAGEMENT_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self._add_issuer_signature_on_ticket(
            new_ticket, self.device_controller.device_priv_key
        )

        return new_ticket


class GenerateAccessPermissionTicket(GenerateXXXTicket):
    def execute(self, device_id: str, holder_id: str, task_scope: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_ACCESS_PERMISSION_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self._add_issuer_signature_on_ticket(
            new_ticket, self.device_controller.device_priv_key
        )

        return new_ticket


class GenerateChallengeTicket(GenerateXXXTicket):
    def execute(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_CHALLENGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Challenge
        random_challenge = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_challenge)

        new_ticket = self._add_issuer_signature_on_ticket(
            new_ticket, self.device_controller.device_priv_key
        )

        return new_ticket


class GenerateResponseTicket(GenerateXXXTicket):
    def execute(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_RESPONSE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        new_ticket = self._add_issuer_signature_on_ticket(
            new_ticket, self.device_controller.device_priv_key
        )

        return new_ticket


class GenerateKeyExchangeTicket(GenerateXXXTicket):
    def execute(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_KEY_EXCHANGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Salt
        random_salt = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_salt)

        new_ticket = self._add_issuer_signature_on_ticket(
            new_ticket, self.device_controller.device_priv_key
        )

        # Generate (temp) session_key (Side Effect)
        execution_flow = ExecutionFlow(self.device_controller)
        self.device_controller.current_session_key_byte = (
            execution_flow.generate_session_key(
                server_private_key_obj=self.device_controller.device_priv_key,
                salt_byte=random_salt,
                info_byte=b"",
                peer_public_key_obj=key_serialization.str_backto_key(
                    holder_id, key_type="ecc-public-key"
                ),
            )
        )
        logging.debug(
            "current_session_key_byte: "
            + str(self.device_controller.current_session_key_byte)
        )

        return new_ticket


class GenerateCommandTicket(GenerateXXXTicket):
    def execute(self) -> Ticket:
        pass


class GenerateReturnTicket(GenerateXXXTicket):
    def execute(self) -> Ticket:
        pass
