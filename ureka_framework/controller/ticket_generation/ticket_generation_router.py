# import copy
# import logging
# from ureka_framework.data_model.ticket import Ticket
# import ureka_framework.data_model.ticket as ticket
# import ureka_framework.resource.crypto.serialization_util as serialization_util
# import ureka_framework.resource.crypto.ecc as ecc
# import ureka_framework.resource.crypto.ecdh as ecdh
# from abc import ABC, abstractmethod
# from cryptography.hazmat.primitives.asymmetric import ec


# # Interface for the Command Object
# class GenerateXXXTicket(ABC):
#     # Better not have side effect on device_controller
#     def __init__(self, device_controller) -> None:
#         self.device_controller = device_controller

#     @abstractmethod
#     def execute(self, *args, **kwargs):
#         pass

#     ######################################################
#     # Add ECC Signature on Ticket
#     ######################################################
#     def _add_issuer_signature_on_ticket(
#         self, unsigned_ticket: Ticket, private_key: ec.EllipticCurvePrivateKey
#     ) -> Ticket:
#         # Message
#         unsigned_ticket_str = serialization_util.ticket_to_jsonstr(unsigned_ticket)
#         unsigned_ticket_byte = serialization_util.str_to_byte(unsigned_ticket_str)

#         # Sign Signature
#         signature_byte = ecc.sign_signature(unsigned_ticket_byte, private_key)

#         # Add Signature on New Signed Ticket, but Prevent Side Effect on Unsigned Ticket
#         signed_ticket = copy.deepcopy(unsigned_ticket)
#         signed_ticket.issuer_signature = serialization_util.byte_to_str(signature_byte)

#         return signed_ticket


# # Interface for the Invoker/Router
# class TicketGenerationRouter:
#     def __init__(self) -> None:
#         self.ticket_types: dict = {}

#     # Set Route-Command
#     def add_ticket_type(self, ticket_type: str, command: GenerateXXXTicket) -> None:
#         self.ticket_types[ticket_type] = command

#     # Execute Command
#     def generate_xxx_ticket(self, ticket_type: str, *args, **kwargs) -> Ticket:
#         if ticket_type in self.ticket_types:
#             command = self.ticket_types[ticket_type]
#             return command.execute(*args, **kwargs)
#         else:
#             print(f"Ticket type '{ticket_type}' not found.")
#             return None


# ######################################################
# # Message Generation Flow
# ######################################################
# class GenerateArbitraryTicket(GenerateXXXTicket):
#     def execute(
#         self, arbitrary_dict: dict, device_priv_key: ec.EllipticCurvePublicKey
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket(**arbitrary_dict)

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Random Salt for Challenge-response or Key-exchange

#         # Add Signature
#         # new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         ######################################################
#         # Side Effect
#         ######################################################
#         # Generate (temp) session_key (Side Effect)

#         return new_ticket


# class GenerateInitializationTicket(GenerateXXXTicket):
#     def execute(self, holder_id: str) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()
#         new_ticket.ticket_type = ticket.TYPE_INITIALIZATION_TICKET
#         new_ticket.device_id = ""
#         new_ticket.holder_id = holder_id

#         return new_ticket


# class GenerateManagementTicket(GenerateXXXTicket):
#     def execute(
#         self,
#         device_priv_key: ec.EllipticCurvePublicKey,
#         device_id: str,
#         holder_id: str,
#         task_scope: str,
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()

#         new_ticket.ticket_type = ticket.TYPE_MANAGEMENT_TICKET
#         new_ticket.device_id = device_id
#         new_ticket.holder_id = holder_id
#         new_ticket.task_scope = task_scope

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Add Signature
#         new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         return new_ticket


# class GenerateAccessPermissionTicket(GenerateXXXTicket):
#     def execute(
#         self,
#         device_priv_key: ec.EllipticCurvePublicKey,
#         device_id: str,
#         holder_id: str,
#         task_scope: str,
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()

#         new_ticket.ticket_type = ticket.TYPE_ACCESS_PERMISSION_TICKET
#         new_ticket.device_id = device_id
#         new_ticket.holder_id = holder_id
#         new_ticket.task_scope = task_scope

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Add Signature
#         new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         return new_ticket


# class GenerateChallengeTicket(GenerateXXXTicket):
#     def execute(
#         self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()

#         new_ticket.ticket_type = ticket.TYPE_CHALLENGE_TICKET
#         new_ticket.device_id = device_id
#         new_ticket.holder_id = holder_id

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Random Salt for Challenge-response
#         random_salt = ecdh.generate_random_byte(32)
#         new_ticket.task_scope = serialization_util.byte_to_str(random_salt)

#         # Add Signature & Salt
#         new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         return new_ticket


# class GenerateResponseTicket(GenerateXXXTicket):
#     def execute(
#         self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()

#         new_ticket.ticket_type = ticket.TYPE_RESPONSE_TICKET
#         new_ticket.device_id = device_id
#         new_ticket.holder_id = holder_id

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Add Signature
#         new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         return new_ticket


# class GenerateKeyExchangeTicket(GenerateXXXTicket):
#     def execute(
#         self, device_priv_key: ec.EllipticCurvePublicKey, device_id: str, holder_id: str
#     ) -> Ticket:
#         ######################################################
#         # Unsigned Ticket
#         ######################################################
#         new_ticket = ticket.Ticket()

#         new_ticket.ticket_type = ticket.TYPE_KEY_EXCHANGE_TICKET
#         new_ticket.device_id = device_id
#         new_ticket.holder_id = holder_id

#         ######################################################
#         # Signed Ticket
#         ######################################################
#         # Random Salt for Key-exchange
#         random_salt = ecdh.generate_random_byte(32)
#         new_ticket.task_scope = serialization_util.byte_to_str(random_salt)

#         # Add Signature & Salt
#         new_ticket = self._add_issuer_signature_on_ticket(new_ticket, device_priv_key)

#         ######################################################
#         # Side Effect
#         ######################################################
#         # Generate (temp) session_key (Side Effect)
#         self.device_controller.execute_update_current_session_key_byte(
#             server_private_key_obj=device_priv_key,
#             salt_byte=random_salt,
#             info_byte=b"",
#             peer_public_key_obj=serialization_util.str_to_key(
#                 holder_id, key_type="ecc-public-key"
#             ),
#         )

#         return new_ticket
