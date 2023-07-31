import ureka_framework.controller.ticket_generation.generate_ticket as generate_ticket
from ureka_framework.controller.ticket_generation.ticket_generation_router import (
    TicketGenerationRouter,
)
from ureka_framework.controller.ticket_verification import VerificationFlow
import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.resource.storage.secure_db as secure_db
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
import ureka_framework.resource.crypto.key_serialization as key_serialization
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class DeviceController:
    def __init__(
        self, device_type: str = "", device_name: str = "", db_path: str = ""
    ) -> None:
        # Device Type (Device can be Private Autenticator or IoT Device...)
        self.device_type: str = device_type
        self.device_name: str = device_name

        # False: Uninitialized / True: Initialized
        self.is_initialized: bool = False
        self.device_priv_key: ec.EllipticCurvePrivateKey = None
        self.device_pub_key: ec.EllipticCurvePublicKey = None
        self.owner_pub_key: ec.EllipticCurvePublicKey = None

        # Current Session (RAM-only)
        self.current_holder_pub_key: ec.EllipticCurvePublicKey = None
        self.current_session_key_byte: bytes = None

        # Set Ticket Generation Router
        self.ticket_generation_router: TicketGenerationRouter = None
        self.set_ticket_generation_route()

        # +++ Load SecureDB +++
        self.mSecureDB = secure_db.SecureDB(db_path=db_path)
        (
            self.is_initialized,
            self.device_priv_key,
            self.device_pub_key,
            self.owner_pub_key,
        ) = self.mSecureDB.load_secure_db()

        if self.is_initialized:
            logging.debug(
                "+++ Device controller <%s> was initailized +++" % device_name
            )
            self.display_state()
        else:
            logging.debug(
                "+++ Device controller <%s> was uninitailized +++" % device_name
            )

    @property
    def device_priv_key_str(self) -> str:
        if self.device_priv_key is None:
            return ""
        return key_serialization.key_to_str(
            self.device_priv_key, key_type="ecc-private-key"
        )

    @property
    def device_pub_key_str(self) -> str:
        if self.device_pub_key is None:
            return ""
        return key_serialization.key_to_str(
            self.device_pub_key, key_type="ecc-public-key"
        )

    @property
    def owner_pub_key_str(self) -> str:
        if self.owner_pub_key is None:
            return ""
        return key_serialization.key_to_str(
            self.owner_pub_key, key_type="ecc-public-key"
        )

    ######################################################
    # Display (Debug/Test)
    ######################################################
    def display_state(self) -> None:
        if self.device_type == ticket.USER_AGENT_OR_CLOUD_SERVER:
            logging.debug("#" * 100)
            logging.debug("device_type: %s" % self.device_type)
            logging.debug("")
            logging.debug("device_priv_key_str: %s" % self.device_priv_key_str[0:64])
            logging.debug("device_pub_key_str: %s" % self.device_pub_key_str[0:64])
            logging.debug("#" * 100)

        if self.device_type == ticket.IOT_DEVICE:
            logging.debug("#" * 100)
            logging.debug("device_type: %s" % self.device_type)
            logging.debug("")
            logging.debug("device_priv_key_str: %s" % self.device_priv_key_str[0:64])
            logging.debug("device_pub_key_str: %s" % self.device_pub_key_str[0:64])
            logging.debug("")
            logging.debug("owner_pub_key_str: %s" % self.owner_pub_key_str[0:64])
            logging.debug("#" * 100)

    ######################################################
    # Generate Different Ticket Types
    ######################################################
    def set_ticket_generation_route(self) -> None:
        self.ticket_generation_router = TicketGenerationRouter()
        self.ticket_generation_router.add_ticket_type(
            "intialization", generate_ticket.GenerateInitializationTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "query", generate_ticket.GenerateQueryTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "management", generate_ticket.GenerateManagementTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "access_permission", generate_ticket.GenerateAccessPermissionTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "challenge", generate_ticket.GenerateChallengeTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "response", generate_ticket.GenerateResponseTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "key_exchange", generate_ticket.GenerateKeyExchangeTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "command", generate_ticket.GenerateCommandTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "return", generate_ticket.GenerateReturnTicket(self)
        )

    ######################################################
    # Verify Different Ticket Types
    ######################################################
    def verify_xxx_ticket(self, ticket_in: Ticket) -> None:
        verification_flow = VerificationFlow(self)
        verification_flow.verify_ticket_protocol_verision(ticket_in)
        verification_flow.verify_ticket_type(ticket_in)
        verification_flow.verify_device_id(ticket_in, self.device_pub_key_str)
        verification_flow.verify_issuer_signature(
            ticket_in, self.owner_pub_key, self.current_holder_pub_key
        )
        verification_flow.execute_ticket_operation(ticket_in, self.device_priv_key)

    # ######################################################
    # # Observer
    # ######################################################
    # def update_current_holder_pub_key(
    #     new_current_holder_pub_key: ec.EllipticCurvePublicKey,
    # ) -> None:
    #     pass

    # def update_current_session_key_byte(new_current_session_key_byte: bytes) -> None:
    #     pass

    ######################################################
    # Initilize User Agent or Cloud Server (without using Ticket)
    ######################################################
    def one_time_intialization_command(self) -> bool:
        if self.device_type != ticket.USER_AGENT_OR_CLOUD_SERVER:
            logging.debug(
                "ERROR: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS OPERATION"
            )
            return False

        if self.is_initialized:
            logging.debug("ERROR: ALREADY INITIALIZED")
            return False

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        device_priv_key_byte = b""
        device_pub_key_byte = b""
        (device_priv_key_byte, device_pub_key_byte) = ecc.generate_key_pair()

        # RAM
        self.is_initialized = True
        self.device_priv_key = key_serialization.byte_backto_key(
            device_priv_key_byte, key_type="ecc-private-key"
        )
        self.device_pub_key = key_serialization.byte_backto_key(
            device_pub_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.mSecureDB.store_device_id(device_priv_key_byte, device_pub_key_byte)

        self.display_state()
        return True

    ######################################################
    # Reset Device (Teardown - Development Only Function)
    ######################################################
    def reset_device(self) -> bool:
        self.mSecureDB.delete_secure_db()
        return True
