from returns.pipeline import flow, pipe
from returns.pointfree import bind
from returns.result import Result, Success, Failure
from ureka_framework.controller.ticket_generation.ticket_generation_router import (
    TicketGenerationRouter,
    GenerateAccessPermissionTicket,
    GenerateChallengeTicket,
    GenerateInitializationTicket,
    GenerateKeyExchangeTicket,
    GenerateManagementTicket,
    GenerateResponseTicket,
)
from ureka_framework.controller.ticket_verification.ticket_verification_flow import (
    VerificationFlow,
)
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from typing import Union


class DeviceController:
    def __init__(self, device_type: str = "", device_name: str = "") -> None:
        # Device Type (Device can be User Agent, Cloud Server, or IoT Device...)
        self.device_type: str = ""
        self.device_name: str = ""
        self.has_device_type: bool = False

        # Generate Keys after Intialization
        self.is_initialized: bool = False
        self.device_priv_key: ec.EllipticCurvePrivateKey = None
        self.device_pub_key: ec.EllipticCurvePublicKey = None
        self.owner_pub_key: ec.EllipticCurvePublicKey = None

        # Current Session (RAM-only)
        self.current_holder_pub_key: ec.EllipticCurvePublicKey = None
        self.current_session_key_byte: bytes = None

        # Set Ticket Generation Router based on Ticket Protocol
        self.ticket_generation_router: TicketGenerationRouter = None
        self.set_ticket_generation_route()

        # Set SecureDB
        self.secure_db = SecureDB(device_name=device_name)

        # Always load SecureDB after Reboot
        (
            self.has_device_type,
            self.is_initialized,
            self.device_type,
            self.device_name,
            self.device_priv_key,
            self.device_pub_key,
            self.owner_pub_key,
        ) = self.secure_db.load_secure_db()

        # Set Device Type
        if self.has_device_type is False:
            self.execute_one_time_set_time_device_type_and_name(
                device_type, device_name
            )

    @property
    def device_priv_key_str(self) -> str:
        if self.device_priv_key is None:
            return ""
        return serialization_util.key_to_str(
            self.device_priv_key, key_type="ecc-private-key"
        )

    @property
    def device_pub_key_str(self) -> str:
        if self.device_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.device_pub_key, key_type="ecc-public-key"
        )

    @property
    def owner_pub_key_str(self) -> str:
        if self.owner_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.owner_pub_key, key_type="ecc-public-key"
        )

    ######################################################
    # Device Activity Cycle
    ######################################################
    def reboot_device(self) -> None:
        self.__init__(device_type=self.device_type, device_name=self.device_name)

    ######################################################
    # Generate Different Ticket Types
    ######################################################
    def set_ticket_generation_route(self) -> None:
        self.ticket_generation_router = TicketGenerationRouter()
        self.ticket_generation_router.add_ticket_type(
            "intialization", GenerateInitializationTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "management", GenerateManagementTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "access_permission",
            GenerateAccessPermissionTicket(self),
        )
        self.ticket_generation_router.add_ticket_type(
            "challenge", GenerateChallengeTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "response", GenerateResponseTicket(self)
        )
        self.ticket_generation_router.add_ticket_type(
            "key_exchange", GenerateKeyExchangeTicket(self)
        )

    ######################################################
    # Verify Different Ticket Types
    ######################################################
    def verify_xxx_ticket(self, ticket_in: Ticket) -> Union[Failure, Success]:
        logging.info(f"+ {self.device_name} is verifying ticket...")

        # verification_flow = VerificationFlow(self)
        # verification_flow.verify_ticket_protocol_version(ticket_in)
        # verification_flow.verify_ticket_type(ticket_in)
        # verification_flow.verify_device_id(ticket_in, self.device_pub_key_str)
        # verification_flow.verify_issuer_signature(
        #     ticket_in, self.owner_pub_key, self.current_holder_pub_key
        # )
        # verification_flow.execute_ticket_operation(ticket_in, self.device_priv_key)

        verification_flow = VerificationFlow(self)
        verification_result = flow(
            ticket_in,
            lambda ticket_in_flow: verification_flow.verify_ticket_protocol_version(
                ticket_in_flow
            ),
            bind(
                lambda ticket_in_flow: verification_flow.verify_ticket_type(
                    ticket_in_flow
                )
            ),
            bind(
                lambda ticket_in_flow: verification_flow.verify_device_id(
                    ticket_in_flow, self.device_pub_key_str
                )
            ),
            bind(
                lambda ticket_in_flow: verification_flow.verify_issuer_signature(
                    ticket_in_flow, self.owner_pub_key, self.current_holder_pub_key
                )
            ),
            bind(
                lambda ticket_in_flow: verification_flow.execute_ticket_operation(
                    ticket_in_flow, self.device_priv_key
                )
            ),
        )
        return verification_result

    ######################################################
    # Set Device Type
    ######################################################
    def execute_one_time_set_time_device_type_and_name(
        self, device_type: str, device_name: str
    ) -> bool:
        # Determine device type name, but still be uninitialized
        # Determine device name (for test)
        self.is_initialized = False
        self.device_type = device_type
        self.device_name = device_name

        # DB
        self.secure_db.store_device_type_and_name(device_type, device_name)

        return Success(None)

    ######################################################
    # Initilize User Agent or Cloud Server (without using Ticket)
    ######################################################
    def execute_one_time_intialize_agent_or_server(self) -> Union[Failure, Success]:
        logging.info(f"+ {self.device_name} is initializing...")

        if self.device_type != ticket.USER_AGENT_OR_CLOUD_SERVER:
            failure_msg = "FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        if self.is_initialized:
            failure_msg = "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        device_priv_key_byte = b""
        device_pub_key_byte = b""
        (device_priv_key_byte, device_pub_key_byte) = ecc.generate_key_pair()

        # RAM
        self.is_initialized = True
        self.device_priv_key = serialization_util.byte_to_key(
            device_priv_key_byte, key_type="ecc-private-key"
        )
        self.device_pub_key = serialization_util.byte_to_key(
            device_pub_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.secure_db.store_is_initialized()
        self.secure_db.store_device_id(device_priv_key_byte, device_pub_key_byte)

        return Success(None)

    ######################################################
    # Execute Initialization & Managment Ticket (E-Z)
    ######################################################
    def execute_one_time_initialize_iot_device(self, new_ticket: Ticket) -> Union[Failure, Success]:
        logging.info(f"+ {self.device_name} is intializing...")

        if self.device_type != ticket.IOT_DEVICE:
            failure_msg = (
                "FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION"
            )
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        if self.is_initialized:
            failure_msg = "FAILURE: IOT_DEVICE ALREADY INITIALIZED"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        device_priv_key_byte = b""
        device_pub_key_byte = b""
        (device_priv_key_byte, device_pub_key_byte) = ecc.generate_key_pair()

        # RAM
        self.is_initialized = True
        self.device_priv_key = serialization_util.byte_to_key(
            device_priv_key_byte, key_type="ecc-private-key"
        )
        self.device_pub_key = serialization_util.byte_to_key(
            device_pub_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.secure_db.store_is_initialized()
        self.secure_db.store_device_id(device_priv_key_byte, device_pub_key_byte)

        ######################################################
        # Update Permission Table (only for IoT Device)
        ######################################################

        # RAM
        self.owner_pub_key = serialization_util.str_to_key(new_ticket.holder_id)

        # DB
        owner_public_key_byte = serialization_util.str_to_byte(new_ticket.holder_id)
        self.secure_db.store_owner_id(owner_public_key_byte)

        return Success(None)

    def execute_ownership_transfer(self, new_ticket: Ticket) -> None:
        logging.info(f"+ {self.device_name} is transferring ownership...")

        ######################################################
        # Decode Request Body
        ######################################################
        task_scope_dict = serialization_util.jsonstr_to_dict(
            new_ticket.task_scope
        )  # sort_keys = True

        ######################################################
        # Update Permission Table (MANAGEMENT_OWNER)
        ######################################################
        if (
            task_scope_dict[ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE]
            == ticket.MANAGEMENT_OWNER
        ):
            # RAM
            self.owner_pub_key = serialization_util.str_to_key(
                new_ticket.holder_id, key_type="ecc-public-key"
            )

            # DB
            owner_public_key_byte = serialization_util.str_to_byte(new_ticket.holder_id)
            self.secure_db.store_owner_id(owner_public_key_byte)

        return Success(None)

    ######################################################
    # Execute Access Permission Ticket (E-N)
    ######################################################
    def execute_update_current_holder_pub_key(
        self,
        new_current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> Success:
        logging.info(f"+ {self.device_name} is updating current holder pub key...")

        # RAM
        self.current_holder_pub_key = new_current_holder_pub_key

        return Success(None)

    def execute_update_current_session_key_byte(
        self,
        server_private_key_obj: ec.EllipticCurvePrivateKey,
        salt_byte: bytes,
        info_byte: bytes,
        peer_public_key_obj: ec.EllipticCurvePublicKey,
    ) -> Success:
        logging.info(f"+ {self.device_name} is updating current session key byte...")

        # RAM
        self.current_session_key_byte = ecdh.generate_ecdh_key(
            server_private_key=server_private_key_obj,
            salt=salt_byte,
            info=info_byte,
            peer_public_key=peer_public_key_obj,
        )
        logging.debug(
            f"current_session_key_byte in {self.device_name}: {str(self.current_session_key_byte)}"
        )

        return Success(None)
