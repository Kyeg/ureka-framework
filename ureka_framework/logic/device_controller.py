from returns.pipeline import flow
from returns.pointfree import bind
from returns.result import Result, Success, Failure
from ureka_framework.logic.ticket_generator import (
    TicketGenerator,
)
from ureka_framework.logic.ticket_verifier import (
    TicketVerifier,
)
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.other_device import OtherDevice, device_table_to_jsonstr
from ureka_framework.data_model.this_person import ThisPerson
from ureka_framework.data_model.ticket import Ticket, jsonstr_to_ticket
import ureka_framework.data_model.ticket as ticket

from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel
from ureka_framework.resource.storage.simple_storage import SimpleStorage
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class DeviceController:
    def __init__(self, device_type: str = "", device_name: str = "") -> None:
        # Data Model
        self.this_device: ThisDevice = ThisDevice()
        self.device_table: dict[str, OtherDevice] = {}
        # Data Model (User Agent or Cloud Server only)
        self.this_person: ThisPerson = ThisPerson()

        # Set Storage
        self.simple_storage: SimpleStorage = SimpleStorage(device_name=device_name)
        # Set Communication
        self.comm_channel: FakeCommChannel = None

        # Always load Storage after Reboot
        (
            self.this_device,
            self.device_table,
            self.this_person,
        ) = self.simple_storage.load_storage()

        # Set Device Type (must after loading storage)
        if self.this_device.has_device_type is False:
            self.execute_one_time_set_time_device_type_and_name(
                device_type, device_name
            )

        logging.info(f"+ Here is a {self.this_device.device_name}...")

    ######################################################
    # Device Activity Cycle
    ######################################################
    def reboot_device(self) -> None:
        self.__init__(
            device_type=self.this_device.device_type,
            device_name=self.this_device.device_name,
        )

    ######################################################
    # Communication
    ######################################################
    def connect(self, comm_channel: FakeCommChannel) -> None:
        self.comm_channel = comm_channel
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is connecting with {end.this_device.device_name}..."
                )

    def send_xxx_ticket(self, ticket_json: str) -> None:
        self.comm_channel.message_in_channel = ticket_json
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is sending ticket to {end.this_device.device_name}..."
                )
                # logging.debug(f"+ Ticket=\n{self.comm_channel.message_in_channel}")

    def recv_xxx_ticket(self) -> str:
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is receiving ticket from {end.this_device.device_name}..."
                )
                # logging.debug(f"+ Ticket=\n{self.comm_channel.message_in_channel}")

        # ToDo: Update Device Table (Role, State, etc.)
        # RAM: Add Device & Ticket in Device Table
        recveived_ticket_json = self.comm_channel.message_in_channel
        recveived_ticket = jsonstr_to_ticket(recveived_ticket_json)
        if recveived_ticket.ticket_type != ticket.TYPE_INITIALIZATION_TICKET:
            self.device_table[recveived_ticket.device_id] = OtherDevice(
                device_id=recveived_ticket.device_id,
                device_name="device_id's name",
                device_ticket=recveived_ticket_json,
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return recveived_ticket_json

    ######################################################
    # Set Device Type
    ######################################################
    def execute_one_time_set_time_device_type_and_name(
        self, device_type: str, device_name: str
    ) -> bool:
        # Determine device type name, but still be uninitialized
        # Determine device name (for test)
        self.this_device.is_initialized = False
        self.this_device.has_device_type = True
        self.this_device.device_type = device_type
        self.this_device.device_name = device_name

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return Success(None)

    ######################################################
    # Initilize without using Ticket (User Agent or Cloud Server only)
    ######################################################
    def execute_one_time_intialize_agent_or_server(
        self,
    ) -> Result[None, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is initializing...")

        if self.this_device.device_type != ticket.USER_AGENT_OR_CLOUD_SERVER:
            failure_msg = "FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        if self.this_device.is_initialized:
            failure_msg = "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()

        # RAM
        self.this_device.is_initialized = True
        self.this_device.device_priv_key = device_priv_key
        self.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Personal Id
        ######################################################
        # CRYPTO
        (person_priv_key, person_pub_key) = ecc.generate_key_pair()

        # RAM
        self.this_person.person_priv_key = person_priv_key
        self.this_person.person_pub_key = person_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.this_device.owner_pub_key = self.this_person.person_pub_key

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return Success(None)

    ######################################################
    # Generate Different Ticket Types (User Agent or Cloud Server only)
    ######################################################
    def generate_xxx_ticket(self, arbitrary_dict: dict) -> str:
        logging.info(f"+ {self.this_device.device_name} is generating ticket...")

        ticket_generator = TicketGenerator(self.this_device, self.this_person)
        generated_ticket_json = flow(
            arbitrary_dict,
            ticket_generator.generate_arbitrary_ticket,
        )
        self.execute_generate_xxx_ticket(generated_ticket_json)
        return generated_ticket_json

    ######################################################
    # Execute Operation based on generate_xxx_ticket
    ######################################################
    def execute_generate_xxx_ticket(self, generated_ticket_json) -> None:
        generated_ticket = jsonstr_to_ticket(generated_ticket_json)

        # RAM: Generate session_key (Device)
        if generated_ticket.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            self.execute_update_current_session_key_byte(
                server_private_key_obj=self.this_device.device_priv_key,
                salt_byte=serialization_util.base64str_backto_byte(
                    generated_ticket.task_scope
                ),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    generated_ticket.holder_id, key_type="ecc-public-key"
                ),
            )

        # ToDo: Update Device Table (Role, State, etc.)

    ######################################################
    # Verify Different Ticket Types
    ######################################################
    def verify_xxx_ticket(self, arbitrary_json: str) -> Result[Ticket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is verifying ticket...")

        ticket_verifier = TicketVerifier(self.this_device, self.this_person)
        verification_and_execution_result = flow(
            arbitrary_json,
            ticket_verifier.verify_json_schema,
            bind(ticket_verifier.verify_ticket_protocol_version),
            bind(ticket_verifier.verify_ticket_type),
            bind(ticket_verifier.verify_device_id),
            bind(ticket_verifier.verify_issuer_signature),
            bind(self.execute_verify_xxx_ticket),
        )
        return verification_and_execution_result

    ######################################################
    # Execute Operation based on verify_xxx_ticket
    ######################################################
    def execute_verify_xxx_ticket(
        self, ticket_in: Ticket
    ) -> Result[Ticket, RuntimeError]:
        failure_msg = f"-> FAILURE: WIRED TICKET TYPE {ticket_in.ticket_type}"

        # (E-Z) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            result = self.execute_one_time_initialize_iot_device(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            result = self.execute_ownership_transfer(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            # Generate session_key (Device)
            self.execute_update_current_holder_pub_key(
                serialization_util.str_to_key(
                    ticket_in.holder_id, key_type="ecc-public-key"
                )
            )
            # To-Do: Auto-Generate Challenge Ticket
            result = Success(None)
        # (E-N) Execute TICKET
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Auto-Generate Response Ticket
            result = Success(None)
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Auto-Generate Key Exchange Ticket
            result = Success(None)
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # Generate session_key (Person)
            result = self.execute_update_current_session_key_byte(
                server_private_key_obj=self.this_person.person_priv_key,
                salt_byte=serialization_util.base64str_backto_byte(
                    ticket_in.task_scope
                ),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            # To-Do: Create Session
            # To-Do: Auto-Generate Command Ticket
        else:  # pragma: no cover
            # Never reach here: Because of verify_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        return result

    ######################################################
    # Execute Initialization & Managment Ticket (E-Z)
    ######################################################
    def execute_one_time_initialize_iot_device(
        self, new_ticket: Ticket
    ) -> Result[None, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is intializing...")

        if self.this_device.device_type != ticket.IOT_DEVICE:
            failure_msg = (
                "FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION"
            )
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        if self.this_device.is_initialized:
            failure_msg = "FAILURE: IOT_DEVICE ALREADY INITIALIZED"
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()

        # RAM
        self.this_device.is_initialized = True
        self.this_device.device_priv_key = device_priv_key
        self.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.this_device.owner_pub_key = serialization_util.str_to_key(
            new_ticket.holder_id
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return Success(None)

    def execute_ownership_transfer(self, new_ticket: Ticket) -> None:
        logging.info(f"+ {self.this_device.device_name} is transferring ownership...")

        ######################################################
        # Decode Request Body
        ######################################################
        task_scope_dict = serialization_util.jsonstr_to_dict(
            new_ticket.task_scope
        )  # sort_keys = True

        ######################################################
        # Update Device Owner
        ######################################################
        if (
            task_scope_dict[ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE]
            == ticket.MANAGEMENT_OWNER
        ):
            # RAM
            self.this_device.owner_pub_key = serialization_util.str_to_key(
                new_ticket.holder_id, key_type="ecc-public-key"
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return Success(None)

    ######################################################
    # Execute Access Permission Ticket (E-N)
    ######################################################
    def execute_update_current_holder_pub_key(
        self,
        new_current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> Result[None, RuntimeError]:
        logging.info(
            f"+ {self.this_device.device_name} is updating current holder pub key..."
        )

        ######################################################
        # Update Session
        ######################################################
        # RAM
        self.this_device.current_holder_pub_key = new_current_holder_pub_key

        ######################################################
        # Storage (RAM Only)
        ######################################################
        # self.simple_storage.store_storage(self.this_device, self.device_table, self.this_person)

        return Success(None)

    def execute_update_current_session_key_byte(
        self,
        server_private_key_obj: ec.EllipticCurvePrivateKey,
        salt_byte: bytes,
        info_byte: bytes,
        peer_public_key_obj: ec.EllipticCurvePublicKey,
    ) -> Result[None, RuntimeError]:
        logging.info(
            f"+ {self.this_device.device_name} is updating current session key byte..."
        )

        ######################################################
        # Update Session
        ######################################################
        # RAM
        self.this_device.current_session_key_byte = ecdh.generate_ecdh_key(
            server_private_key=server_private_key_obj,
            salt=salt_byte,
            info=info_byte,
            peer_public_key=peer_public_key_obj,
        )
        logging.debug(
            f"current_session_key_byte in {self.this_device.device_name}: {str(self.this_device.current_session_key_byte)}"
        )

        ######################################################
        # Storage (RAM Only)
        ######################################################
        # self.simple_storage.store_storage(self.this_device, self.device_table, self.this_person)

        return Success(None)
