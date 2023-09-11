from returns.pipeline import flow
from returns.pointfree import bind
from returns.result import Result, Success, Failure
from ureka_framework.logic.u_ticket_generator import (
    UTicketGenerator,
)
from ureka_framework.logic.u_ticket_verifier import (
    UTicketVerifier,
)
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.other_device import OtherDevice, device_table_to_jsonstr
from ureka_framework.data_model.this_person import ThisPerson
from ureka_framework.data_model.u_ticket import UTicket, jsonstr_to_u_ticket
import ureka_framework.data_model.u_ticket as u_ticket

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
            self._execute_one_time_set_time_device_type_and_name(
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
    # [IO-level] TODO
    # REQ: holder_issue_request()
    # CST: issuer_respond_received_request() / issuer_issue_consent()
    # APY: holder_access_device()
    ######################################################
    def issuer_issue_consent(self, arbitrary_dict: dict) -> str:
        generated_u_ticket: str = self._generate_xxx_u_ticket(arbitrary_dict)
        self._send_xxx_u_ticket(generated_u_ticket)
        return generated_u_ticket

    def holder_receive_consent(self) -> str:
        received_u_ticket: str = self._recv_xxx_u_ticket()
        return received_u_ticket

    def holder_access_device(self, device_id: str) -> str:
        stored_u_ticket: str = self.device_table[device_id].device_u_ticket
        self._send_xxx_u_ticket(stored_u_ticket)
        return stored_u_ticket

    def device_be_accessed(self) -> Result[UTicket, RuntimeError]:
        forwarded_u_ticket: str = self._recv_xxx_u_ticket()
        result = self._verify_xxx_u_ticket(forwarded_u_ticket)
        # TODO: Return result in R-Ticket
        return forwarded_u_ticket

    ######################################################
    # [Func-level: 'R'VEGE"S"] Message Communication
    ######################################################
    def _connect(self, comm_channel: FakeCommChannel) -> None:
        self.comm_channel = comm_channel
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is connecting with {end.this_device.device_name}..."
                )

    def _recv_xxx_u_ticket(self) -> str:
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is receiving u_ticket from {end.this_device.device_name}..."
                )
                # logging.debug(f"+ UTicket=\n{self.comm_channel.message_in_channel}")

        # TODO: [R'VE'GES] Verify Message -> Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        recveived_u_ticket_json = self.comm_channel.message_in_channel
        recveived_u_ticket = jsonstr_to_u_ticket(recveived_u_ticket_json)
        if recveived_u_ticket.u_ticket_type != u_ticket.TYPE_INITIALIZATION_UTICKET:
            self.device_table[recveived_u_ticket.device_id] = OtherDevice(
                device_id=recveived_u_ticket.device_id,
                device_name="device_id's name",
                device_u_ticket=recveived_u_ticket_json,
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return recveived_u_ticket_json

    def _send_xxx_u_ticket(self, u_ticket_json: str) -> None:
        self.comm_channel.message_in_channel = u_ticket_json
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is sending u_ticket to {end.this_device.device_name}..."
                )
                # logging.debug(f"+ UTicket=\n{self.comm_channel.message_in_channel}")

    ######################################################
    # [Func-level: R'V'EGES] Message Verification
    ######################################################
    def _verify_xxx_u_ticket(
        self, arbitrary_json: str
    ) -> Result[UTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is verifying u_ticket...")

        u_ticket_verifier = UTicketVerifier(self.this_device, self.this_person)
        verification_and_execution_result = flow(
            arbitrary_json,
            u_ticket_verifier.verify_json_schema,
            bind(u_ticket_verifier.verify_protocol_version),
            bind(u_ticket_verifier.verify_u_ticket_type),
            bind(u_ticket_verifier.verify_device_id),
            bind(u_ticket_verifier.verify_issuer_signature),
            bind(self._execute_verify_xxx_u_ticket),
        )
        return verification_and_execution_result

    ######################################################
    # [Func-level: RV'E'GES] Message Execution (after Verification)
    ######################################################
    def _execute_verify_xxx_u_ticket(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        failure_msg = f"-> FAILURE: WIRED UTICKET TYPE {u_ticket_in.u_ticket_type}"

        # (E-Z) Execute UTICKET
        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            result = self._execute_one_time_initialize_iot_device(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_MANAGEMENT_UTICKET:
            self._execute_ownership_transfer(u_ticket_in)
            result = Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET:
            # Generate session_key (Device)
            self._execute_update_current_holder_pub_key(
                serialization_util.str_to_key(
                    u_ticket_in.holder_id, key_type="ecc-public-key"
                )
            )
            # To-Do: Auto-Generate Challenge UTicket
            result = Success(u_ticket_in)
        # (E-N) Execute UTICKET
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_CHALLENGE_UTICKET:
            # To-Do: Auto-Generate Response UTicket
            result = Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_RESPONSE_UTICKET:
            # To-Do: Auto-Generate Key Exchange UTicket
            result = Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_KEY_EXCHANGE_UTICKET:
            # Generate session_key (Person)
            self._execute_update_current_session_key_byte(
                server_private_key_obj=self.this_person.person_priv_key,
                salt_byte=serialization_util.base64str_backto_byte(
                    u_ticket_in.task_scope
                ),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    u_ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            result = Success(u_ticket_in)
            # To-Do: Create Session
            # To-Do: Auto-Generate Command UTicket
        else:  # pragma: no cover
            # Never reach here: Because of verify_u_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        return result

    def _execute_one_time_set_time_device_type_and_name(
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

    def _execute_one_time_intialize_agent_or_server(
        self,
    ) -> Result[None, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is initializing...")

        if self.this_device.device_type != u_ticket.USER_AGENT_OR_CLOUD_SERVER:
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

    def _execute_one_time_initialize_iot_device(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is intializing...")

        if self.this_device.device_type != u_ticket.IOT_DEVICE:
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
            u_ticket_in.holder_id
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return Success(u_ticket_in)

    def _execute_ownership_transfer(self, new_u_ticket: UTicket) -> None:
        logging.info(f"+ {self.this_device.device_name} is transferring ownership...")

        ######################################################
        # Decode Request Body
        ######################################################
        task_scope_dict = serialization_util.jsonstr_to_dict(
            new_u_ticket.task_scope
        )  # sort_keys = True

        ######################################################
        # Update Device Owner
        ######################################################
        if (
            task_scope_dict[u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE]
            == u_ticket.MANAGEMENT_OWNER
        ):
            # RAM
            self.this_device.owner_pub_key = serialization_util.str_to_key(
                new_u_ticket.holder_id, key_type="ecc-public-key"
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

    def _execute_update_current_holder_pub_key(
        self,
        new_current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> None:
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

    def _execute_update_current_session_key_byte(
        self,
        server_private_key_obj: ec.EllipticCurvePrivateKey,
        salt_byte: bytes,
        info_byte: bytes,
        peer_public_key_obj: ec.EllipticCurvePublicKey,
    ) -> None:
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

    ######################################################
    # [Func-level: RVE'G'ES] Message Generation
    ######################################################
    def _generate_xxx_u_ticket(self, arbitrary_dict: dict) -> str:
        logging.info(f"+ {self.this_device.device_name} is generating u_ticket...")

        u_ticket_generator = UTicketGenerator(self.this_device, self.this_person)
        generated_u_ticket_json = flow(
            arbitrary_dict,
            u_ticket_generator.generate_arbitrary_u_ticket,
        )
        self._execute_generate_xxx_u_ticket(generated_u_ticket_json)
        return generated_u_ticket_json

    ######################################################
    # [Func-level: RVEG'E'S] Message Execution (after Generation)
    ######################################################
    def _execute_generate_xxx_u_ticket(self, generated_u_ticket_json) -> None:
        generated_u_ticket = jsonstr_to_u_ticket(generated_u_ticket_json)

        # RAM: Generate session_key (Device)
        if generated_u_ticket.u_ticket_type == u_ticket.TYPE_KEY_EXCHANGE_UTICKET:
            self._execute_update_current_session_key_byte(
                server_private_key_obj=self.this_device.device_priv_key,
                salt_byte=serialization_util.base64str_backto_byte(
                    generated_u_ticket.task_scope
                ),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    generated_u_ticket.holder_id, key_type="ecc-public-key"
                ),
            )

        # TODO: [RVEG'E'S] Update Device Table (Role, State, etc.)
