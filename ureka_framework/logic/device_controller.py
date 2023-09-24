from returns.pipeline import flow
from returns.pointfree import bind
from returns.result import Result, Success, Failure
from ureka_framework.data_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
from ureka_framework.logic.r_ticket_generator import RTicketGenerator
from ureka_framework.logic.r_ticket_verifier import RTicketVerifier
from ureka_framework.logic.u_ticket_generator import (
    UTicketGenerator,
)
from ureka_framework.logic.u_ticket_verifier import (
    UTicketVerifier,
)
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.other_device import OtherDevice
from ureka_framework.data_model.this_person import ThisPerson
from ureka_framework.data_model.u_ticket import (
    UTicket,
    jsonstr_to_u_ticket,
    u_ticket_to_jsonstr,
)
import ureka_framework.data_model.u_ticket as u_ticket
import ureka_framework.data_model.r_ticket as r_ticket

from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel
from ureka_framework.resource.storage.simple_storage import SimpleStorage
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
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
    # [IO-level]
    #
    # CST: issuer_issue_consent_to_herself()
    # REQ: issuer_receive_request() <- holder_issue_request_to_issuer()
    # CST: issuer_issue_consent_to_holder() -> holder_receive_consent()
    # APY: holder_access_device() -> device_be_accessed()
    #       holder_receive_r_ticket() <- device_send_r_ticket()
    # CR-KE-PS:
    #      holder_access_device() -> device_be_accessed()
    #                     holder_recv_cr_ke_1() <- device_send_cr_ke_1()
    #                     holder_send_cr_ke_2() -> device_recv_cr_ke_2()
    #           device_recv_1st_data_r_ticket() <- device_send_1st_data_r_ticket()
    #                     holder_send_command() -> device_recv_command()
    #                        holder_recv_data() <- device_send_data()
    #                                           ...
    #       holder_receive_r_ticket() <- device_send_r_ticket()
    #
    # TODO: More complete Tx (with DID, etc.))
    # TODO: Rollback (e.g., delete the temporary stored state and stored message) if fail
    ######################################################
    def issuer_issue_consent_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> str:
        # [Func-level: RTVE'GT'S]
        if device_id in self.device_table or device_id == "no_id":
            generated_u_ticket_json: str = self._generate_xxx_u_ticket(arbitrary_dict)
            logging.debug(f"Generated UTicket: {generated_u_ticket_json}")
            self._stored_generated_xxx_u_ticket(generated_u_ticket_json)
            return generated_u_ticket_json
        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)
            return failure_msg

    def issuer_issue_consent_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> str:
        # [Func-level: RTVE'GTS']
        if device_id in self.device_table:
            generated_u_ticket_json: str = self._generate_xxx_u_ticket(arbitrary_dict)
            logging.debug(f"Generated UTicket: {generated_u_ticket_json}")
            self._stored_generated_xxx_u_ticket(generated_u_ticket_json)
            self._send_xxx_message(generated_u_ticket_json)
            return generated_u_ticket_json
        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)
            return failure_msg

    def holder_receive_consent(self) -> str:
        # [Func-level: 'RT'VEGTS]
        received_u_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received UTicket: {received_u_ticket_json}")
        self._store_recieved_xxx_u_ticket()
        # [Func-level: RT'VEGTS']
        # Can optionally _verify_xxx_u_ticket
        # Can optionally _generate_xxx_r_ticket & _send_xxx_message
        return received_u_ticket_json

    def holder_access_device(self, device_id: str) -> str:
        # [Func-level: RTVEGT'S']
        if device_id in self.device_table:
            stored_u_ticket_json: str = self.device_table[device_id].device_u_ticket
            logging.debug(f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}")
            # Also can add command in u_ticket
            self._send_xxx_message(stored_u_ticket_json)
            return stored_u_ticket_json
        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)
            return failure_msg

    def device_be_accessed(self) -> None:
        # [Func-level: 'RTVE'GTS]
        received_u_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received UTicket: {received_u_ticket_json}")
        # Can optionally _store_recieved_xxx_u_ticket
        result = self._verify_xxx_u_ticket(received_u_ticket_json)

        # [Func-level: RTVE'GTS']
        if type(result) == Success:
            result_message = f"Success"
        elif type(result) == Failure:
            result_message = f"{result.failure().args[0]}"

        received_u_ticket = jsonstr_to_u_ticket(received_u_ticket_json)
        # CR-KE-PS
        if received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET:
            self._device_send_cr_ke_1(received_u_ticket, result_message)
        # No CR
        else:
            self._device_send_r_ticket(received_u_ticket, result_message)

    def _device_send_cr_ke_1(
        self, received_u_ticket: UTicket, result_message: str
    ) -> None:
        r_ticket_request: dict = {
            "r_ticket_type": f"{r_ticket.TYPE_CRKE1_RTICKET}",
            "device_id": f"{received_u_ticket.device_id}",
            "result": f"{result_message}",
        }
        generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
        logging.debug(f"Generated RTicket: {generated_r_ticket_json}")

        # Can optionally _stored_generated_xxx_r_ticket

        self._send_xxx_message(generated_r_ticket_json)

    def _device_send_r_ticket(
        self, received_u_ticket: UTicket, result_message: str
    ) -> None:
        r_ticket_request: dict = {
            "r_ticket_type": f"{received_u_ticket.u_ticket_type}",
            "device_id": f"{self.this_device.device_pub_key_str}",
            "audit_start": f"{received_u_ticket.u_ticket_id}",
            "result": f"{result_message}",
        }
        generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
        logging.debug(f"Generated RTicket: {generated_r_ticket_json}")

        # Can optionally _stored_generated_xxx_r_ticket

        self._send_xxx_message(generated_r_ticket_json)

    def holder_receive_r_ticket(self) -> str:
        # [Func-level: 'RTVE'GTS]
        recieved_r_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received RTicket: {recieved_r_ticket_json}")
        device_id = self._store_recieved_xxx_r_ticket()

        recieved_r_ticket = jsonstr_to_r_ticket(recieved_r_ticket_json)
        if device_id in self.device_table:
            # Query Corresponding UTicket(s)
            # Notice that even Initialization UTicket is copied to the device_table["device_id"]
            logging.debug(
                f"Corresponding UTicket: {self.device_table[device_id].device_u_ticket}"
            )
            stored_u_ticket: UTicket = jsonstr_to_u_ticket(
                self.device_table[device_id].device_u_ticket
            )

            result = self._verify_xxx_r_ticket(
                arbitrary_json=recieved_r_ticket_json,
                audit_start_ticket=stored_u_ticket,
                audit_end_ticket="",
            )

            if type(result) == Success:
                result_message = f"Success (meaningful R-Ticket)"
            elif type(result) == Failure:  # pragma: no cover -> Weird R-Ticket
                result_message = f"{result.failure().args[0]}"
            logging.debug(f"result_message = {result_message}")
        else:  # pragma: no cover -> IO-level
            failure_msg = (
                f"FAILURE: YOU DO NOT HAVE CORRESPONDING UTICKET FOR THIS DEVICE"
            )
            logging.error(failure_msg)
            return failure_msg

        return recieved_r_ticket_json

    ######################################################
    # [Func-level: 'R'TVEGT"S"] Message Communication
    ######################################################
    def _connect(self, comm_channel: FakeCommChannel) -> None:
        self.comm_channel = comm_channel
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is connecting with {end.this_device.device_name}..."
                )

    def _recv_xxx_message(self) -> str:
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is receiving message from {end.this_device.device_name}..."
                )
                # logging.debug(f"+ Message=\n{self.comm_channel.message_in_channel}")
        recveived_message_json = self.comm_channel.message_in_channel

        return recveived_message_json

    def _send_xxx_message(self, sent_message_json: str) -> None:
        self.comm_channel.message_in_channel = sent_message_json
        for end in self.comm_channel.ends:
            if end.this_device.device_name != self.this_device.device_name:
                logging.info(
                    f"+ {self.this_device.device_name} is sending message to {end.this_device.device_name}..."
                )
                # logging.debug(f"+ Message=\n{self.comm_channel.message_in_channel}")

    ######################################################
    # [Func-level: R'T'VEGTS] Message Storage (after Receiving)
    ######################################################
    def _store_recieved_xxx_u_ticket(self) -> str:
        ######################################################
        # Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        ######################################################
        recveived_u_ticket_json = self.comm_channel.message_in_channel
        recveived_u_ticket = jsonstr_to_u_ticket(recveived_u_ticket_json)

        # We store this UTicket in device_table["device_id"]
        # We do not forward Initialization UTicket
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

        return recveived_u_ticket.device_id

    def _store_recieved_xxx_r_ticket(self) -> str:
        ######################################################
        # Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        ######################################################
        recveived_r_ticket_json = self.comm_channel.message_in_channel
        recveived_r_ticket = jsonstr_to_r_ticket(recveived_r_ticket_json)

        # We store this RTicket (but not verified) in device_table["device_id"]
        if recveived_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            # Create new table by newly-created device public key
            created_device_id = recveived_r_ticket.device_id
            # Put u_ticket (temporary in device_table["no_id"]) & r_ticket in device_table["created_device_id"]
            self.device_table[created_device_id] = OtherDevice(
                device_id=created_device_id,
                device_name="device_id's name",
                device_u_ticket=self.device_table["no_id"].device_u_ticket,
                device_r_ticket=recveived_r_ticket_json,
            )
        else:
            # Not create new table, just add r_ticket to existing table
            self.device_table[
                recveived_r_ticket.device_id
            ].device_r_ticket = recveived_r_ticket_json

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return recveived_r_ticket.device_id

    ######################################################
    # [Func-level: RT'VE'GTS] Message Verification
    ######################################################
    def _verify_xxx_u_ticket(
        self, arbitrary_json: str
    ) -> Result[UTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is verifying u_ticket...")

        u_ticket_verifier = UTicketVerifier(self.this_device)
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

    def _verify_xxx_r_ticket(
        self,
        arbitrary_json: str,
        audit_start_ticket: UTicket,
        audit_end_ticket: str | UTicket,
    ) -> Result[RTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is verifying r_ticket...")

        r_ticket_verifier = RTicketVerifier(
            audit_start_ticket=audit_start_ticket,
            audit_end_ticket=audit_end_ticket,
        )
        verification_and_execution_result = flow(
            arbitrary_json,
            r_ticket_verifier.verify_json_schema,
            bind(r_ticket_verifier.verify_protocol_version),
            bind(r_ticket_verifier.verify_r_ticket_type),
            bind(r_ticket_verifier.verify_device_id),
            bind(r_ticket_verifier.verify_audit_start),
            bind(r_ticket_verifier.verify_audit_end),
            bind(r_ticket_verifier.verify_result),
            bind(r_ticket_verifier.verify_device_signature),
            bind(self._execute_verify_xxx_r_ticket),
        )
        return verification_and_execution_result

    ######################################################
    # [Func-level: RT'VE'GTS] Message Execution (after Verification)
    ######################################################
    def _execute_verify_xxx_u_ticket(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        failure_msg = f"-> FAILURE: WIRED UTICKET TYPE {u_ticket_in.u_ticket_type}"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            result = self._execute_one_time_initialize_iot_device(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_MANAGEMENT_UTICKET:
            self._execute_ownership_transfer(u_ticket_in)
            result = Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_PERMISSION_UTICKET:
            result = Success(u_ticket_in)
        else:  # pragma: no cover -> Never reach here: Because of verify_u_ticket_type()
            logging.error(failure_msg)
            result = Failure(RuntimeError(failure_msg))

        return result

    def _execute_one_time_set_time_device_type_and_name(
        self, device_type: str, device_name: str
    ) -> bool:
        ######################################################
        # Determine device type name, but still be uninitialized
        # Determine device name (for test)
        ######################################################
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
        if task_scope_dict[u_ticket.TASK_SCOPE_MANAGEMENT] == u_ticket.MANAGEMENT_OWNER:
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

    def _execute_verify_xxx_r_ticket(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        # if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:

        result = Success(r_ticket_in)
        return result

    ######################################################
    # [Func-level: RTVE'G'TS] Message Generation
    ######################################################
    def _generate_xxx_u_ticket(self, arbitrary_dict: dict) -> str:
        logging.info(f"+ {self.this_device.device_name} is generating u_ticket...")

        u_ticket_generator = UTicketGenerator(self.this_device, self.this_person)
        generated_u_ticket = flow(
            arbitrary_dict,
            u_ticket_generator.generate_arbitrary_u_ticket,
        )
        generated_u_ticket_json = u_ticket_to_jsonstr(generated_u_ticket)

        return generated_u_ticket_json

    def _generate_xxx_r_ticket(self, arbitrary_dict: dict) -> str:
        logging.info(f"+ {self.this_device.device_name} is generating r_ticket...")

        r_ticket_generator = RTicketGenerator(self.this_device, self.this_person)
        generated_r_ticket = flow(
            arbitrary_dict,
            r_ticket_generator.generate_arbitrary_r_ticket,
        )
        generated_r_ticket_json = r_ticket_to_jsonstr(generated_r_ticket)

        return generated_r_ticket_json

    ######################################################
    # [Func-level: RTVEG'T'S] Message Storage (after Generation)
    ######################################################
    def _stored_generated_xxx_u_ticket(self, generated_u_ticket_json: str) -> str:
        generated_u_ticket = jsonstr_to_u_ticket(generated_u_ticket_json)

        ######################################################
        # Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        ######################################################
        # Because device hasn't created the id yet,
        # we temporary store Initialization UTicket in device_table["no_id"]
        # and the device_table will be updated by its RTicket with newly-created device_id
        if generated_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            id_for_initialization_u_ticket = "no_id"
            self.device_table[id_for_initialization_u_ticket] = OtherDevice(
                device_id=id_for_initialization_u_ticket,
                device_name="device_id's name",
                device_u_ticket=generated_u_ticket_json,
            )
        # Else we store this UTicket in device_table["device_id"]
        else:
            self.device_table[generated_u_ticket.device_id] = OtherDevice(
                device_id=generated_u_ticket.device_id,
                device_name="device_id's name",
                device_u_ticket=generated_u_ticket_json,
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person
        )

        return generated_u_ticket_json
