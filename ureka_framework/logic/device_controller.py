import time
from queue import Queue
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
import ureka_framework.data_model.this_device as this_device
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.other_device import OtherDevice
from ureka_framework.data_model.this_person import ThisPerson
from ureka_framework.data_model.current_session import (
    CurrentSession,
    current_session_to_jsonstr,
)
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
import threading
import logging


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
        # Test Only Flag
        self.test_stop_flag = False

        # Data Model (Persistent)
        self.this_device: ThisDevice = ThisDevice()
        self.device_table: dict[str, OtherDevice] = {}
        self.current_session: CurrentSession = CurrentSession()
        # Data Model (Persistent: User Agent or Cloud Server only)
        self.this_person: ThisPerson = ThisPerson()

        # Data Model (RAM-only)
        self.state: str = None

        # Set Storage
        self.simple_storage: SimpleStorage = SimpleStorage(device_name=device_name)
        # Set Communication
        self.comm_channel: FakeCommChannel = FakeCommChannel()
        self.comm_channel.reciever_queue = Queue()

        # Always load Storage after Reboot
        (
            self.this_device,
            self.device_table,
            self.this_person,
            self.current_session,
        ) = self.simple_storage.load_storage()

        # Set Device Type (must after loading storage)
        if self.this_device.has_device_type is False:
            self._execute_one_time_set_time_device_type_and_name(
                device_type, device_name
            )

        logging.info(f"+ Here is a {self.this_device.device_name}...")

    ######################################################
    # Test Only Function
    #   Pytest finishes this test when main thread is finished
    #       (& all daemon threads, e.g. all receiver_threads will also be terminated)
    #   In production, we may need Ctrl+C or other shutdown method to stop this loop program
    ######################################################
    def wait_all_test_completed(self) -> None:
        while not self.test_stop_flag:
            time.sleep(0.01)
        logging.info(f"[TEST ONLY] {self.this_device.device_name}: all test completed")

    def complete_test_in_this_device(self) -> None:
        self.test_stop_flag = True

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
    # TODO: REQ: issuer_receive_request() <- holder_issue_request_to_issuer()
    # CST: issuer_issue_consent_to_holder() -> holder_receive_consent()
    #
    # TODO: More complete Tx (with DID, etc.))
    # TODO: Rollback (e.g., delete the temporary stored state and stored message) if fail
    ######################################################
    def issuer_issue_consent_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> str:
        # [FUNC-level: RTVE'GT'S]
        if device_id in self.device_table or device_id == "no_id":
            generated_u_ticket_json: str = self._generate_xxx_u_ticket(arbitrary_dict)
            # logging.debug(f"Generated UTicket: {generated_u_ticket_json}")
            self._stored_generated_xxx_u_ticket(generated_u_ticket_json)
            return generated_u_ticket_json
        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)
            return failure_msg

    def issuer_issue_consent_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> str:
        # [FUNC-level: RTVE'GTS']
        if device_id in self.device_table:
            generated_u_ticket_json: str = self._generate_xxx_u_ticket(arbitrary_dict)
            # logging.debug(f"Generated UTicket: {generated_u_ticket_json}")
            self._send_xxx_message(generated_u_ticket_json)
            self.state = this_device.STATE_WAIT_FOR_RT

            # End Test
            self.complete_test_in_this_device()

            return generated_u_ticket_json
        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)
            return failure_msg

    def _holder_receive_consent(self, received_u_ticket_json) -> str:
        # [FUNC-level: 'RT'VEGTS]
        # received_u_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received UTicket: {received_u_ticket_json}")
        self._store_recieved_xxx_u_ticket(received_u_ticket_json)
        # [FUNC-level: RT'VEGTS']
        # Can optionally _verify_xxx_u_ticket
        # Can optionally _generate_xxx_r_ticket & _send_xxx_message

        # End Test
        self.complete_test_in_this_device()

        return received_u_ticket_json

    ######################################################
    # [IO-level]
    #
    # APY (No CR):
    #       holder_access_device() -> device_be_accessed()
    #       holder_receive_r_ticket() <- device_send_r_ticket()
    #
    # TO-DO: Automatic UT-RT & UT-CR-KE-PS-RT
    #           Concurrent device_controller,
    #           i.e., FakeComm (Sequential Sender/Receiver) -> (Concurrent Sender/Receiver)
    ######################################################
    def holder_access_device(self, device_id: str) -> None:
        # [FUNC-level: RTVEGT'S']
        if device_id in self.device_table:
            stored_u_ticket_json: str = self.device_table[device_id].device_u_ticket
            stored_u_ticket: UTicket = jsonstr_to_u_ticket(stored_u_ticket_json)
            # logging.debug(f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}")
            # Also can add command in u_ticket
            self._send_xxx_message(stored_u_ticket_json)

            if (
                stored_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or stored_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                self.state = this_device.STATE_WAIT_FOR_RT
            elif stored_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                self.state = this_device.STATE_WAIT_FOR_CRKE1
                # Update session
                self._execute_update_current_session(stored_u_ticket, "holder")

        else:  # pragma: no cover -> IO-level
            failure_msg = f"FAILURE: YOU DO NOT OWN THIS DEVICE"
            logging.error(failure_msg)

    def _device_be_accessed(self, received_u_ticket_json: str) -> None:
        # [FUNC-level: 'RTVE'GTS]
        # received_u_ticket_json: str = self._recv_xxx_message()
        received_u_ticket = jsonstr_to_u_ticket(received_u_ticket_json)
        logging.debug(f"Received UTicket: {received_u_ticket_json}")
        # Can optionally _store_recieved_xxx_u_ticket
        result = self._verify_and_execute_xxx_u_ticket(received_u_ticket_json)

        # [FUNC-level: RTVE'GTS']
        if type(result) == Success:
            result_message = f"Success"
        elif type(result) == Failure:
            result_message = f"{result.failure().args[0]}"
        # CR-KE-PS
        if received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            self._device_send_cr_ke_1(received_u_ticket, result_message)
        # No CR
        else:
            self._device_send_r_ticket(received_u_ticket, result_message)

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
        # logging.debug(f"Generated RTicket: {generated_r_ticket_json}")

        # Can optionally _stored_generated_xxx_r_ticket

        self._send_xxx_message(generated_r_ticket_json)
        self.state = this_device.STATE_WAIT_FOR_UT

        # End Test
        self.complete_test_in_this_device()

    def _holder_receive_r_ticket(self, recieved_r_ticket_json) -> None:
        # [FUNC-level: 'RT'VEGTS]
        # recieved_r_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received RTicket: {recieved_r_ticket_json}")
        device_id = self._store_recieved_xxx_r_ticket(recieved_r_ticket_json)

        # [FUNC-level: RT'VE'GTS]
        if device_id in self.device_table:
            # Query Corresponding UTicket(s)
            # Notice that even Initialization UTicket is copied to the device_table["device_id"]
            logging.debug(
                f"Corresponding UTicket: {self.device_table[device_id].device_u_ticket}"
            )
            stored_u_ticket: UTicket = jsonstr_to_u_ticket(
                self.device_table[device_id].device_u_ticket
            )

            result = self._verify_and_execute_xxx_r_ticket(
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

        # End Test
        self.complete_test_in_this_device()

    ######################################################
    # [IO-level]
    #
    # APY (With CR-KE-PS):
    #       holder_access_device() -> device_be_accessed()
    #                     holder_recv_cr_ke_1() <- device_send_cr_ke_1()
    #                     holder_send_cr_ke_2() -> device_recv_cr_ke_2()
    #           device_recv_1st_data_r_ticket() <- device_send_1st_data_r_ticket()
    #                     holder_send_command() -> device_recv_command()
    #                        holder_recv_data() <- device_send_data()
    #                                           ...
    #       holder_receive_r_ticket() <- device_send_r_ticket()
    ######################################################
    def _device_send_cr_ke_1(
        self, received_u_ticket: UTicket, result_message: str
    ) -> None:
        # Generate CR-KE RTicket
        r_ticket_request: dict = {
            "r_ticket_type": f"{r_ticket.TYPE_CRKE1_RTICKET}",
            "device_id": f"{received_u_ticket.device_id}",
            "audit_start": f"{received_u_ticket.u_ticket_id}",
            "result": f"{result_message}",
            "challenge_1": f"{self.current_session.challenge_1}",
            "key_exchange_salt_1": f"{self.current_session.key_exchange_salt_1}",
        }
        generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
        # logging.debug(f"Generated RTicket: {generated_r_ticket_json}")

        # Can optionally _stored_generated_xxx_r_ticket

        self._send_xxx_message(generated_r_ticket_json)
        self.state = this_device.STATE_WAIT_FOR_CRKE2

        # TO-DO: End Test
        self.complete_test_in_this_device()

    def _holder_recv_cr_ke_1(self, recieved_r_ticket_json) -> None:
        self._holder_recv_cr_ke_r_tickets(recieved_r_ticket_json)

    def _holder_recv_cr_ke_r_tickets(self, recieved_r_ticket_json) -> None:
        # [FUNC-level: 'RT'VEGTS]
        # recieved_r_ticket_json: str = self._recv_xxx_message()
        logging.debug(f"Received CRKE-RTicket: {recieved_r_ticket_json}")
        # Can optionally _store_recieved_xxx_r_ticket

        # [FUNC-level: RT'VE'GTS]
        result = self._verify_and_execute_xxx_r_ticket(
            arbitrary_json=recieved_r_ticket_json,
            audit_start_ticket="",
            audit_end_ticket="",
        )

        if type(result) == Success:
            result_message = f"Success (meaningful R-Ticket)"
        elif type(result) == Failure:  # pragma: no cover -> Weird R-Ticket
            result_message = f"{result.failure().args[0]}"
        logging.debug(f"result_message = {result_message}")

        # End Test
        self.complete_test_in_this_device()

    ######################################################
    # [FUNC-level: 'R'TVEGT"S"] Message Communication
    ######################################################
    def _connect(self, end: "DeviceController") -> None:
        logging.info(
            f"+ {self.this_device.device_name} is connecting with {end.this_device.device_name}..."
        )
        # Set Sender (on Main Thread)
        self.comm_channel.end = end
        self.comm_channel.sender_queue = end.comm_channel.reciever_queue
        # Start Reciever Thread
        self._start_reciever()

    def _start_reciever(self) -> None:
        # Create a receiver thread
        receiver_thread = threading.Thread(target=self._recv_xxx_message, daemon=True)
        receiver_thread.start()

    def _recv_xxx_message(self) -> str:
        while True:
            # This will block until message is received
            recveived_message_json = self.comm_channel.reciever_queue.get()

            logging.info(
                f"+ {self.this_device.device_name} is receiving message from {self.comm_channel.end.this_device.device_name}..."
            )
            if self.this_device.device_type == this_device.IOT_DEVICE:
                if self.state == this_device.STATE_WAIT_FOR_UT:
                    self._device_be_accessed(recveived_message_json)
            if self.this_device.device_type == this_device.USER_AGENT_OR_CLOUD_SERVER:
                if self.state == this_device.STATE_WAIT_FOR_UT:
                    self._holder_receive_consent(recveived_message_json)
                elif self.state == this_device.STATE_WAIT_FOR_RT:
                    self._holder_receive_r_ticket(recveived_message_json)
                elif self.state == this_device.STATE_WAIT_FOR_CRKE1:
                    self._holder_recv_cr_ke_1(recveived_message_json)

    def _send_xxx_message(self, sent_message_json: str) -> None:
        logging.info(
            f"+ {self.this_device.device_name} is sending message to {self.comm_channel.end.this_device.device_name}..."
        )

        # Simulate Network Delay
        for i in range(10):
            logging.info(f"+ network delay")
        # time.sleep(3)

        self.comm_channel.sender_queue.put(sent_message_json)

    ######################################################
    # [FUNC-level: R'T'VEGTS] Message Storage (after Receiving)
    ######################################################
    def _store_recieved_xxx_u_ticket(self, received_u_ticket_json: str) -> str:
        ######################################################
        # Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        ######################################################
        recveived_u_ticket = jsonstr_to_u_ticket(received_u_ticket_json)

        # We store this UTicket in device_table["device_id"]
        # We do not forward Initialization UTicket
        if recveived_u_ticket.u_ticket_type != u_ticket.TYPE_INITIALIZATION_UTICKET:
            self.device_table[recveived_u_ticket.device_id] = OtherDevice(
                device_id=recveived_u_ticket.device_id,
                device_name="device_id's name",
                device_u_ticket=received_u_ticket_json,
            )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return recveived_u_ticket.device_id

    def _store_recieved_xxx_r_ticket(self, recveived_r_ticket_json: str) -> str:
        ######################################################
        # Update Device Table (Role, State, etc.)
        # RAM: Add Device & UTicket in Device Table
        ######################################################
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
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return recveived_r_ticket.device_id

    ######################################################
    # [FUNC-level: RT'VE'GTS] Message Verification
    ######################################################
    def _verify_and_execute_xxx_u_ticket(
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
            bind(self._execute_xxx_u_ticket),
        )
        return verification_and_execution_result

    def _verify_and_execute_xxx_r_ticket(
        self,
        arbitrary_json: str,
        audit_start_ticket: UTicket,
        audit_end_ticket: str | UTicket,
    ) -> Result[RTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is verifying r_ticket...")

        r_ticket_verifier = RTicketVerifier(
            audit_start_ticket=audit_start_ticket,
            audit_end_ticket=audit_end_ticket,
            current_session=self.current_session,
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
            bind(r_ticket_verifier.verify_cr_ke),
            bind(r_ticket_verifier.verify_ps),
            bind(r_ticket_verifier.verify_device_signature),
            bind(self._execute_xxx_r_ticket),
        )
        return verification_and_execution_result

    ######################################################
    # [FUNC-level: RT'VE'GTS] Message Execution (after Verification)
    ######################################################
    # Execute Initialization
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
        # State
        ######################################################
        if self.this_device.device_type == this_device.IOT_DEVICE:
            self.state = this_device.STATE_WAIT_FOR_UT
        elif self.this_device.device_type == this_device.USER_AGENT_OR_CLOUD_SERVER:
            self.state = this_device.STATE_WAIT_FOR_UT

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return Success(None)

    def _execute_one_time_intialize_agent_or_server(
        self,
    ) -> Result[None, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is initializing...")

        if self.this_device.device_type != this_device.USER_AGENT_OR_CLOUD_SERVER:
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
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return Success(None)

    # Execute UTicket
    def _execute_xxx_u_ticket(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        failure_msg = f"-> FAILURE: WIRED UTICKET TYPE {u_ticket_in.u_ticket_type}"

        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            result = self._execute_one_time_initialize_iot_device(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            self._execute_ownership_transfer(u_ticket_in)
            result = Success(u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            self._execute_update_current_session(u_ticket_in, "device")
            result = Success(u_ticket_in)
        else:  # pragma: no cover -> Never reach here: Because of verify_u_ticket_type()
            logging.error(failure_msg)
            result = Failure(RuntimeError(failure_msg))

        return result

    def _execute_one_time_initialize_iot_device(
        self, u_ticket_in: UTicket
    ) -> Result[UTicket, RuntimeError]:
        logging.info(f"+ {self.this_device.device_name} is intializing...")

        if self.this_device.device_type != this_device.IOT_DEVICE:
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
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return Success(u_ticket_in)

    def _execute_ownership_transfer(self, new_u_ticket: UTicket) -> None:
        logging.info(f"+ {self.this_device.device_name} is transferring ownership...")

        ######################################################
        # Update Device Owner
        ######################################################
        # RAM
        self.this_device.owner_pub_key = serialization_util.str_to_key(
            new_u_ticket.holder_id, key_type="ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    def _execute_update_current_session(
        self, ticket_in: UTicket, comm_end: str
    ) -> None:
        logging.info(f"+ {self.this_device.device_name} is updating current session...")

        ######################################################
        # Update Session
        ######################################################
        # RAM
        if ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            if comm_end == "holder":
                # Access Permission UT
                self.current_session.current_u_ticket_id = ticket_in.u_ticket_id
                self.current_session.current_device_id = ticket_in.device_id
                self.current_session.current_holder_id = ticket_in.holder_id
                self.current_session.current_task_scope = ticket_in.task_scope
            elif comm_end == "device":
                # Access Permission UT
                self.current_session.current_u_ticket_id = ticket_in.u_ticket_id
                self.current_session.current_device_id = ticket_in.device_id
                self.current_session.current_holder_id = ticket_in.holder_id
                self.current_session.current_task_scope = ticket_in.task_scope
                # CR-KE
                self.current_session.challenge_1 = serialization_util.byte_to_base64str(
                    ecdh.generate_random_byte(32)
                )
                self.current_session.key_exchange_salt_1 = (
                    serialization_util.byte_to_base64str(ecdh.generate_random_byte(32))
                )

        logging.debug(
            f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}"
        )

        ######################################################
        # Storage (Persistent vs. RAM-only)
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    # Execute RTicket
    def _execute_xxx_r_ticket(
        self, r_ticket_in: RTicket
    ) -> Result[RTicket, RuntimeError]:
        # if r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:

        result = Success(r_ticket_in)
        return result

    ######################################################
    # [FUNC-level: RTVE'G'TS] Message Generation
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
    # [FUNC-level: RTVEG'T'S] Message Storage (after Generation)
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
            self.this_device, self.device_table, self.this_person, self.current_session
        )

        return generated_u_ticket_json
