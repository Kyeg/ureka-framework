import time
from queue import Queue
import threading

from typing import Tuple

from ureka_framework.logic.r_ticket_generator import RTicketGenerator
from ureka_framework.logic.r_ticket_verifier import RTicketVerifier
from ureka_framework.logic.u_ticket_generator import UTicketGenerator
from ureka_framework.logic.u_ticket_verifier import UTicketVerifier

import ureka_framework.data_model.this_device as this_device
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.other_device import OtherDevice
from ureka_framework.data_model.this_person import ThisPerson
from ureka_framework.data_model.current_session import CurrentSession

import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.data_model.u_ticket import (
    UTicket,
    u_ticket_to_jsonstr,
)
import ureka_framework.data_model.r_ticket as r_ticket
from ureka_framework.data_model.r_ticket import (
    RTicket,
    r_ticket_to_jsonstr,
)

from ureka_framework.environment import Environment
from ureka_framework.resource.logger.simple_logger import simple_log
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel

import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    byte_to_base64str,
    str_to_key,
    str_to_byte,
    byte_backto_str,
)


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
        # [TEST ONLY]
        self.comm_done_flag = False

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
        self.comm_channel.receiver_queue = Queue()

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

        simple_log("info", f"+ Here is a {self.this_device.device_name}...")

    ######################################################
    # [TEST ONLY] Function
    #   Pytest finishes this test when main thread is finished
    #       (& all daemon threads, e.g. all receiver_threads will also be terminated)
    #   In production, we may need Ctrl+C or other shutdown method to stop this loop program
    ######################################################
    def wait_comm_completed(self) -> None:
        while not self.comm_done_flag:
            time.sleep(0.01)
        # simple_log("info",f"{self.this_device.device_name}: this communication is completed")

    def complete_comm(self) -> None:
        self.comm_done_flag = True

    ######################################################
    # Device Activity Cycle
    ######################################################
    def reboot_device(self) -> None:
        self.__init__(
            device_type=self.this_device.device_type,
            device_name=self.this_device.device_name,
        )

    ######################################################
    # [PIPELINE FLOW]
    #
    # CST: issuer_issue_u_ticket_to_herself()
    # TODO: REQ: _issuer_receive_request() <- holder_issue_request_to_issuer()
    # CST: issuer_issue_u_ticket_to_holder() -> _holder_recv_u_ticket()
    #
    # TODO: More complete Tx (with DID, etc.))
    # TODO: Rollback (e.g., delete the temporary stored state and stored message) if fail
    ######################################################
    def issuer_issue_u_ticket_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (V0)]
            if device_id in self.device_table or device_id == "no_id":
                # [STAGE: (G)]
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    arbitrary_dict
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                self._store_generated_xxx_u_ticket(generated_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def issuer_issue_u_ticket_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (V0)]
            if device_id in self.device_table:
                # [STAGE: (G)]
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    arbitrary_dict
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                # TODO: Issuer can moreover store this UTicket so that can receive and verify RTicket from holder
                # self._store_generated_xxx_u_ticket(generated_u_ticket_json)

                # [STAGE: (C)]
                self._change_state(this_device.STATE_WAIT_FOR_RT)
                # [STAGE: (S)]
                self._send_xxx_message(generated_u_ticket_json)

                # End Comm
                simple_log("debug", f"+ Finish UT-UT~~ (issuer)")
                self.complete_comm()

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_u_ticket(self, received_u_ticket_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log(
                "demo",
                f"Received (& to be Forwarded) UTicket: {received_u_ticket_json}",
            )

            # [TO-DO: STAGE: (V1)]
            received_u_ticket = self._classify_message_is_defined_type(
                received_u_ticket_json
            )

            # [STAGE: (V2)]
            # TODO: Can moreover _verify_xxx_u_ticket
            # (but the actual ticket order in device is still unknown -> TODO: Attack)

            # [TO-DO: STAGE: (SR)]
            self._store_received_xxx_u_ticket(received_u_ticket_json)

            # [STAGE: (O)]
            self._execute_update_ticket_order("receive", received_u_ticket)

            # [STAGE: (G)(C)(S)]
            # Can optionally _generate_xxx_r_ticket & _send_xxx_message

        except RuntimeError:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (No CR):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    #
    # Automatic UT-RT & UT-CR-KE-PS-RT
    #           Concurrent device_controller,
    #           i.e., FakeComm (Sequential Sender/Receiver) -> (Concurrent Sender/Receiver)
    ######################################################
    def holder_apply_u_ticket(self, device_id: str, cmd: str = "") -> None:
        try:
            # [STAGE: (V0)]
            stored_u_ticket_json: str = self.device_table[device_id].device_u_ticket
            # simple_log("debug",f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}")

            # [STAGE: (V1)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            if (
                stored_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or stored_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                # [STAGE: (C)]
                self._change_state(this_device.STATE_WAIT_FOR_RT)
            elif stored_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # [STAGE: (E)]
                self._execute_cr_ke(stored_u_ticket, "holder", cmd)
                # [STAGE: (C)]
                self._change_state(this_device.STATE_WAIT_FOR_CRKE1)
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

            # [STAGE: (S)]
            self._send_xxx_message(stored_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_u_ticket(self, received_u_ticket_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log("demo", f"Received UTicket: {received_u_ticket_json}")

            # [TO-DO: STAGE: (SR)]
            # No need to optionally _store_received_xxx_u_ticket

            # [STAGE: (V2)]
            received_u_ticket = self._verify_xxx_u_ticket(received_u_ticket_json)
            result_message = f"Success (verify_u_ticket_can_execute)"

            # [STAGE: (E)]
            self._execute_xxx_u_ticket(received_u_ticket)
            # After TX End
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                # [STAGE: (G)(C)(S)]
                self._device_send_r_ticket(
                    received_u_ticket.u_ticket_type,
                    received_u_ticket.u_ticket_id,
                    result_message,
                )
            # CR-KE-PS
            elif received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # [STAGE: (G)(C)(S)]
                self._device_send_cr_ke_1(result_message)
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V2)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_send_r_ticket(
        self, u_ticket_type: str, u_ticket_id: str, result_message: str
    ) -> None:
        try:
            # [STAGE: (G)]
            if (
                u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                r_ticket_request: dict = {
                    "r_ticket_type": f"{u_ticket_type}",
                    "device_id": f"{self.this_device.device_pub_key_str}",
                    "audit_start": f"{u_ticket_id}",
                    "result": f"{result_message}",
                }
            elif u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # audit_start has already stored when receiving Access UTicket
                r_ticket_request: dict = {
                    "r_ticket_type": f"{u_ticket_type}",
                    "device_id": f"{self.this_device.device_pub_key_str}",
                    "audit_start": f"{self.current_session.current_u_ticket_id}",
                    "audit_end": f"TX_END",
                    "result": f"{result_message}",
                }
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (SG)]
            # Can optionally _stored_generated_xxx_r_ticket

            # [STAGE: (C)]
            self._change_state(this_device.STATE_WAIT_FOR_UT)
            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_r_ticket(self, received_r_ticket_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log("demo", f"Received RTicket: {received_r_ticket_json}")

            # [STAGE: (V1)]
            # received_r_ticket = self._classify_message_is_defined_type(received_r_ticket_json)
            received_r_ticket = self._classify_message_is_defined_type(
                received_r_ticket_json
            )

            # [TO-DO: STAGE: (SR)]
            self._store_received_xxx_r_ticket(received_r_ticket_json)

            # Query Corresponding UTicket(s)
            #   Notice that even Initialization UTicket is copied in the device_table["device_id"]
            # [STAGE: (V0)]
            stored_u_ticket_json: str = self.device_table[
                received_r_ticket.device_id
            ].device_u_ticket
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (V1)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            if (
                received_r_ticket.audit_end == None
                or received_r_ticket.audit_end == "TX_END"
            ):
                try:
                    # [STAGE: (V3)]
                    received_r_ticket = self._verify_xxx_r_ticket(
                        arbitrary_json=received_r_ticket_json,
                        audit_start_ticket=stored_u_ticket,
                        audit_end_ticket=None,
                    )
                    result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                    # [STAGE: (E)]
                    self._execute_xxx_r_ticket(received_r_ticket)
                    # [STAGE: (C)]
                    self._change_state(this_device.STATE_WAIT_FOR_UT)
                except RuntimeError as error:  # pragma: no cover -> FAILURE: (V3)
                    result_message = f"{error}"

                simple_log("debug", f"result_message = {result_message}")

            else:  # pragma: no cover -> TODO: Auditted by Revocation UTicket
                failure_msg = f"Not implemented yet"
                simple_log("error", failure_msg)

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V1)
            if error == "NOT VALID JSON or VALID RTICKET SCHEMA":
                failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
                simple_log("error", failure_msg)
            elif error == "NOT VALID JSON or VALID UTICKET SCHEMA":
                failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
                simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (CR-KE):
    #       holder_apply_u_ticket() -> _device_recv_u_ticket()
    #       _holder_recv_cr_ke_1() <- _device_send_cr_ke_1()
    #       _holder_send_cr_ke_2() -> _device_recv_cr_ke_2()
    #       _holder_recv_cr_ke_3() <- _device_send_cr_ke_3()
    ######################################################
    def _device_send_cr_ke_1(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE1_RTICKET}",
                "device_id": f"{self.current_session.current_device_id}",
                "audit_start": f"{self.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.current_session.challenge_1}",
                "key_exchange_salt_1": f"{self.current_session.key_exchange_salt_1}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (C)]
            self._change_state(this_device.STATE_WAIT_FOR_CRKE2)
            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_1(self, received_r_ticket_json: str) -> None:
        self._recv_cr_ke_r_tickets(received_r_ticket_json)

    def _holder_send_cr_ke_2(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE2_RTICKET}",
                "device_id": f"{self.current_session.current_device_id}",
                "audit_start": f"{self.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.current_session.challenge_1}",
                "challenge_2": f"{self.current_session.challenge_2}",
                "key_exchange_salt_2": f"{self.current_session.key_exchange_salt_2}",
                "iv_cmd": f"{self.current_session.iv_cmd}",
                "associated_plaintext_cmd": f"{self.current_session.associated_plaintext_cmd}",
                "ciphertext_cmd": f"{self.current_session.ciphertext_cmd}",
                "gcm_authentication_tag_cmd": f"{self.current_session.gcm_authentication_tag_cmd}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (C)]
            self._change_state(this_device.STATE_WAIT_FOR_CRKE3)
            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cr_ke_2(self, received_r_ticket_json: str) -> None:
        self._recv_cr_ke_r_tickets(received_r_ticket_json)

    def _device_send_cr_ke_3(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE3_RTICKET}",
                "device_id": f"{self.current_session.current_device_id}",
                "audit_start": f"{self.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_2": f"{self.current_session.challenge_2}",
                "iv_data": f"{self.current_session.iv_data}",
                "associated_plaintext_data": f"{self.current_session.associated_plaintext_data}",
                "ciphertext_data": f"{self.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.current_session.gcm_authentication_tag_data}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (C)]
            self._change_state(this_device.STATE_WAIT_FOR_CMD)
            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_3(self, received_r_ticket_json: str) -> None:
        self._recv_cr_ke_r_tickets(received_r_ticket_json)

    def _recv_cr_ke_r_tickets(self, received_r_ticket_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log("demo", f"Received CRKE-RTicket: {received_r_ticket_json}")

            try:
                # [STAGE: (V3)]
                received_r_ticket = self._verify_xxx_r_ticket(
                    arbitrary_json=received_r_ticket_json,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                )
                result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                # [STAGE: (E)]
                self._execute_xxx_r_ticket(received_r_ticket)
                if received_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
                    # [STAGE: (G)(C)(S)]
                    self._holder_send_cr_ke_2(result_message)
                elif received_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
                    # [STAGE: (G)(C)(S)]
                    self._device_send_cr_ke_3(result_message)
                elif received_r_ticket.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
                    # [STAGE: (C)]
                    self._change_state(this_device.STATE_WAIT_FOR_UT)
                else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                    simple_log("error", "weird ticket type")
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (V3)
                result_message = f"{error}"

            simple_log("debug", f"result_message = {result_message}")

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [PIPELINE FLOW]
    #
    # APY (PS):
    #       holder_send_cmd()   -> _device_recv_cmd()
    #       _holder_recv_data() <- _device_send_data()
    #                           ...
    #                       ..repeated..
    #                           ...
    #       holder_send_cmd(tx_end) -> _device_recv_cmd(tx_end)
    #       _holder_recv_r_ticket() <- _device_send_r_ticket()
    ######################################################
    def holder_send_cmd(self, device_id: str, cmd: str, tx_end: bool = False) -> None:
        try:
            # [STAGE: (V0)]
            if device_id in self.device_table:
                # [STAGE: (E)]
                # Update Session: PS
                self.current_session.plaintext_cmd = cmd
                self.current_session.associated_plaintext_cmd = (
                    "additional unencrypted cmd"
                )
                # Message Encryption (str + key byte)
                self._execute_cmd_encryption(
                    base64str_backto_byte(self.current_session.current_session_key_str)
                )

                # [STAGE: (G)]
                if tx_end == False:
                    u_ticket_type = f"{u_ticket.TYPE_CMD_UTOKEN}"
                else:
                    u_ticket_type = f"{u_ticket.TYPE_TX_END_UTOKEN}"
                generated_request: dict = {
                    "device_id": f"{self.current_session.current_device_id}",
                    "u_ticket_type": f"{u_ticket_type}",
                    "associated_plaintext": f"{self.current_session.associated_plaintext_cmd}",
                    "iv": f"{self.current_session.iv_cmd}",
                    "ciphertext": f"{self.current_session.ciphertext_cmd}",
                    "gcm_authentication_tag": f"{self.current_session.gcm_authentication_tag_cmd}",
                }
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    generated_request
                )
                # simple_log("debug", f"Generated UToken: {generated_u_ticket_json}")

                # [STAGE: (C)]
                if tx_end == False:
                    self._change_state(this_device.STATE_WAIT_FOR_DATA)
                else:
                    self._change_state(this_device.STATE_WAIT_FOR_RT)
                # [STAGE: (S)]
                self._send_xxx_message(generated_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cmd(self, received_u_token_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log("demo", f"Received UToken: {received_u_token_json}")

            # [STAGE: (V2)]
            received_u_token = self._verify_xxx_u_ticket(received_u_token_json)
            result_message = f"Success (verify_u_ticket_can_execute)"

            # [STAGE: (E)]
            self._execute_xxx_u_ticket(received_u_token)
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (G)(C)(S)]
                self._device_send_data(result_message)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # [STAGE: (G)(C)(S)]
                self._device_send_r_ticket(
                    received_u_token.u_ticket_type,
                    received_u_token.u_ticket_id,
                    result_message,
                )
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V2)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_send_data(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            generated_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_DATA_RTOKEN}",
                "device_id": f"{self.this_device.device_pub_key_str}",
                "audit_start": f"{self.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "associated_plaintext_data": f"{self.current_session.associated_plaintext_data}",
                "iv_data": f"{self.current_session.iv_data}",
                "ciphertext_data": f"{self.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.current_session.gcm_authentication_tag_data}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(
                generated_request
            )
            # simple_log("debug", f"Generated RToken: {generated_r_ticket_json}")

            # [STAGE: (C)]
            self._change_state(this_device.STATE_WAIT_FOR_CMD)
            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_data(self, received_r_token_json: str) -> None:
        try:
            # [STAGE: (R)]
            simple_log("demo", f"Received RToken: {received_r_token_json}")

            # [STAGE: (V1)]
            device_id = self._classify_message_is_defined_type(
                received_r_token_json
            ).device_id

            # Query Corresponding UTicket
            # [STAGE: (V0)]
            stored_u_ticket_json = self.device_table[device_id].device_u_ticket
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (V1)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            try:
                # [STAGE: (V3)]
                received_r_ticket = self._verify_xxx_r_ticket(
                    arbitrary_json=received_r_token_json,
                    audit_start_ticket=stored_u_ticket,
                    audit_end_ticket=None,
                )
                result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                # [STAGE: (E)]
                self._execute_xxx_r_ticket(received_r_ticket)
                # [STAGE: (C)]
                self._change_state(this_device.STATE_WAIT_FOR_CMD)
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (V3)
                result_message = f"{error}"

            simple_log("debug", f"result_message = {result_message}")

        except KeyError:  # pragma: no cover -> FAILURE: (V0)
            failure_msg = f"FAILURE: (V0): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V1)
            if error == "NOT VALID JSON or VALID RTICKET SCHEMA":
                failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
                simple_log("error", failure_msg)
            elif error == "NOT VALID JSON or VALID UTICKET SCHEMA":
                failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
                simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (R)] Receive Message
    ######################################################
    def _connect(self, end: "DeviceController") -> None:
        # simple_log("info",
        #     f"+ {self.this_device.device_name} is connecting with {end.this_device.device_name}..."
        # )
        # Set Sender (on Main Thread)
        self.comm_channel.end = end
        self.comm_channel.sender_queue = end.comm_channel.receiver_queue
        # Start Reciever Thread
        self._start_receiver()

    def _start_receiver(self) -> None:
        # Create a receiver thread
        receiver_thread = threading.Thread(target=self._recv_xxx_message, daemon=True)
        receiver_thread.start()

    def _recv_xxx_message(self) -> str:
        while True:
            # This will block until message is received
            received_message_json = self.comm_channel.receiver_queue.get()

            simple_log(
                "info",
                f"+ {self.this_device.device_name} is receiving message from {self.comm_channel.end.this_device.device_name}...",
            )
            if self.this_device.device_type == this_device.IOT_DEVICE:
                if self.state == this_device.STATE_WAIT_FOR_UT:
                    self._device_recv_u_ticket(received_message_json)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.complete_comm()
                elif self.state == this_device.STATE_WAIT_FOR_CRKE2:
                    self._device_recv_cr_ke_2(received_message_json)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.this_device.device_name} = {self.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (device)")
                    self.complete_comm()
                elif self.state == this_device.STATE_WAIT_FOR_CMD:
                    self._device_recv_cmd(received_message_json)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.this_device.device_name} = {self.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (device)")
                    self.complete_comm()
            elif self.this_device.device_type == this_device.USER_AGENT_OR_CLOUD_SERVER:
                if self.state == this_device.STATE_WAIT_FOR_UT:
                    self._holder_recv_u_ticket(received_message_json)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                    self.complete_comm()
                elif self.state == this_device.STATE_WAIT_FOR_RT:
                    self._holder_recv_r_ticket(received_message_json)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.complete_comm()
                elif self.state == this_device.STATE_WAIT_FOR_CRKE1:
                    self._holder_recv_cr_ke_1(received_message_json)
                elif self.state == this_device.STATE_WAIT_FOR_CRKE3:
                    self._holder_recv_cr_ke_3(received_message_json)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.this_device.device_name} = {self.current_session.plaintext_data}",
                    )
                    simple_log(
                        "demo",
                        f"\n+++Session is Constucted+++",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (holder)")
                    self.complete_comm()
                elif self.state == this_device.STATE_WAIT_FOR_DATA:
                    self._holder_recv_data(received_message_json)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.this_device.device_name} = {self.current_session.plaintext_data}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (holder)")
                    self.complete_comm()
            else:  # pragma: no cover -> Weird Device Type
                simple_log("error", "weird device type")

    ######################################################
    # [STAGE: (V)] Verify Message & Execute
    #   (V0): has_u_ticket_in_device_table
    #   (V1): classify_message_is_defined_type
    #   (V2): verify_u_ticket_can_execute
    #   (V3): verify_u_ticket_has_successfully_executed_through_r_ticket
    #   (V4): verify_u_token_with_hmac
    #   (V5): verify_cmd_is_in_task_scope
    ######################################################
    def _classify_message_is_defined_type(
        self, arbitrary_json: str
    ) -> UTicket | RTicket:
        simple_log(
            "info", f"+ {self.this_device.device_name} is classifying message..."
        )

        # Notice that Pydantic can classify message type by json schema,
        #   while other implementation may need classify message type by message_type field
        try:
            # [STAGE: (V1: UTicket)]
            u_ticket_verifier = UTicketVerifier(this_device=None)

            u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.has_device_id(u_ticket_in)

            return u_ticket_in
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V1)
            try:
                # [STAGE: (V1: RTicket)]
                r_ticket_verifier = RTicketVerifier(
                    this_device=None,
                    device_table=None,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                    current_session=None,
                )

                r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
                r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
                r_ticket_in = r_ticket_verifier.has_device_id(r_ticket_in)

                return r_ticket_in
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (V1)
                # "NOT VALID JSON or VALID UTICKET/RTICKET SCHEMA"
                failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA"
                simple_log("error", f"{failure_msg}: {error}")
                raise RuntimeError(error)
            except:  # pragma: no cover -> Unpredicted Error
                failure_msg = f"FAILURE: UNPREDICTED ERROR"
                simple_log("error", failure_msg)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _verify_xxx_u_ticket(self, arbitrary_json: str) -> UTicket:
        simple_log("info", f"+ {self.this_device.device_name} is verifying u_ticket...")

        try:
            u_ticket_verifier = UTicketVerifier(this_device=self.this_device)

            u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_device_id(u_ticket_in)

            u_ticket_in = u_ticket_verifier.verify_ticket_order(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_holder_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_task_scope(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_ps(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_issuer_signature(u_ticket_in)

            return u_ticket_in
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V2)
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _verify_xxx_r_ticket(
        self,
        arbitrary_json: str,
        audit_start_ticket: None | UTicket,
        audit_end_ticket: None | UTicket,
    ) -> RTicket:
        simple_log("info", f"+ {self.this_device.device_name} is verifying r_ticket...")

        try:
            r_ticket_verifier = RTicketVerifier(
                this_device=self.this_device,
                device_table=self.device_table,
                audit_start_ticket=audit_start_ticket,
                audit_end_ticket=audit_end_ticket,
                current_session=self.current_session,
            )

            r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
            r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_id(r_ticket_in)

            r_ticket_in = r_ticket_verifier.verify_ticket_order(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_start(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_end(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_result(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_cr_ke(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_ps(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_signature(r_ticket_in)

            return r_ticket_in
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (V3)
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (E)] Execute
    ######################################################
    # Execute Initialization (Update Keystore)
    def _execute_one_time_set_time_device_type_and_name(
        self, device_type: str, device_name: str
    ) -> bool:
        ######################################################
        # Determine device type name, but still be uninitialized
        # Determine device name (for test)
        ######################################################
        self.this_device.device_type = device_type
        self.this_device.device_name = device_name
        self.this_device.has_device_type = True

        ######################################################
        # Initial Order
        ######################################################
        # [STAGE: (O)]
        self.this_device.ticket_order = 0
        self.this_device.is_initialized = False

        ######################################################
        # Initial State
        ######################################################
        # [STAGE: (C)]
        if self.this_device.device_type == this_device.IOT_DEVICE:
            self._change_state(this_device.STATE_WAIT_FOR_UT)
        elif self.this_device.device_type == this_device.USER_AGENT_OR_CLOUD_SERVER:
            self._change_state(this_device.STATE_WAIT_FOR_UT)

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    def _execute_one_time_intialize_agent_or_server(self) -> None:
        simple_log("info", f"+ {self.this_device.device_name} is initializing...")

        ######################################################
        # TODO: New way for _execute_one_time_intialize_agent_or_server()
        #         + DM: Apply Initialization Ticket
        #         + DM: Apply Personal Key Gen Ticket
        #         + DO: Generate Personal Key
        #         + DO: Request Ownership Ticket from DM
        ######################################################

        if (
            self.this_device.device_type != this_device.USER_AGENT_OR_CLOUD_SERVER
        ):  # pragma: no cover -> weird operation
            failure_msg = "FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        if (
            self.this_device.ticket_order != 0
        ):  # pragma: no cover -> FAILURE: (V1), because of verify_ticket_order()
            failure_msg = "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        if self.this_device.is_initialized:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

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

        # [STAGE: (O)]
        self.this_device.ticket_order = self.this_device.ticket_order + 1
        simple_log(
            "debug",
            f"{self.this_device.device_name}: ticket_order={self.this_device.ticket_order}",
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    # Execute UTicket (Update Keystore)
    def _execute_xxx_u_ticket(self, u_ticket_in: UTicket) -> None:
        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            try:
                # [STAGE: (E)]
                self._execute_one_time_initialize_iot_device(u_ticket_in)
                # [STAGE: (O)]
                self._execute_update_ticket_order("verify", u_ticket_in)
            except RuntimeError as error:  # pragma: no cover -> werid operation
                simple_log("error", f"{error}")
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            # [STAGE: (E)]
            self._execute_ownership_transfer(u_ticket_in)
            # [STAGE: (O)]
            self._execute_update_ticket_order("verify", u_ticket_in)
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(u_ticket_in, "device")
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            # [STAGE: (E)]
            # Message Decryption (str + key byte)
            self._execute_cmd_decryption(
                associated_plaintext=u_ticket_in.associated_plaintext,
                iv=u_ticket_in.iv,
                ciphertext=u_ticket_in.ciphertext,
                gcm_authentication_tag=u_ticket_in.gcm_authentication_tag,
                session_key=base64str_backto_byte(
                    self.current_session.current_session_key_str
                ),
            )
            # Message Encryption (str + key byte)
            self._execute_data_processing_and_encryption(
                base64str_backto_byte(self.current_session.current_session_key_str)
            )
            if u_ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # [STAGE: (V4)]
                if self.current_session.plaintext_cmd == "TX_END":
                    simple_log("info", f"-> SUCCESS: VERIFY_TX_END")
                    # [STAGE: (O)]
                    self._execute_update_ticket_order("verify", u_ticket_in)
                else:  # pragma: no cover -> FAILURE: (V4)
                    simple_log("error", f"-> FAILURE: VERIFY_TX_END")
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
            simple_log("error", "weird ticket type")

    def _execute_one_time_initialize_iot_device(self, u_ticket_in: UTicket) -> None:
        simple_log("info", f"+ {self.this_device.device_name} is intializing...")

        if (
            self.this_device.device_type != this_device.IOT_DEVICE
        ):  # pragma: no cover -> Never reach here: weird operation
            failure_msg = (
                "FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION"
            )
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        if (
            self.this_device.is_initialized
        ):  # pragma: no cover -> Never reach here: FAILURE: (V1), because of verify_ticket_order()
            failure_msg = "FAILURE: IOT_DEVICE ALREADY INITIALIZED"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

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
        self.this_device.owner_pub_key = str_to_key(
            u_ticket_in.holder_id, "ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    def _execute_ownership_transfer(self, new_u_ticket: UTicket) -> None:
        simple_log(
            "info", f"+ {self.this_device.device_name} is transferring ownership..."
        )

        ######################################################
        # Update Device Owner
        ######################################################
        # RAM
        self.this_device.owner_pub_key = str_to_key(
            new_u_ticket.holder_id, key_type="ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device, self.device_table, self.this_person, self.current_session
        )

    # Execute UTicket (Update Session)
    def _execute_cr_ke(
        self, ticket_in: UTicket | RTicket, comm_end: str, cmd: str = ""
    ) -> None:
        simple_log(
            "info", f"+ {self.this_device.device_name} is updating current session..."
        )
        ######################################################
        # Update Session
        ######################################################
        # RAM
        if (
            type(ticket_in) == UTicket
            and ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ):
            if comm_end == "holder":
                # Update Session: Access UT
                self.current_session.current_u_ticket_id = ticket_in.u_ticket_id
                self.current_session.current_device_id = ticket_in.device_id
                self.current_session.current_holder_id = ticket_in.holder_id
                self.current_session.current_task_scope = ticket_in.task_scope
                # Update Session: PS
                self.current_session.plaintext_cmd = cmd
                self.current_session.associated_plaintext_cmd = (
                    "additional unencrypted cmd"
                )
            elif comm_end == "device":
                # Update Session: Access UT
                self.current_session.current_u_ticket_id = ticket_in.u_ticket_id
                self.current_session.current_device_id = ticket_in.device_id
                self.current_session.current_holder_id = ticket_in.holder_id
                self.current_session.current_task_scope = ticket_in.task_scope
                # Update Session: CR-KE
                self.current_session.challenge_1 = ecdh.generate_random_str(32)
                self.current_session.key_exchange_salt_1 = ecdh.generate_random_str(32)
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "weird comm_end")
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
        ):
            # Update Session: CR-KE
            self.current_session.challenge_1 = ticket_in.challenge_1
            self.current_session.key_exchange_salt_1 = ticket_in.key_exchange_salt_1
            self.current_session.challenge_2 = ecdh.generate_random_str(32)
            self.current_session.key_exchange_salt_2 = ecdh.generate_random_str(32)
            # Session Key Gereration ("holder")
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.current_session.key_exchange_salt_1,
                salt_2=self.current_session.key_exchange_salt_2,
                server_priv_key=self.this_person.person_priv_key,
                peer_pub_key=str_to_key(
                    self.current_session.current_device_id, "ecc-public-key"
                ),
            )
            # Message Encryption (str + key byte)
            self._execute_cmd_encryption(current_session_key_byte)
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET
        ):
            # Update Session: CR-KE
            self.current_session.challenge_2 = ticket_in.challenge_2
            self.current_session.key_exchange_salt_2 = ticket_in.key_exchange_salt_2
            # Session Key Gereration ("device")
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.current_session.key_exchange_salt_1,
                salt_2=ticket_in.key_exchange_salt_2,
                server_priv_key=self.this_device.device_priv_key,
                peer_pub_key=str_to_key(
                    self.current_session.current_holder_id, "ecc-public-key"
                ),
            )
            self.current_session.current_session_key_str = byte_to_base64str(
                current_session_key_byte
            )
            # Message Decryption (str + key byte)
            self._execute_cmd_decryption(
                associated_plaintext=ticket_in.associated_plaintext_cmd,
                iv=ticket_in.iv_cmd,
                ciphertext=ticket_in.ciphertext_cmd,
                gcm_authentication_tag=ticket_in.gcm_authentication_tag_cmd,
                session_key=current_session_key_byte,
            )
            # Message Encryption (str + key byte)
            self._execute_data_processing_and_encryption(current_session_key_byte)
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
        ):
            # Session Key Obtaining ("holder")
            current_session_key_byte = base64str_backto_byte(
                self.current_session.current_session_key_str
            )
            # Message Decryption (str + key byte)
            self._execute_data_decryption(
                associated_plaintext=ticket_in.associated_plaintext_data,
                iv=ticket_in.iv_data,
                ciphertext=ticket_in.ciphertext_data,
                gcm_authentication_tag=ticket_in.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
            )
        else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
            simple_log("error", "weird ticket type")

        # simple_log(
        #     "debug",
        #     f"current_session_json in {self.this_device.device_name} = {current_session_to_jsonstr(self.current_session)}",
        # )

        ######################################################
        # Storage (Persistent vs. RAM-only)
        ######################################################
        # self.simple_storage.store_storage(
        #     self.this_device, self.device_table, self.this_person, self.current_session
        # )

    def _execute_generate_session_key(
        self,
        salt_1: str,
        salt_2: str,
        server_priv_key: ec.EllipticCurvePrivateKey,
        peer_pub_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        salt_1_byte = base64str_backto_byte(salt_1)
        salt_2_byte = base64str_backto_byte(salt_2)
        # # Bitweise AND operation (python operates bit through int, & bytes is int arrary)
        # type(salt_1[0])  # = int
        # salt_1_bit = "".join(format(byte, "08b") for byte in salt_1)
        # simple_log("debug", f"salt_1_bit = {salt_1_bit}")
        # salt_2_bit = "".join(format(byte, "08b") for byte in salt_2)
        # simple_log("debug", f"salt_2_bit = {salt_2_bit}")
        # shared_salt_bit = "".join(format(byte, "08b") for byte in shared_salt)
        # simple_log("debug", f"share_salt = {shared_salt_bit}")
        # simple_log("debug", f"share_salt length (byte) = {len(shared_salt_bit)}")
        shared_salt_byte = bytes(
            [salt_1_byte[i] & salt_2_byte[i] for i in range(len(salt_1_byte))]
        )
        # len(shared_salt)  # = 32 bytes
        current_session_key: bytes = ecdh.generate_ecdh_key(
            server_private_key=server_priv_key,
            salt=shared_salt_byte,
            info=None,
            peer_public_key=peer_pub_key,
        )
        # len(current_session_key)  # = 32 bytes
        return current_session_key

    def _execute_cmd_encryption(self, current_session_key_byte: bytes) -> None:
        # Message Encryption
        plaintext_cmd = self.current_session.plaintext_cmd
        associated_plaintext = self.current_session.associated_plaintext_cmd
        (ciphertext, gcm_authentication_tag, iv) = self._execute_encrypt_plaintext(
            plaintext=plaintext_cmd,
            associated_plaintext=associated_plaintext,
            session_key=current_session_key_byte,
        )
        # Update Session: PS
        self.current_session.current_session_key_str = byte_to_base64str(
            current_session_key_byte
        )
        self.current_session.iv_cmd = iv
        self.current_session.ciphertext_cmd = ciphertext
        self.current_session.gcm_authentication_tag_cmd = gcm_authentication_tag

    def _execute_cmd_decryption(
        self,
        associated_plaintext: str,
        iv: str,
        ciphertext: str,
        gcm_authentication_tag: str,
        session_key: bytes,
    ) -> None:
        # Message Decryption
        plaintext_cmd = self._execute_decrypt_ciphertext(
            associated_plaintext=associated_plaintext,
            iv=iv,
            ciphertext=ciphertext,
            gcm_authentication_tag=gcm_authentication_tag,
            session_key=session_key,
        )
        # Update Session: PS
        self.current_session.plaintext_cmd = plaintext_cmd
        self.current_session.associated_plaintext_cmd = associated_plaintext
        self.current_session.iv_cmd = iv
        self.current_session.ciphertext_cmd = ciphertext
        self.current_session.gcm_authentication_tag_cmd = gcm_authentication_tag

    def _execute_data_processing_and_encryption(
        self, current_session_key_byte: bytes
    ) -> None:
        # Data Processing
        (plaintext_data, associated_plaintext) = self._execute_data_processing(
            self.current_session.plaintext_cmd,
            self.current_session.associated_plaintext_cmd,
        )
        # Message Encryption
        (ciphertext, gcm_authentication_tag, iv) = self._execute_encrypt_plaintext(
            plaintext=plaintext_data,
            associated_plaintext=associated_plaintext,
            session_key=current_session_key_byte,
        )
        # Update Session: PS
        self.current_session.plaintext_data = plaintext_data
        self.current_session.associated_plaintext_data = associated_plaintext
        self.current_session.iv_data = iv
        self.current_session.ciphertext_data = ciphertext
        self.current_session.gcm_authentication_tag_data = gcm_authentication_tag

    def _execute_data_decryption(
        self,
        associated_plaintext: str,
        iv: str,
        ciphertext: str,
        gcm_authentication_tag: str,
        session_key: bytes,
    ) -> None:
        # Message Decryption
        plaintext_data = self._execute_decrypt_ciphertext(
            associated_plaintext=associated_plaintext,
            iv=iv,
            ciphertext=ciphertext,
            gcm_authentication_tag=gcm_authentication_tag,
            session_key=session_key,
        )
        # Update Session: PS
        self.current_session.plaintext_data = plaintext_data
        self.current_session.associated_plaintext_data = associated_plaintext
        self.current_session.iv_data = iv
        self.current_session.ciphertext_data = ciphertext
        self.current_session.gcm_authentication_tag_data = gcm_authentication_tag

    def _execute_encrypt_plaintext(
        self, plaintext: str, associated_plaintext: str, session_key: bytes
    ) -> Tuple[str, str, str]:
        plaintext_byte: bytes = str_to_byte(plaintext)
        associated_plaintext_byte: bytes = str_to_byte(associated_plaintext)
        (ciphertext_byte, gcm_authentication_tag_byte, iv_byte) = ecdh.gcm_encrypt(
            plaintext_byte, associated_plaintext_byte, session_key
        )
        ciphertext = byte_to_base64str(ciphertext_byte)
        gcm_authentication_tag = byte_to_base64str(gcm_authentication_tag_byte)
        iv = byte_to_base64str(iv_byte)

        return (ciphertext, gcm_authentication_tag, iv)

    def _execute_decrypt_ciphertext(
        self,
        associated_plaintext: str,
        iv: str,
        ciphertext: str,
        gcm_authentication_tag: str,
        session_key: bytes,
    ) -> str:
        # [STAGE: (V4)]
        try:
            ciphertext_byte: bytes = base64str_backto_byte(ciphertext)
            associated_plaintext_byte: bytes = str_to_byte(associated_plaintext)
            gcm_authentication_tag_byte: bytes = base64str_backto_byte(
                gcm_authentication_tag
            )
            iv_byte: bytes = base64str_backto_byte(iv)

            plaintext_byte: bytes = ecdh.gcm_decrypt(
                ciphertext_byte,
                associated_plaintext_byte,
                gcm_authentication_tag_byte,
                session_key,
                iv_byte,
            )

            plaintext: str = byte_backto_str(plaintext_byte)

            simple_log("info", "-> SUCCESS: verify_u_token_with_hmac")

        except InvalidTag:  # pragma: no cover -> TODO: Attack
            simple_log("info", "-> FAILURE: verify_u_token_with_hmac")

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        return plaintext

    # Execute RTicket (Update Session)
    def _execute_xxx_r_ticket(self, r_ticket_in: RTicket) -> None:
        if (
            r_ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            or r_ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            # [STAGE: (O)]
            self._execute_update_ticket_order("verify", r_ticket_in)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "holder")
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "device")
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "holder")
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            # [STAGE: (E)]
            # Session Key Obtaining ("holder")
            current_session_key_byte = base64str_backto_byte(
                self.current_session.current_session_key_str
            )
            # Message Decryption (str + key byte)
            self._execute_data_decryption(
                associated_plaintext=r_ticket_in.associated_plaintext_data,
                iv=r_ticket_in.iv_data,
                ciphertext=r_ticket_in.ciphertext_data,
                gcm_authentication_tag=r_ticket_in.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
            )
            # [STAGE: (O)] (Update Ticket Order when TXEnd)
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", "weird ticket type")

    # [STAGE: (V5)] TODO: Verify Task Scope before Execution
    # Execute Application & Data Processing
    def _execute_data_processing(
        self, plaintext_cmd: str, associated_plaintext_cmd: str
    ) -> Tuple[str, str]:
        plaintext_cmd = f"Data: {plaintext_cmd}"
        associated_plaintext_cmd = f"Data: {associated_plaintext_cmd}"
        return (plaintext_cmd, associated_plaintext_cmd)

    ######################################################
    # [STAGE: (SR)] Store Received Message
    ######################################################
    def _store_received_xxx_u_ticket(self, received_u_ticket_json: str) -> None:
        try:
            # [STAGE: (V1)]
            received_u_ticket = self._classify_message_is_defined_type(
                received_u_ticket_json
            )

            # [STAGE: (SR)]
            # We store this UTicket in device_table["device_id"]
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            ):
                self.device_table[received_u_ticket.device_id] = OtherDevice(
                    device_id=received_u_ticket.device_id,
                    device_u_ticket=received_u_ticket_json,
                )
            # Normally, we do not forward Initialization UTicket
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

            ######################################################
            # Storage
            ######################################################
            self.simple_storage.store_storage(
                self.this_device,
                self.device_table,
                self.this_person,
                self.current_session,
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _store_received_xxx_r_ticket(self, received_r_ticket_json: str) -> None:
        try:
            # [STAGE: (V1)]
            received_r_ticket = self._classify_message_is_defined_type(
                received_r_ticket_json
            )

            # We store this RTicket (but not verified) in device_table["device_id"]
            if received_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                # Create new table by newly-created device public key
                created_device_id = received_r_ticket.device_id
                # Put u_ticket (temporary in device_table["no_id"]) & r_ticket in device_table["created_device_id"]
                self.device_table[created_device_id] = OtherDevice(
                    device_id=created_device_id,
                    device_u_ticket=self.device_table["no_id"].device_u_ticket,
                    device_r_ticket=received_r_ticket_json,
                )
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                # Not create new table, just add r_ticket to existing table
                self.device_table[
                    received_r_ticket.device_id
                ].device_r_ticket = received_r_ticket_json
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # Not create new table, just add r_ticket to existing table
                self.device_table[
                    received_r_ticket.device_id
                ].device_r_ticket = received_r_ticket_json
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

            ######################################################
            # Storage
            ######################################################
            self.simple_storage.store_storage(
                self.this_device,
                self.device_table,
                self.this_person,
                self.current_session,
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (O)] Update Ticket Order
    #   Update Ticket Order after:
    #       "holder": Receive UTicket (expected ticket order)
    #       "device": Verify UTicket & End TX (actual ticket order)
    #       "holder": Verify RTicket (actual ticket order)
    ######################################################
    def _execute_update_ticket_order(
        self, updating_case: str, ticket_in: UTicket | RTicket
    ) -> None:
        simple_log(
            "info", f"+ {self.this_device.device_name} is updating ticket order..."
        )

        if updating_case == "receive":
            # Recieve UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            ):
                self.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.this_device.device_name}: ticket_order={self.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "Other ticket types should not update ticket_order")
        elif updating_case == "verify":
            # Execute UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                self.this_device.ticket_order = self.this_device.ticket_order + 1
                simple_log(
                    "debug",
                    f"{self.this_device.device_name}: ticket_order={self.this_device.ticket_order}",
                )
            # Execute UTicket
            elif type(ticket_in) == RTicket and (
                ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                self.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.this_device.device_name}: ticket_order={self.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "Other ticket types should not update ticket_order")
        else:  # pragma: no cover -> Never reach here: Because of verify_updating_case()
            simple_log("error", "weird updating_case")

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.this_device,
            self.device_table,
            self.this_person,
            self.current_session,
        )

    ######################################################
    # [STAGE: (G)] Generate Message
    ######################################################
    def _generate_xxx_u_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info", f"+ {self.this_device.device_name} is generating u_ticket..."
        )

        u_ticket_generator = UTicketGenerator(
            self.this_device, self.this_person, self.device_table
        )
        generated_u_ticket = u_ticket_generator.generate_arbitrary_u_ticket(
            arbitrary_dict
        )
        generated_u_ticket_json = u_ticket_to_jsonstr(generated_u_ticket)

        return generated_u_ticket_json

    def _generate_xxx_r_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info", f"+ {self.this_device.device_name} is generating r_ticket..."
        )

        r_ticket_generator = RTicketGenerator(
            self.this_device, self.this_person, self.device_table
        )
        generated_r_ticket = r_ticket_generator.generate_arbitrary_r_ticket(
            arbitrary_dict
        )
        generated_r_ticket_json = r_ticket_to_jsonstr(generated_r_ticket)

        return generated_r_ticket_json

    ######################################################
    # [STAGE: (SG)] Store Generated Message
    ######################################################
    def _store_generated_xxx_u_ticket(self, generated_u_ticket_json: str) -> None:
        try:
            # [STAGE: (V1)]
            generated_u_ticket = self._classify_message_is_defined_type(
                generated_u_ticket_json
            )

            # Because device hasn't created the id yet,
            #   we temporary store Initialization UTicket in device_table["no_id"]
            #   and the device_table will be updated by its RTicket with newly-created device_id
            if generated_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                id_for_initialization_u_ticket = "no_id"
                self.device_table[id_for_initialization_u_ticket] = OtherDevice(
                    device_id=id_for_initialization_u_ticket,
                    device_u_ticket=generated_u_ticket_json,
                )
            # TODO: Issuer can moreover store this UTicket so that can receive and verify RTicket from holder
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                failure_msg = f"Not implemented yet"
                simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> FAILURE: (V1)
            failure_msg = f"FAILURE: (V1): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (C)] Change Reciever State
    ######################################################
    def _change_state(self, new_state: str) -> None:
        self.state = new_state

    ######################################################
    # [STAGE: (S)] Send Message
    ######################################################
    def _send_xxx_message(self, sent_message_json: str) -> None:
        simple_log(
            "info",
            f"+ {self.this_device.device_name} is sending message to {self.comm_channel.end.this_device.device_name}...",
        )

        # Simulate Network Delay
        for i in range(3):
            for i in range(3):
                simple_log("info", f"+ network delay")
            if Environment.DEPLOYMENT_ENV == "PRODUCTION":  # pragma: no cover
                time.sleep(0.5)
            elif Environment.DEPLOYMENT_ENV == "DEMO":  # pragma: no cover
                time.sleep(0.5)

        self.comm_channel.sender_queue.put(sent_message_json)
