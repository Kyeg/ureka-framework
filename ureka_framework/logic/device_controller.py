# Deployment Environment
from ureka_framework.environment import Environment

# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.model.data_model.this_device import ThisDevice
from ureka_framework.model.data_model.other_device import OtherDevice
from ureka_framework.model.data_model.current_session import CurrentSession
from ureka_framework.model.data_model.this_person import ThisPerson

# Data Model (Message)
import ureka_framework.model.message.u_ticket as u_ticket
from ureka_framework.model.message.u_ticket import (
    UTicket,
    u_ticket_to_jsonstr,
)
import ureka_framework.model.message.r_ticket as r_ticket
from ureka_framework.model.message.r_ticket import (
    RTicket,
    r_ticket_to_jsonstr,
)

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Comm)
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel

# Resource (Crypto)
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

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Worker
from ureka_framework.logic.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.u_ticket_verifier import UTicketVerifier
from ureka_framework.logic.r_ticket_verifier import RTicketVerifier
from ureka_framework.logic.executor import Executor
from ureka_framework.logic.u_ticket_generator import UTicketGenerator
from ureka_framework.logic.r_ticket_generator import RTicketGenerator
from ureka_framework.logic.generated_msg_storer import GeneratedMsgStorer


# Threading
import time
from queue import Queue
import threading


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
        # [TEST ONLY]
        self.comm_done_flag = False

        # Data Model
        self.shared_data: SharedData = SharedData()

        # Resource (Storage)
        self.simple_storage: SimpleStorage = SimpleStorage(device_name=device_name)
        # Resource (Communication)
        self.comm_channel: FakeCommChannel = FakeCommChannel()
        self.comm_channel.receiver_queue = Queue()

        # Worker
        self.received_msg_storer = ReceivedMsgStorer(
            shared_data=self.shared_data,
            simple_storage=self.simple_storage,
        )
        self.executor = Executor(
            shared_data=self.shared_data,
            simple_storage=self.simple_storage,
        )
        self.generated_msg_storer = GeneratedMsgStorer(
            shared_data=self.shared_data,
            simple_storage=self.simple_storage,
        )

        # Always load Storage after Reboot
        (
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        ) = self.simple_storage.load_storage()

        # Set Device Type (must after loading storage)
        if self.shared_data.this_device.has_device_type is False:
            self.executor._execute_one_time_set_time_device_type_and_name(
                device_type, device_name
            )

        simple_log("info", f"+ Here is a {self.shared_data.this_device.device_name}...")

    ######################################################
    # [TEST ONLY] Function
    #   Pytest finishes this test when main thread is finished
    #       (& all daemon threads, e.g. all receiver_threads will also be terminated)
    #   In production, we may need Ctrl+C or other shutdown method to stop this loop program
    ######################################################
    def wait_comm_completed(self) -> None:
        while not self.comm_done_flag:
            time.sleep(0.01)
        # simple_log("info",f"{self.shared_data.this_device.device_name}: this communication is completed")

    def complete_comm(self) -> None:
        self.comm_done_flag = True

    ######################################################
    # Device Activity Cycle
    ######################################################
    def reboot_device(self) -> None:
        self.__init__(
            device_type=self.shared_data.this_device.device_type,
            device_name=self.shared_data.this_device.device_name,
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
    #         execution only change state after success, but need pay attention to (SR)
    ######################################################
    def issuer_issue_u_ticket_to_herself(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table or device_id == "no_id":
                # [STAGE: (G)]
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    arbitrary_dict
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                self.generated_msg_storer._store_generated_xxx_u_ticket(
                    generated_u_ticket_json
                )

        except RuntimeError:  # pragma: no cover -> Weird U-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def issuer_issue_u_ticket_to_holder(
        self, device_id: str, arbitrary_dict: dict
    ) -> None:
        try:
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (G)]
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    arbitrary_dict
                )
                # simple_log("debug", f"Generated UTicket: {generated_u_ticket_json}")

                # [STAGE: (SG)]
                # TODO: Issuer can moreover store this UTicket so that can receive and verify RTicket from holder
                # self.generated_msg_storer._store_generated_xxx_u_ticket(generated_u_ticket_json)

                # [STAGE: (S)]
                self._send_xxx_message(generated_u_ticket_json)

                # End Comm
                simple_log("debug", f"+ Finish UT-UT~~ (issuer)")
                self.complete_comm()

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> Weird U-Request (ValidationError)
            failure_msg = f"FAILURE: (VUREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]
            # But the actual ticket order in device is still unknown -> TODO: Attack

            # [STAGE: (SR)]
            self.received_msg_storer._store_received_xxx_u_ticket(received_u_ticket)

            # [STAGE: (O)]
            self.executor._execute_update_ticket_order(
                "holder-receive-uticket", received_u_ticket
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (VR)
            failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # [STAGE: (G)(S)]
            # Can optionally _generate_xxx_r_ticket & _send_xxx_message
            pass

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
            # [STAGE: (VL)]
            stored_u_ticket_json: str = self.shared_data.device_table[
                device_id
            ].device_u_ticket
            # simple_log("debug",f"Stored (& to be Forwarded) UTicket: {stored_u_ticket_json}")

            # [STAGE: (VR)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            if (
                stored_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or stored_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
            ):
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_RT)
            elif stored_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # [STAGE: (E)]
                self.executor._execute_cr_ke(stored_u_ticket, "holder", cmd)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_CRKE1)
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

            # [STAGE: (S)]
            self._send_xxx_message(stored_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> FAILURE: (VR)
            failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (SR)]
            # No need to optionally _store_received_xxx_u_ticket

            # [STAGE: (VUT)]
            self.verify_u_ticket_can_execute(received_u_ticket)
            result_message = f"Success (verify_u_ticket_can_execute)"

            # After TX End
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                # [STAGE: (EO)]
                self.executor._execute_xxx_u_ticket(received_u_ticket)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)
            # CR-KE-PS
            elif received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # [STAGE: (E)]
                self.executor._execute_xxx_u_ticket(received_u_ticket)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CRKE2)
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VUT)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # After TX End
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                # [STAGE: (G)(S)]
                self._device_send_r_ticket(
                    received_u_ticket.u_ticket_type,
                    received_u_ticket.u_ticket_id,
                    result_message,
                )
            # CR-KE-PS
            elif received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET:
                # [STAGE: (G)(S)]
                self._device_send_cr_ke_1(result_message)
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

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
                    "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                    "audit_start": f"{u_ticket_id}",
                    "result": f"{result_message}",
                }
            elif u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # audit_start has already stored when receiving Access UTicket
                r_ticket_request: dict = {
                    "r_ticket_type": f"{u_ticket_type}",
                    "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                    "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                    "audit_end": f"TX_END",
                    "result": f"{result_message}",
                }
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (SG)]
            # Can optionally _stored_generated_xxx_r_ticket

            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_r_ticket(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (SR)]
            self.received_msg_storer._store_received_xxx_r_ticket(received_r_ticket)

            # Query Corresponding UTicket(s)
            #   Notice that even Initialization UTicket is copied in the device_table["device_id"]
            # [STAGE: (VL)]
            stored_u_ticket_json: str = self.shared_data.device_table[
                received_r_ticket.device_id
            ].device_u_ticket
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (VR)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            if (
                received_r_ticket.audit_end == None
                or received_r_ticket.audit_end == "TX_END"
            ):
                try:
                    # [STAGE: (VRT)]
                    self.verify_u_ticket_has_successfully_executed_through_r_ticket(
                        r_ticket_in=received_r_ticket,
                        audit_start_ticket=stored_u_ticket,
                        audit_end_ticket=None,
                    )
                    result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                    # [STAGE: (E)(O)]
                    self.executor._execute_xxx_r_ticket(received_r_ticket)
                    # [STAGE: (C)]
                    self.executor._change_state(
                        this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                    )
                except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
                    result_message = f"{error}"

                simple_log("debug", f"result_message = {result_message}")

            else:  # pragma: no cover -> TODO: Auditted by Revocation UTicket
                failure_msg = f"Not implemented yet"
                simple_log("error", failure_msg)

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            if error == "NOT VALID JSON or VALID RTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)
            elif error == "NOT VALID JSON or VALID UTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
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
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.shared_data.current_session.challenge_1}",
                "key_exchange_salt_1": f"{self.shared_data.current_session.key_exchange_salt_1}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug",f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_1(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]
            # [STAGE: (VRT)]
            self.verify_u_ticket_has_successfully_executed_through_r_ticket(
                r_ticket_in=received_r_ticket,
                audit_start_ticket=None,
                audit_end_ticket=None,
            )
            result_message = (
                f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
            )
            # [STAGE: (E)]
            self.executor._execute_xxx_r_ticket(received_r_ticket)
            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_CRKE3)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # [STAGE: (G)(S)]
            simple_log("debug", f"result_message = {result_message}")
            self._holder_send_cr_ke_2(result_message)

    def _holder_send_cr_ke_2(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE2_RTICKET}",
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_1": f"{self.shared_data.current_session.challenge_1}",
                "challenge_2": f"{self.shared_data.current_session.challenge_2}",
                "key_exchange_salt_2": f"{self.shared_data.current_session.key_exchange_salt_2}",
                "iv_cmd": f"{self.shared_data.current_session.iv_cmd}",
                "associated_plaintext_cmd": f"{self.shared_data.current_session.associated_plaintext_cmd}",
                "ciphertext_cmd": f"{self.shared_data.current_session.ciphertext_cmd}",
                "gcm_authentication_tag_cmd": f"{self.shared_data.current_session.gcm_authentication_tag_cmd}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cr_ke_2(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (VRT)]
            self.verify_u_ticket_has_successfully_executed_through_r_ticket(
                r_ticket_in=received_r_ticket,
                audit_start_ticket=None,
                audit_end_ticket=None,
            )
            result_message = (
                f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
            )
            # [STAGE: (E)]
            self.executor._execute_xxx_r_ticket(received_r_ticket)
            # [STAGE: (C)]
            self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # [STAGE: (G)(S)]
            simple_log("debug", f"result_message = {result_message}")
            self._device_send_cr_ke_3(result_message)

    def _device_send_cr_ke_3(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            r_ticket_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_CRKE3_RTICKET}",
                "device_id": f"{self.shared_data.current_session.current_device_id}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "challenge_2": f"{self.shared_data.current_session.challenge_2}",
                "iv_data": f"{self.shared_data.current_session.iv_data}",
                "associated_plaintext_data": f"{self.shared_data.current_session.associated_plaintext_data}",
                "ciphertext_data": f"{self.shared_data.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.shared_data.current_session.gcm_authentication_tag_data}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(r_ticket_request)
            # simple_log("debug", f"Generated RTicket: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_cr_ke_3(self, received_r_ticket: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            try:
                # [STAGE: (VRT)]
                self.verify_u_ticket_has_successfully_executed_through_r_ticket(
                    r_ticket_in=received_r_ticket,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                )
                result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                # [STAGE: (E)]
                self.executor._execute_xxx_r_ticket(received_r_ticket)
                # [STAGE: (C)]
                self.executor._change_state(
                    this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                )
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
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
            # [STAGE: (VL)]
            if device_id in self.shared_data.device_table:
                # [STAGE: (E)]
                # Update Session: PS
                self.shared_data.current_session.plaintext_cmd = cmd
                self.shared_data.current_session.associated_plaintext_cmd = (
                    "additional unencrypted cmd"
                )
                # Message Encryption (str + key byte)
                self.executor._execute_cmd_encryption(
                    base64str_backto_byte(
                        self.shared_data.current_session.current_session_key_str
                    )
                )

                if tx_end == False:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_DATA)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_CMD_UTOKEN}"
                else:
                    # [STAGE: (C)]
                    self.executor._change_state(this_device.STATE_AGENT_WAIT_FOR_RT)
                    # [STAGE: (G)]
                    u_ticket_type = f"{u_ticket.TYPE_TX_END_UTOKEN}"

                # [STAGE: (G)]
                generated_request: dict = {
                    "device_id": f"{self.shared_data.current_session.current_device_id}",
                    "u_ticket_type": f"{u_ticket_type}",
                    "associated_plaintext": f"{self.shared_data.current_session.associated_plaintext_cmd}",
                    "iv": f"{self.shared_data.current_session.iv_cmd}",
                    "ciphertext": f"{self.shared_data.current_session.ciphertext_cmd}",
                    "gcm_authentication_tag": f"{self.shared_data.current_session.gcm_authentication_tag_cmd}",
                }
                generated_u_ticket_json: str = self._generate_xxx_u_ticket(
                    generated_request
                )
                # simple_log("debug", f"Generated UToken: {generated_u_ticket_json}")

                # [STAGE: (S)]
                self._send_xxx_message(generated_u_ticket_json)

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError:  # pragma: no cover -> Weird UTK-Request (ValidationError)
            failure_msg = f"FAILURE: (VUTKREQ)"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _device_recv_cmd(self, received_u_token: UTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # [STAGE: (VUT)]
            self.verify_u_ticket_can_execute(received_u_token)
            result_message = f"Success (verify_u_ticket_can_execute)"

            # [STAGE: (E)]
            self.executor._execute_xxx_u_ticket(received_u_token)
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                pass
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VUT)
            result_message = f"{error}"

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

        finally:
            # PS
            if received_u_token.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN:
                # [STAGE: (G)(S)]
                self._device_send_data(result_message)
            elif received_u_token.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # [STAGE: (G)(S)]
                self._device_send_r_ticket(
                    received_u_token.u_ticket_type,
                    received_u_token.u_ticket_id,
                    result_message,
                )
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

    def _device_send_data(self, result_message: str) -> None:
        try:
            # [STAGE: (G)]
            generated_request: dict = {
                "r_ticket_type": f"{r_ticket.TYPE_DATA_RTOKEN}",
                "device_id": f"{self.shared_data.this_device.device_pub_key_str}",
                "audit_start": f"{self.shared_data.current_session.current_u_ticket_id}",
                "result": f"{result_message}",
                "associated_plaintext_data": f"{self.shared_data.current_session.associated_plaintext_data}",
                "iv_data": f"{self.shared_data.current_session.iv_data}",
                "ciphertext_data": f"{self.shared_data.current_session.ciphertext_data}",
                "gcm_authentication_tag_data": f"{self.shared_data.current_session.gcm_authentication_tag_data}",
            }
            generated_r_ticket_json: str = self._generate_xxx_r_ticket(
                generated_request
            )
            # simple_log("debug", f"Generated RToken: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self._send_xxx_message(generated_r_ticket_json)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _holder_recv_data(self, received_r_token: RTicket) -> None:
        try:
            # [STAGE: (R)(VR)]

            # Query Corresponding UTicket
            # [STAGE: (VL)]
            device_id = received_r_token.device_id
            stored_u_ticket_json = self.shared_data.device_table[
                device_id
            ].device_u_ticket
            simple_log("debug", f"Corresponding UTicket: {stored_u_ticket_json}")
            # [STAGE: (VR)]
            stored_u_ticket = self._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            try:
                # [STAGE: (VRT)]
                self.verify_u_ticket_has_successfully_executed_through_r_ticket(
                    r_ticket_in=received_r_token,
                    audit_start_ticket=stored_u_ticket,
                    audit_end_ticket=None,
                )
                result_message = f"Success (verify_u_ticket_has_successfully_executed_through_r_ticket)"
                # [STAGE: (E)]
                self.executor._execute_xxx_r_ticket(received_r_token)
                # [STAGE: (C)]
                self.executor._change_state(this_device.STATE_DEVICE_WAIT_FOR_CMD)
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
                result_message = f"{error}"

            simple_log("debug", f"result_message = {result_message}")

        except KeyError:  # pragma: no cover -> FAILURE: (VL)
            failure_msg = f"FAILURE: (VL): has_u_ticket_in_device_table"
            simple_log("error", failure_msg)

        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            if error == "NOT VALID JSON or VALID RTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)
            elif error == "NOT VALID JSON or VALID UTICKET SCHEMA":
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (R)] Receive Message
    ######################################################
    def _connect(self, end: "DeviceController") -> None:
        # simple_log("info",
        #     f"+ {self.shared_data.this_device.device_name} is connecting with {end.shared_data.this_device.device_name}..."
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
            try:
                # [STAGE: (R)]
                # This will block until message is received
                received_message_json = self.comm_channel.receiver_queue.get()
                simple_log(
                    "info",
                    f"+ {self.shared_data.this_device.device_name} is receiving message from {self.comm_channel.end.shared_data.this_device.device_name}...",
                )
                simple_log("demo", f"Received Message: {received_message_json}")

                # [STAGE: (VR)]
                received_message = self._classify_message_is_defined_type(
                    received_message_json
                )

                # IOT_DEVICE
                if self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_UT:
                    self._device_recv_u_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CRKE2:
                    self._device_recv_cr_ke_2(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (device)")
                    self.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CMD:
                    self._device_recv_cmd(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_cmd in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_cmd}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (device)")
                    self.complete_comm()

                # USER_AGENT_OR_CLOUD_SERVER
                elif (
                    self.shared_data.state
                    == this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                ):
                    self._holder_recv_u_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                    self.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_RT:
                    self._holder_recv_r_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE1:
                    self._holder_recv_cr_ke_1(received_message)
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE3:
                    self._holder_recv_cr_ke_3(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log(
                        "demo",
                        f"\n+++Session is Constucted+++",
                    )
                    simple_log("debug", f"+ Finish CR-KE~~ (holder)")
                    self.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_DATA:
                    self._holder_recv_data(received_message)
                    # End Comm
                    # simple_log(
                    #     "debug",
                    #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
                    # )
                    simple_log(
                        "demo",
                        f"\nplaintext_data in {self.shared_data.this_device.device_name} = {self.shared_data.current_session.plaintext_data}",
                    )
                    simple_log("debug", f"+ Finish PS~~ (holder)")
                    self.complete_comm()
                else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                    simple_log("error", "weird ticket type")

            except (
                RuntimeError
            ):  # pragma: no cover -> FAILURE: (VR) TODO: device_send_error_r_ticket (Sterilization)
                failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
                simple_log("error", failure_msg)

            except:  # pragma: no cover -> Unpredicted Error
                failure_msg = f"FAILURE: UNPREDICTED ERROR"
                simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (V)] Verify Message & Execute
    #   (VR): classify_message_is_defined_type
    #   (VL): has_u_ticket_in_device_table
    #   (VUT): verify_u_ticket_can_execute
    #   (VRT): verify_u_ticket_has_successfully_executed_through_r_ticket
    #   (VTK): verify_token_through_hmac
    #   (VTS): verify_cmd_is_in_task_scope
    ######################################################
    def _classify_message_is_defined_type(
        self, arbitrary_json: str
    ) -> UTicket | RTicket:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is classifying message...",
        )

        # Notice that Pydantic can classify message type by json schema,
        #   while other implementation may need classify message type by message_type field
        try:
            # [STAGE: (VR: UTicket)]
            u_ticket_verifier = UTicketVerifier(this_device=None)

            u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.has_device_id(u_ticket_in)

            return u_ticket_in
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
            try:
                # [STAGE: (VR: RTicket)]
                r_ticket_verifier = RTicketVerifier(
                    this_device=None,
                    device_table=None,
                    audit_start_ticket=None,
                    audit_end_ticket=None,
                    current_session=None,
                )

                r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
                r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
                r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in)
                r_ticket_in = r_ticket_verifier.has_device_id(r_ticket_in)

                return r_ticket_in
            except RuntimeError as error:  # pragma: no cover -> FAILURE: (VR)
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

    def verify_u_ticket_can_execute(self, u_ticket_in: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is verifying u_ticket...",
        )

        try:
            u_ticket_verifier = UTicketVerifier(
                this_device=self.shared_data.this_device
            )

            # u_ticket_in = u_ticket_verifier.verify_json_schema(arbitrary_json)
            # u_ticket_in = u_ticket_verifier.verify_protocol_version(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_message_type(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_u_ticket_id(u_ticket_in)
            # u_ticket_in = u_ticket_verifier.verify_u_ticket_type(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_device_id(u_ticket_in)

            u_ticket_in = u_ticket_verifier.verify_ticket_order(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_holder_id(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_task_scope(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_ps(u_ticket_in)
            u_ticket_in = u_ticket_verifier.verify_issuer_signature(u_ticket_in)
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VUT)
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def verify_u_ticket_has_successfully_executed_through_r_ticket(
        self,
        r_ticket_in: RTicket,
        audit_start_ticket: None | UTicket,
        audit_end_ticket: None | UTicket,
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is verifying r_ticket...",
        )

        try:
            r_ticket_verifier = RTicketVerifier(
                this_device=self.shared_data.this_device,
                device_table=self.shared_data.device_table,
                audit_start_ticket=audit_start_ticket,
                audit_end_ticket=audit_end_ticket,
                current_session=self.shared_data.current_session,
            )

            # r_ticket_in = r_ticket_verifier.verify_json_schema(arbitrary_json)
            # r_ticket_in = r_ticket_verifier.verify_protocol_version(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_message_type(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_r_ticket_id(r_ticket_in)
            # r_ticket_in = r_ticket_verifier.verify_r_ticket_type(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_id(r_ticket_in)

            r_ticket_in = r_ticket_verifier.verify_ticket_order(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_start(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_audit_end(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_result(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_cr_ke(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_ps(r_ticket_in)
            r_ticket_in = r_ticket_verifier.verify_device_signature(r_ticket_in)
        except RuntimeError as error:  # pragma: no cover -> FAILURE: (VRT)
            raise RuntimeError(error)
        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    ######################################################
    # [STAGE: (G)] Generate Message
    ######################################################
    def _generate_xxx_u_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is generating u_ticket...",
        )

        u_ticket_generator = UTicketGenerator(
            self.shared_data.this_device,
            self.shared_data.this_person,
            self.shared_data.device_table,
        )
        generated_u_ticket = u_ticket_generator.generate_arbitrary_u_ticket(
            arbitrary_dict
        )
        generated_u_ticket_json = u_ticket_to_jsonstr(generated_u_ticket)

        return generated_u_ticket_json

    def _generate_xxx_r_ticket(self, arbitrary_dict: dict) -> str:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is generating r_ticket...",
        )

        r_ticket_generator = RTicketGenerator(
            self.shared_data.this_device,
            self.shared_data.this_person,
            self.shared_data.device_table,
        )
        generated_r_ticket = r_ticket_generator.generate_arbitrary_r_ticket(
            arbitrary_dict
        )
        generated_r_ticket_json = r_ticket_to_jsonstr(generated_r_ticket)

        return generated_r_ticket_json

    ######################################################
    # [STAGE: (S)] Send Message
    ######################################################
    def _send_xxx_message(self, sent_message_json: str) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is sending message to {self.comm_channel.end.shared_data.this_device.device_name}...",
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
