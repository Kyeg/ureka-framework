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
from ureka_framework.model.message.u_ticket import UTicket
import ureka_framework.model.message.r_ticket as r_ticket
from ureka_framework.model.message.r_ticket import RTicket

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

# Threading
import time
from queue import Queue
import threading

# Stage Worker
from ureka_framework.logic.received_msg_storer import ReceivedMsgStorer
from ureka_framework.logic.msg_verifier import MsgVerifier
from ureka_framework.logic.executor import Executor
from ureka_framework.logic.msg_generator import MsgGenerator
from ureka_framework.logic.generated_msg_storer import GeneratedMsgStorer
from ureka_framework.logic.msg_sender import MsgSender

# Pipeline Flow
from ureka_framework.logic.pipeline_flow.flow_issue_u_ticket import FlowIssueUTicket
from ureka_framework.logic.pipeline_flow.flow_apply_u_ticket import FlowApplyUTicket
from ureka_framework.logic.pipeline_flow.flow_open_session import FlowOpenSession


class DeviceController:
    def __init__(self, device_type: str = None, device_name: str = None) -> None:
        # # [TEST ONLY]
        # self.shared_data.comm_done_flag = False

        # Data Model (RAM)
        self.shared_data: SharedData = SharedData(
            this_device=ThisDevice(),
            current_session=CurrentSession(),
            this_person=ThisPerson(),
            device_table={},
            state=None,
            comm_done_flag=False,
        )

        # Resource (Storage)
        self.simple_storage: SimpleStorage = SimpleStorage(device_name=device_name)
        # Resource (Communication)
        self.comm_channel: FakeCommChannel = FakeCommChannel(
            end=None, receiver_queue=Queue(), sender_queue=None
        )

        # Stage Worker
        self.received_msg_storer = ReceivedMsgStorer(
            shared_data=self.shared_data, simple_storage=self.simple_storage
        )
        self.msg_verifier = MsgVerifier(shared_data=self.shared_data)
        self.executor = Executor(
            shared_data=self.shared_data, simple_storage=self.simple_storage
        )
        self.msg_generator = MsgGenerator(shared_data=self.shared_data)
        self.generated_msg_storer = GeneratedMsgStorer(
            shared_data=self.shared_data, simple_storage=self.simple_storage
        )
        self.msg_sender = MsgSender(
            shared_data=self.shared_data, comm_channel=self.comm_channel
        )

        # Flow
        self.flow_issuer_issue_u_ticket = FlowIssueUTicket(
            share_data=self.shared_data,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
        )
        self.flow_open_session = FlowOpenSession(
            share_data=self.shared_data,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
        )
        self.flow_apply_u_ticket = FlowApplyUTicket(
            share_data=self.shared_data,
            received_msg_storer=self.received_msg_storer,
            msg_verifier=self.msg_verifier,
            executor=self.executor,
            msg_generator=self.msg_generator,
            generated_msg_storer=self.generated_msg_storer,
            msg_sender=self.msg_sender,
            flow_open_session=self.flow_open_session,
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
        while not self.shared_data.comm_done_flag:
            time.sleep(0.01)
        # simple_log("info",f"{self.shared_data.this_device.device_name}: this communication is completed")

    # def complete_comm(self) -> None:
    #     self.shared_data.comm_done_flag = True

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
                generated_u_ticket_json: str = (
                    self.msg_generator._generate_xxx_u_ticket(generated_request)
                )
                # simple_log("debug", f"Generated UToken: {generated_u_ticket_json}")

                # [STAGE: (S)]
                self.msg_sender._send_xxx_message(generated_u_ticket_json)

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
            self.msg_verifier.verify_u_ticket_can_execute(received_u_token)
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
                self.flow_apply_u_ticket._device_send_r_ticket(
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
            generated_r_ticket_json: str = self.msg_generator._generate_xxx_r_ticket(
                generated_request
            )
            # simple_log("debug", f"Generated RToken: {generated_r_ticket_json}")

            # [STAGE: (S)]
            self.msg_sender._send_xxx_message(generated_r_ticket_json)

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
            stored_u_ticket = self.msg_verifier._classify_message_is_defined_type(
                stored_u_ticket_json
            )

            try:
                # [STAGE: (VRT)]
                self.msg_verifier.verify_u_ticket_has_successfully_executed_through_r_ticket(
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
                received_message = self.msg_verifier._classify_message_is_defined_type(
                    received_message_json
                )

                # IOT_DEVICE
                if self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_UT:
                    self.flow_apply_u_ticket._device_recv_u_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (device)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_DEVICE_WAIT_FOR_CRKE2:
                    self.flow_open_session._device_recv_cr_ke_2(received_message)
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
                    self.executor.complete_comm()
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
                    self.executor.complete_comm()

                # USER_AGENT_OR_CLOUD_SERVER
                elif (
                    self.shared_data.state
                    == this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT
                ):
                    self.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
                        received_message
                    )
                    # End Comm
                    simple_log("debug", f"+ Finish UT-UT~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_RT:
                    self.flow_apply_u_ticket._holder_recv_r_ticket(received_message)
                    # End Comm
                    simple_log("debug", f"+ Finish UT-RT~~ (holder)")
                    self.executor.complete_comm()
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE1:
                    self.flow_open_session._holder_recv_cr_ke_1(received_message)
                elif self.shared_data.state == this_device.STATE_AGENT_WAIT_FOR_CRKE3:
                    self.flow_open_session._holder_recv_cr_ke_3(received_message)
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
                    self.executor.complete_comm()
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
                    self.executor.complete_comm()
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
