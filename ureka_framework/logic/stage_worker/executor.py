# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
import ureka_framework.model.data_model.this_device as this_device

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import UTicket
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import RTicket
from typing import Tuple

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Cyrpto)
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


class Executor:
    def __init__(self, shared_data: SharedData, simple_storage: SimpleStorage) -> None:
        self.shared_data = shared_data
        self.simple_storage = simple_storage

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
        self.shared_data.this_device.device_type = device_type
        self.shared_data.this_device.device_name = device_name
        self.shared_data.this_device.has_device_type = True

        ######################################################
        # Initial Order
        ######################################################
        # [STAGE: (O)]
        self._execute_update_ticket_order("has-type")

        ######################################################
        # Initial State
        ######################################################
        # [STAGE: (C)]
        if self.shared_data.this_device.device_type == this_device.IOT_DEVICE:
            self._change_state(this_device.STATE_DEVICE_WAIT_FOR_UT)
        elif (
            self.shared_data.this_device.device_type
            == this_device.USER_AGENT_OR_CLOUD_SERVER
        ):
            self._change_state(this_device.STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT)

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    def _execute_one_time_intialize_agent_or_server(self) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is initializing...",
        )

        ######################################################
        # TODO: New way for _execute_one_time_intialize_agent_or_server()
        #         + DM: Apply Initialization Ticket
        #         + DM: Apply Personal Key Gen Ticket
        #         + DO: Generate Personal Key
        #         + DO: Request Ownership Ticket from DM
        ######################################################

        if (
            self.shared_data.this_device.device_type
            != this_device.USER_AGENT_OR_CLOUD_SERVER
        ):  # pragma: no cover -> weird operation
            failure_msg = "FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS INITIALIZATION OPERATION"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        if (
            self.shared_data.this_device.ticket_order != 0
        ):  # pragma: no cover -> FAILURE: (VR), because of verify_ticket_order()
            failure_msg = "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()

        # RAM
        self.shared_data.this_device.device_priv_key = device_priv_key
        self.shared_data.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Personal Id
        ######################################################
        # CRYPTO
        (person_priv_key, person_pub_key) = ecc.generate_key_pair()

        # RAM
        self.shared_data.this_person.person_priv_key = person_priv_key
        self.shared_data.this_person.person_pub_key = person_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = (
            self.shared_data.this_person.person_pub_key
        )

        # [STAGE: (O)]
        self._execute_update_ticket_order("agent-initialization")
        simple_log(
            "debug",
            f"{self.shared_data.this_device.device_name}: ticket_order={self.shared_data.this_device.ticket_order}",
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    # Execute UTicket (Update Keystore)
    def _execute_xxx_u_ticket(self, u_ticket_in: UTicket) -> None:
        if u_ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
            try:
                # [STAGE: (E)]
                self._execute_one_time_initialize_iot_device(u_ticket_in)
                # [STAGE: (O)]
                self._execute_update_ticket_order("device-verify-uticket", u_ticket_in)
            except RuntimeError as error:  # pragma: no cover -> werid operation
                simple_log("error", f"{error}")
        elif u_ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
            # [STAGE: (E)]
            self._execute_ownership_transfer(u_ticket_in)
            # [STAGE: (O)]
            self._execute_update_ticket_order("device-verify-uticket", u_ticket_in)
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
        ):
            # [STAGE: (E)]
            self._execute_cr_ke(u_ticket_in, "device")
        elif (
            u_ticket_in.u_ticket_type == u_ticket.TYPE_CMD_UTOKEN
            or u_ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
        ):
            # [STAGE: (E)]
            # Update Session: PS-Cmd
            self._execute_cmd_decryption(
                associated_plaintext=u_ticket_in.associated_plaintext_cmd,
                iv=self.shared_data.current_session.iv_cmd,
                ciphertext=u_ticket_in.ciphertext_cmd,
                gcm_authentication_tag=u_ticket_in.gcm_authentication_tag_cmd,
                session_key=base64str_backto_byte(
                    self.shared_data.current_session.current_session_key_str
                ),
            )
            # Update Session: PS-Data
            self.shared_data.current_session.iv_data = u_ticket_in.iv_data
            self._execute_data_processing_and_encryption(
                base64str_backto_byte(
                    self.shared_data.current_session.current_session_key_str
                )
            )
            if u_ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # [STAGE: (VTK)]
                if self.shared_data.current_session.plaintext_cmd == "TX_END":
                    simple_log("info", f"-> SUCCESS: VERIFY_TX_END")
                    # [STAGE: (O)]
                    self._execute_update_ticket_order(
                        "device-verify-uticket", u_ticket_in
                    )
                else:  # pragma: no cover -> FAILURE: (VTK)
                    simple_log("error", f"-> FAILURE: VERIFY_TX_END")
        else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
            simple_log("error", "weird ticket type")

    def _execute_one_time_initialize_iot_device(self, u_ticket_in: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is intializing...",
        )

        if (
            self.shared_data.this_device.device_type != this_device.IOT_DEVICE
        ):  # pragma: no cover -> Never reach here: weird operation
            failure_msg = (
                "FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION"
            )
            simple_log("error", failure_msg)
            raise RuntimeError(failure_msg)

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        (device_priv_key, device_pub_key) = ecc.generate_key_pair()

        # RAM
        self.shared_data.this_device.device_priv_key = device_priv_key
        self.shared_data.this_device.device_pub_key = device_pub_key

        ######################################################
        # Initialize Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = str_to_key(
            u_ticket_in.holder_id, "ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    def _execute_ownership_transfer(self, new_u_ticket: UTicket) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is transferring ownership...",
        )

        ######################################################
        # Update Device Owner
        ######################################################
        # RAM
        self.shared_data.this_device.owner_pub_key = str_to_key(
            new_u_ticket.holder_id, key_type="ecc-public-key"
        )

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    # Execute UTicket (Update Session)
    def _execute_cr_ke(
        self, ticket_in: UTicket | RTicket, comm_end: str, cmd: str = ""
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is updating current session...",
        )
        ######################################################
        # Update Session
        ######################################################
        # RAM
        if (
            type(ticket_in) == UTicket
            and ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
        ) or (
            type(ticket_in) == UTicket
            and ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
        ):
            if comm_end == "holder":
                # Update Session: Access UT
                self.shared_data.current_session.current_u_ticket_id = (
                    ticket_in.u_ticket_id
                )
                self.shared_data.current_session.current_device_id = ticket_in.device_id
                self.shared_data.current_session.current_holder_id = ticket_in.holder_id
                self.shared_data.current_session.current_task_scope = (
                    ticket_in.task_scope
                )
                # Update Session: PS-Cmd
                self.shared_data.current_session.plaintext_cmd = cmd
                self.shared_data.current_session.associated_plaintext_cmd = (
                    "additional unencrypted cmd"
                )
            elif comm_end == "device":
                # Update Session: Access UT
                self.shared_data.current_session.current_u_ticket_id = (
                    ticket_in.u_ticket_id
                )
                self.shared_data.current_session.current_device_id = ticket_in.device_id
                self.shared_data.current_session.current_holder_id = ticket_in.holder_id
                self.shared_data.current_session.current_task_scope = (
                    ticket_in.task_scope
                )
                # Update Session: CR-KE
                self.shared_data.current_session.challenge_1 = ecdh.generate_random_str(
                    32
                )
                self.shared_data.current_session.key_exchange_salt_1 = (
                    ecdh.generate_random_str(32)
                )
                # Update Session: PS-Cmd
                self.shared_data.current_session.iv_cmd = byte_to_base64str(
                    ecdh.gcm_gen_iv()
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "weird comm_end")
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET
        ):
            # Update Session: CR-KE
            self.shared_data.current_session.challenge_1 = ticket_in.challenge_1
            self.shared_data.current_session.key_exchange_salt_1 = (
                ticket_in.key_exchange_salt_1
            )
            self.shared_data.current_session.challenge_2 = ecdh.generate_random_str(32)
            self.shared_data.current_session.key_exchange_salt_2 = (
                ecdh.generate_random_str(32)
            )
            # Session Key Gereration ("holder")
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.shared_data.current_session.key_exchange_salt_1,
                salt_2=self.shared_data.current_session.key_exchange_salt_2,
                server_priv_key=self.shared_data.this_person.person_priv_key,
                peer_pub_key=str_to_key(
                    self.shared_data.current_session.current_device_id,
                    "ecc-public-key",
                ),
            )
            # Update Session: PS-Cmd
            self.shared_data.current_session.iv_cmd = ticket_in.iv_cmd
            self._execute_cmd_encryption_and_gen_next_iv(current_session_key_byte)
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET
        ):
            # Update Session: CR-KE
            self.shared_data.current_session.challenge_2 = ticket_in.challenge_2
            self.shared_data.current_session.key_exchange_salt_2 = (
                ticket_in.key_exchange_salt_2
            )
            # Session Key Gereration ("device")
            current_session_key_byte = self._execute_generate_session_key(
                salt_1=self.shared_data.current_session.key_exchange_salt_1,
                salt_2=ticket_in.key_exchange_salt_2,
                server_priv_key=self.shared_data.this_device.device_priv_key,
                peer_pub_key=str_to_key(
                    self.shared_data.current_session.current_holder_id,
                    "ecc-public-key",
                ),
            )
            self.shared_data.current_session.current_session_key_str = (
                byte_to_base64str(current_session_key_byte)
            )
            # Update Session: PS-Cmd
            self._execute_cmd_decryption(
                associated_plaintext=ticket_in.associated_plaintext_cmd,
                iv=self.shared_data.current_session.iv_cmd,
                ciphertext=ticket_in.ciphertext_cmd,
                gcm_authentication_tag=ticket_in.gcm_authentication_tag_cmd,
                session_key=current_session_key_byte,
            )
            # Update Session: PS-Data
            self.shared_data.current_session.iv_data = ticket_in.iv_data
            self._execute_data_processing_and_encryption(current_session_key_byte)
        elif (
            type(ticket_in) == RTicket
            and ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET
        ):
            # Session Key Obtaining ("holder")
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Data
            self._execute_data_decryption(
                associated_plaintext=ticket_in.associated_plaintext_data,
                iv=self.shared_data.current_session.iv_data,
                ciphertext=ticket_in.ciphertext_data,
                gcm_authentication_tag=ticket_in.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
            )
            # Update Session: PS-Cmd
            self.shared_data.current_session.iv_cmd = ticket_in.iv_cmd
        else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
            simple_log("error", "weird ticket type")

        # simple_log(
        #     "debug",
        #     f"current_session_json in {self.shared_data.this_device.device_name} = {current_session_to_jsonstr(self.shared_data.current_session)}",
        # )

        ######################################################
        # Storage (Persistent vs. RAM-only)
        ######################################################
        # self.simple_storage.store_storage(
        #     self.shared_data.this_device, self.shared_data.device_table, self.shared_data.this_person, self.shared_data.current_session
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

    def _execute_cmd_encryption_and_gen_next_iv(
        self, current_session_key_byte: bytes
    ) -> None:
        # Message Encryption
        (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
            plaintext=self.shared_data.current_session.plaintext_cmd,
            associated_plaintext=self.shared_data.current_session.associated_plaintext_cmd,
            session_key=current_session_key_byte,
            iv=self.shared_data.current_session.iv_cmd,
        )
        # Update Session: PS-Key
        self.shared_data.current_session.current_session_key_str = byte_to_base64str(
            current_session_key_byte
        )
        # Update Session: PS-Cmd
        self.shared_data.current_session.ciphertext_cmd = ciphertext
        self.shared_data.current_session.gcm_authentication_tag_cmd = (
            gcm_authentication_tag
        )
        # Update Session: PS-Data
        self.shared_data.current_session.iv_data = byte_to_base64str(ecdh.gcm_gen_iv())

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
        # Update Session: PS-Cmd
        self.shared_data.current_session.plaintext_cmd = plaintext_cmd
        self.shared_data.current_session.associated_plaintext_cmd = associated_plaintext
        self.shared_data.current_session.iv_cmd = iv
        self.shared_data.current_session.ciphertext_cmd = ciphertext
        self.shared_data.current_session.gcm_authentication_tag_cmd = (
            gcm_authentication_tag
        )

    def _execute_data_processing_and_encryption(
        self, current_session_key_byte: bytes
    ) -> None:
        # Data Processing
        (plaintext_data, associated_plaintext) = self._execute_data_processing(
            self.shared_data.current_session.plaintext_cmd,
            self.shared_data.current_session.associated_plaintext_cmd,
        )
        # Message Encryption
        (ciphertext, gcm_authentication_tag) = self._execute_encrypt_plaintext(
            plaintext=plaintext_data,
            associated_plaintext=associated_plaintext,
            session_key=current_session_key_byte,
            iv=self.shared_data.current_session.iv_data,
        )
        # Update Session: PS-Data
        self.shared_data.current_session.plaintext_data = plaintext_data
        self.shared_data.current_session.associated_plaintext_data = (
            associated_plaintext
        )
        self.shared_data.current_session.ciphertext_data = ciphertext
        self.shared_data.current_session.gcm_authentication_tag_data = (
            gcm_authentication_tag
        )
        # Update Session: PS-Cmd
        self.shared_data.current_session.iv_cmd = byte_to_base64str(ecdh.gcm_gen_iv())

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
        # Update Session: PS-Data
        self.shared_data.current_session.plaintext_data = plaintext_data
        self.shared_data.current_session.associated_plaintext_data = (
            associated_plaintext
        )
        self.shared_data.current_session.iv_data = iv
        self.shared_data.current_session.ciphertext_data = ciphertext
        self.shared_data.current_session.gcm_authentication_tag_data = (
            gcm_authentication_tag
        )

    def _execute_encrypt_plaintext(
        self,
        plaintext: str,
        associated_plaintext: str,
        session_key: bytes,
        iv: str = "",
    ) -> Tuple[str, str, str]:
        plaintext_byte: bytes = str_to_byte(plaintext)
        associated_plaintext_byte: bytes = str_to_byte(associated_plaintext)
        iv_byte: bytes = base64str_backto_byte(iv)
        (ciphertext_byte, gcm_authentication_tag_byte) = ecdh.gcm_encrypt(
            plaintext_byte, associated_plaintext_byte, session_key, iv_byte
        )
        ciphertext = byte_to_base64str(ciphertext_byte)
        gcm_authentication_tag = byte_to_base64str(gcm_authentication_tag_byte)

        return (ciphertext, gcm_authentication_tag)

    def _execute_decrypt_ciphertext(
        self,
        associated_plaintext: str,
        iv: str,
        ciphertext: str,
        gcm_authentication_tag: str,
        session_key: bytes,
    ) -> str:
        # [STAGE: (VTK)]
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

            result_message = f"-> SUCCESS: VERIFY_IV_AND_HMAC"
            simple_log("info", result_message)
            self.shared_data.result_message = result_message

        except InvalidTag:
            result_message = f"-> FAILURE: VERIFY_IV_AND_HMAC"
            simple_log("error", result_message)
            self.shared_data.result_message = result_message
            raise RuntimeError(result_message)

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
            self._execute_update_ticket_order("holder-verify-rticket", r_ticket_in)
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE1_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "holder")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE2_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "device")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_CRKE3_RTICKET:
            # [STAGE: (E)]
            self._execute_cr_ke(r_ticket_in, "holder")
        elif r_ticket_in.r_ticket_type == r_ticket.TYPE_DATA_RTOKEN:
            # [STAGE: (E)]
            # Session Key Obtaining ("holder")
            current_session_key_byte = base64str_backto_byte(
                self.shared_data.current_session.current_session_key_str
            )
            # Update Session: PS-Data
            self._execute_data_decryption(
                associated_plaintext=r_ticket_in.associated_plaintext_data,
                iv=self.shared_data.current_session.iv_data,
                ciphertext=r_ticket_in.ciphertext_data,
                gcm_authentication_tag=r_ticket_in.gcm_authentication_tag_data,
                session_key=current_session_key_byte,
            )
            # Update Session: PS-Cmd
            self.shared_data.current_session.iv_cmd = r_ticket_in.iv_cmd
        else:  # pragma: no cover -> Never reach here: Because of verify_r_ticket_type()
            simple_log("error", "weird ticket type")

    # [STAGE: (VTS)] TODO: Verify Task Scope before Execution
    # Execute Application & Data Processing
    def _execute_data_processing(
        self, plaintext_cmd: str, associated_plaintext_cmd: str
    ) -> Tuple[str, str]:
        plaintext_cmd = f"Data: {plaintext_cmd}"
        associated_plaintext_cmd = f"Data: {associated_plaintext_cmd}"
        return (plaintext_cmd, associated_plaintext_cmd)

    ######################################################
    # [STAGE: (O)] Update Ticket Order
    #   Update Ticket Order after:
    #       "has-type": Intial Ticket Order = 0
    #       "agent-initialization": Ticket Order = 1 after device/agent is initialized
    #       "holder-generate-or-receive-uticket": Generate or Receive UTicket (expected ticket order)
    #       "device-verify-uticket": Verify UTicket & End TX (actual ticket order)
    #       "holder-verify-rticket": Verify RTicket (actual ticket order)
    ######################################################
    def _execute_update_ticket_order(
        self, updating_case: str, ticket_in: UTicket | RTicket = None
    ) -> None:
        simple_log(
            "info",
            f"+ {self.shared_data.this_device.device_name} is updating ticket order...",
        )

        if updating_case == "has-type":
            self.shared_data.this_device.ticket_order = 0
        elif updating_case == "agent-initialization":
            self.shared_data.this_device.ticket_order = (
                self.shared_data.this_device.ticket_order + 1
            )
        elif updating_case == "holder-generate-or-receive-uticket":
            # Recieve UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                self.shared_data.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: ticket_order={self.shared_data.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "Other ticket types should not update ticket_order")
        elif updating_case == "device-verify-uticket":
            # Execute UTicket
            if type(ticket_in) == UTicket and (
                ticket_in.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.u_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                self.shared_data.this_device.ticket_order = (
                    self.shared_data.this_device.ticket_order + 1
                )
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: ticket_order={self.shared_data.this_device.ticket_order}",
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "Other ticket types should not update ticket_order")
        elif updating_case == "holder-verify-rticket":
            # Execute UTicket
            if type(ticket_in) == RTicket and (
                ticket_in.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or ticket_in.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN
            ):
                self.shared_data.device_table[
                    ticket_in.device_id
                ].ticket_order = ticket_in.ticket_order
                simple_log(
                    "debug",
                    f"{self.shared_data.this_device.device_name}: ticket_order={self.shared_data.device_table[ticket_in.device_id].ticket_order}",
                )
            else:  # pragma: no cover -> Never reach here
                simple_log("error", "Other ticket types should not update ticket_order")
        else:  # pragma: no cover -> Never reach here: Because of verify_updating_case()
            simple_log("error", "weird updating_case")

        ######################################################
        # Storage
        ######################################################
        self.simple_storage.store_storage(
            self.shared_data.this_device,
            self.shared_data.device_table,
            self.shared_data.this_person,
            self.shared_data.current_session,
        )

    ######################################################
    # [STAGE: (C)] Change Reciever State
    ######################################################
    def _change_state(self, new_state: str) -> None:
        self.shared_data.state = new_state

    ######################################################
    # [TEST ONLY] Function
    #   Pytest finishes this test when main thread is finished
    #       (& all daemon threads, e.g. all receiver_threads will also be terminated)
    #   In production, we may need Ctrl+C or other shutdown method to stop this loop program
    ######################################################
    def complete_comm(self) -> None:
        self.shared_data.comm_done_flag = True
