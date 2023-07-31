import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
import ureka_framework.resource.crypto.key_serialization as key_serialization
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class ExecutionFlow:
    def __init__(self, device_controller) -> None:
        # Lots of side effect on device_controller...
        self.device_controller = device_controller

    ######################################################
    # Ticket Handshake
    #   +++ Execute xxxTicket (E-Z) +++
    ######################################################
    def initialize_iot_device(self, new_ticket: Ticket) -> bool:
        if self.device_controller.device_type != ticket.IOT_DEVICE:
            logging.debug("ERROR: ONLY IOT_DEVICE CAN DO THIS OPERATION")
            return False

        if self.device_controller.is_initialized:
            logging.debug("ERROR: ALREADY INITIALIZED")
            return False

        ######################################################
        # Initialize Device Id
        ######################################################
        # CRYPTO
        device_private_key_byte = b""
        device_public_key_byte = b""
        (device_private_key_byte, device_public_key_byte) = ecc.generate_key_pair()

        # RAM
        self.device_controller.is_initialized = True
        self.device_controller.device_priv_key = key_serialization.byte_backto_key(
            device_private_key_byte, key_type="ecc-private-key"
        )
        self.device_controller.device_pub_key = key_serialization.byte_backto_key(
            device_public_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.device_controller.mSecureDB.store_device_id(
            device_private_key_byte, device_public_key_byte
        )

        ######################################################
        # Update Permission Table (only for IoT Device)
        ######################################################

        # RAM
        self.device_controller.owner_pub_key = key_serialization.str_backto_key(
            new_ticket.holder_id
        )

        # DB
        owner_public_key_byte = key_serialization.str_backto_byte(new_ticket.holder_id)
        self.device_controller.mSecureDB.store_owner_id(owner_public_key_byte)

        self.device_controller.display_state()
        return True

    def query(self):
        logging.debug(
            "device_pub_key_str: %s" % self.device_controller.device_pub_key_str[0:64]
        )
        logging.debug(
            "owner_pub_key_str: %s" % self.device_controller.owner_pub_key_str[0:64]
        )

    def ownership_transfer(self, new_ticket: Ticket) -> None:
        ######################################################
        # Decode Request Body
        ######################################################
        task_scope_dict = key_serialization.jsonstr_to_dict(
            new_ticket.task_scope
        )  # sort_keys = True
        logging.debug("task_scope_dict = " + str(task_scope_dict))

        ######################################################
        # Update Permission Table (MANAGEMENT_OWNER)
        ######################################################
        if (
            task_scope_dict[ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE]
            == ticket.MANAGEMENT_OWNER
        ):
            # RAM
            self.device_controller.owner_pub_key = key_serialization.str_backto_key(
                new_ticket.holder_id, key_type="ecc-public-key"
            )

            # DB
            owner_public_key_byte = key_serialization.str_backto_byte(
                new_ticket.holder_id
            )
            self.device_controller.mSecureDB.store_owner_id(owner_public_key_byte)

        self.device_controller.display_state()

    def set_session_permission(self, new_ticket):
        pass

    ######################################################
    # Ticket Handshake
    #   +++ Execute Command Ticket (E-N) +++
    ######################################################
    def generate_session_key(
        self,
        server_private_key_obj: ec.EllipticCurvePrivateKey,
        salt_byte: bytes,
        info_byte: bytes,
        peer_public_key_obj: ec.EllipticCurvePublicKey,
    ) -> bytes:
        return ecdh.generate_ecdh_key(
            server_private_key=server_private_key_obj,
            salt=salt_byte,
            info=info_byte,
            peer_public_key=peer_public_key_obj,
        )

    def check_session_permission(self):
        pass

    def get_session_command(self):
        pass
