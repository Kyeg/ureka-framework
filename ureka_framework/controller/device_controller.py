import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.resource.storage.secure_db as secure_db
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
import ureka_framework.resource.crypto.key_serialization as key_serialization
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class DeviceController:
    def __init__(
        self, device_type: str = "", device_name: str = "", db_path: str = ""
    ) -> None:
        # Device Type (Device can be Private Autenticator or IoT Device...)
        self.device_type: str = device_type
        self.device_name: str = device_name

        # False: Uninitialized / True: Initialized
        self.is_initialized: bool = False
        self.device_priv_key: ec.EllipticCurvePrivateKey = None
        self.device_pub_key: ec.EllipticCurvePublicKey = None
        self.owner_pub_key: ec.EllipticCurvePublicKey = None

        # Current Session (RAM-only)
        self.current_holder_pub_key: ec.EllipticCurvePublicKey = None
        self.current_session_key_byte: bytes = None

        # +++ Load SecureDB +++
        self.mSecureDB = secure_db.SecureDB(db_path=db_path)
        (
            self.is_initialized,
            self.device_priv_key,
            self.device_pub_key,
            self.owner_pub_key,
        ) = self.mSecureDB.load_secure_db()

        if self.is_initialized:
            logging.debug(
                "+++ Device controller <%s> was initailized +++" % device_name
            )
            self.display_state()
        else:
            logging.debug(
                "+++ Device controller <%s> was uninitailized +++" % device_name
            )

    @property
    def device_priv_key_str(self) -> str:
        if self.device_priv_key is None:
            return ""
        return key_serialization.key_to_str(
            self.device_priv_key, key_type="ecc-private-key"
        )

    @property
    def device_pub_key_str(self) -> str:
        if self.device_pub_key is None:
            return ""
        return key_serialization.key_to_str(
            self.device_pub_key, key_type="ecc-public-key"
        )

    @property
    def owner_pub_key_str(self) -> str:
        if self.owner_pub_key is None:
            return ""
        return key_serialization.key_to_str(
            self.owner_pub_key, key_type="ecc-public-key"
        )

    ######################################################
    # Display (Debug/Test)
    ######################################################
    def display_state(self) -> None:
        if self.device_type == ticket.USER_AGENT_OR_CLOUD_SERVER:
            logging.debug("#" * 100)
            logging.debug("device_type: %s" % self.device_type)
            logging.debug("")
            logging.debug("device_priv_key_str: %s" % self.device_priv_key_str[0:64])
            logging.debug("device_pub_key_str: %s" % self.device_pub_key_str[0:64])
            logging.debug("#" * 100)

        if self.device_type == ticket.IOT_DEVICE:
            logging.debug("#" * 100)
            logging.debug("device_type: %s" % self.device_type)
            logging.debug("")
            logging.debug("device_priv_key_str: %s" % self.device_priv_key_str[0:64])
            logging.debug("device_pub_key_str: %s" % self.device_pub_key_str[0:64])
            logging.debug("")
            logging.debug("owner_pub_key_str: %s" % self.owner_pub_key_str[0:64])
            logging.debug("#" * 100)

    ######################################################
    # Generate Different Ticket Types
    ######################################################
    def generate_initialization_ticket(self, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_INITIALIZATION_TICKET
        # no device_id
        new_ticket.holder_id = holder_id

        return new_ticket

    def generate_query_ticket(self):
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_QUERY_TICKET

        return new_ticket

    def generate_management_ticket(
        self, device_id: str, holder_id: str, task_scope: str
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_MANAGEMENT_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self.add_issuer_signature_on_ticket(
            new_ticket, self.device_priv_key
        )

        return new_ticket

    # Similar format with management_ticket
    def generate_access_permission_ticket(
        self, device_id: str, holder_id: str, task_scope: str
    ) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_ACCESS_PERMISSION_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id
        new_ticket.task_scope = task_scope

        new_ticket = self.add_issuer_signature_on_ticket(
            new_ticket, self.device_priv_key
        )

        return new_ticket

    # Similar format with access_permission_ticket
    def generate_challenge_ticket(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_CHALLENGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Challenge
        random_challenge = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_challenge)

        new_ticket = self.add_issuer_signature_on_ticket(
            new_ticket, self.device_priv_key
        )

        return new_ticket

    # Similar format with access_permission_ticket
    def generate_response_ticket(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_RESPONSE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        new_ticket = self.add_issuer_signature_on_ticket(
            new_ticket, self.device_priv_key
        )

        return new_ticket

    # Similar format with access_permission_ticket
    def generate_key_exchange_ticket(self, device_id: str, holder_id: str) -> Ticket:
        new_ticket = ticket.Ticket()

        new_ticket.ticket_type = ticket.TYPE_KEY_EXCHANGE_TICKET
        new_ticket.device_id = device_id
        new_ticket.holder_id = holder_id

        # Random Salt
        random_salt = ecdh.generate_random_byte(32)
        new_ticket.task_scope = key_serialization.byte_to_str(random_salt)

        new_ticket = self.add_issuer_signature_on_ticket(
            new_ticket, self.device_priv_key
        )

        # Generate (temp) session_key
        self.current_session_key_byte = self.generate_session_key(
            server_private_key_obj=self.device_priv_key,
            salt_byte=random_salt,
            info_byte=b"",
            peer_public_key_obj=key_serialization.str_backto_key(
                holder_id, key_type="ecc-public-key"
            ),
        )
        logging.debug("current_session_key_byte: " + str(self.current_session_key_byte))

        return new_ticket

    # Similar format with access_permission_ticket
    def generate_command_ticket(self, device_id, holder_id, task_scope):
        pass

    def generate_return_ticket(self):
        # Query Ticket: Return Device_ID
        # Initialization Ticket: Return Device_ID

        # Command Ticket: Return Data

        pass

    ######################################################
    # Verify Different Ticket Types
    ######################################################
    def verify_xxx_ticket(self, ticket_in: Ticket) -> None:
        # (Z-1) Verify TICKET_PROTOCOL_VERSION
        if ticket_in.ticket_protocol_verision == ticket.TICKET_PROTOCOL_VERSION:
            logging.debug(
                "(Z-1) PASS: TICKET_PROTOCOL_VERSION"
                + " ("
                + ticket.TICKET_PROTOCOL_VERSION
                + ") "
            )
        else:
            logging.debug("(Z-1) ERROR: TICKET_PROTOCOL_VERSION")
            return

        # (Z-2) Classify TICKET_TYPE
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            logging.debug("(Z-2) PASS: TYPE_INITIALIZATION_TICKET")

        elif ticket_in.ticket_type == ticket.TYPE_QUERY_TICKET:
            logging.debug("(Z-2) PASS: TYPE_QUERY_TICKET")

        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            logging.debug("(Z-2) PASS: TYPE_MANAGEMENT_TICKET")

        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            logging.debug("(Z-2) PASS: TYPE_ACCESS_PERMISSION_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            logging.debug("(Z-2) PASS: TYPE_CHALLENGE_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            logging.debug("(Z-2) PASS: TYPE_RESONSE_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            logging.debug("(Z-2) PASS: TYPE_KEY_EXCHANGE_TICKET")
        # elif (ticket_in.ticket_type == ticket.TYPE_COMMAND_TICKET):
        #     logging.debug('(Z-2) PASS: TYPE_COMMAND_TICKET')

        # elif (ticket_in.ticket_type == ticket.TYPE_RETURN_TICKET):
        #     logging.debug('(Z-2) PASS: TYPE_RETURN_TICKET')

        else:
            logging.debug("(Z-2) ERROR: WRONG_TICKET_TYPE")
            return

        # (Z-3) Classify DEVICE_ID
        if (
            ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET
            or ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET
        ):
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(Z-3) PASS: DEVICE_ID")
        elif (
            ticket_in.ticket_type != ticket.TYPE_INITIALIZATION_TICKET
            and ticket_in.ticket_type != ticket.TYPE_QUERY_TICKET
        ):
            if ticket_in.device_id == self.device_pub_key_str:
                logging.debug("(Z-3) PASS: DEVICE_ID")
            else:
                logging.debug("(Z-3) ERROR: DEVICE_ID")
                return

        # (Z-4) Verify ISSUER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            if self.verify_issuer_signature_on_ticket(ticket_in, self.owner_pub_key):
                logging.debug("(Z-4) PASS: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
            else:
                logging.debug("(Z-4) ERROR: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
                return

        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            if self.verify_issuer_signature_on_ticket(ticket_in, self.owner_pub_key):
                self.current_holder_pub_key = key_serialization.str_backto_key(
                    ticket_in.holder_id, key_type="ecc-public-key"
                )
                logging.debug(
                    "(Z-4) PASS: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET"
                )
            else:
                logging.debug(
                    "(Z-4) ERROR: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET"
                )
                return

        # (N) Verify HOLDER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(N-2) PASS: ISSUER_SIGNATURE on CHALLENGE_TICKET")

        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESONSE_TICKET is correct
            if self.verify_issuer_signature_on_ticket(
                ticket_in, self.current_holder_pub_key
            ):
                logging.debug("(N-3) PASS: ISSUER_SIGNATURE on RESONSE_TICKET")
            else:
                logging.debug("(N-3) ERROR: ISSUER_SIGNATURE on RESONSE_TICKET")
                return

        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(N-4) PASS: ISSUER_SIGNATURE on KEY_EXCHANGE_TICKET")

        # (E-Z) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            logging.debug("(E-Z) EXECUTE: INITIALIZATION_TICKET")

            logging.debug("initialize_iot_device( )...")

            self.initialize_iot_device(ticket_in)

        elif ticket_in.ticket_type == ticket.TYPE_QUERY_TICKET:
            logging.debug("(E-Z) EXECUTE: QUERY_TICKET")
            self.query()

        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            logging.debug("(E-Z) EXECUTE: MANAGEMENT_TICKET")

            logging.debug("ownership_transfer( )...")

            self.ownership_transfer(ticket_in)

        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            logging.debug("(E-Z) EXECUTE: ACCESS_PERMISSION_TICKET")

            # To-Do: Session
            # logging.debug ("set_session_permission( )...")

            logging.debug("generate_challenge_ticket( )...")

        # (E-N) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            logging.debug("(E-N) EXECUTE: CHALLENGE_TICKET")

            logging.debug("generate_response_ticket( )...")

        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            logging.debug("(E-N) EXECUTE: RESONSE_TICKET")

            logging.debug("generate_key_exchange_ticket( )...")

        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            logging.debug("(E-N) EXECUTE: KEY_EXCHANGE_TICKET")

            # Generate (temp) session_key
            self.current_session_key_byte = self.generate_session_key(
                server_private_key_obj=self.device_priv_key,
                salt_byte=key_serialization.str_backto_byte(ticket_in.task_scope),
                info_byte=b"",
                peer_public_key_obj=key_serialization.str_backto_key(
                    ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            logging.debug(
                "current_session_key_byte: " + str(self.current_session_key_byte)
            )

            logging.debug("generate_command_ticket( )...")

            # To-Do: Session
            # logging.debug ("check_session_permission( )...")
            # logging.debug ("get_session_command( )...")

        # (AC) Return ticket

    ######################################################
    # Add ECC Signature on Ticket
    #   ticket_in: Ticket
    #
    #   return: Ticket
    ######################################################
    def add_issuer_signature_on_ticket(
        self, ticket_in: Ticket, private_key: ec.EllipticCurvePrivateKey
    ) -> Ticket:
        # Message
        message_str = key_serialization.ticket_to_jsonstr(ticket_in)
        message_byte = key_serialization.str_to_byte(message_str)

        # Sign Signature
        signature_byte = ecc.sign_signature(message_byte, private_key)

        # Add Signature on Ticket
        ticket_with_signature = ticket_in
        ticket_with_signature.issuer_signature = key_serialization.byte_to_str(
            signature_byte
        )

        return ticket_with_signature

    ######################################################
    # Sign ECC Signature on Ticket
    #   ticket_in: Ticket
    #
    #   return: True/False
    ######################################################
    def verify_issuer_signature_on_ticket(
        self, ticket_in: Ticket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        try:
            # Get Signature on Ticket
            signature_byte = key_serialization.str_backto_byte(
                ticket_in.issuer_signature
            )

            # # Message = Remove Signature on Ticket
            # # Notice that we cannot simply set signature = '', but need to 'delete' the signature variable in object
            # del (
            #     ticket_in.issuer_signature
            # )  # == ticket_in.__dict__.pop('issuer_signature')

            # No need to del issuer_signature in dataclass
            ticket_in.issuer_signature = ""

            message_str = key_serialization.ticket_to_jsonstr(ticket_in)
            message_byte = key_serialization.str_to_byte(message_str)

            # Verify Signature
            return ecc.verify_signature(signature_byte, message_byte, public_key)

        except AttributeError:
            logging.debug("ERROR: NO SIGNATURE")
            return False

    ######################################################
    # Ticket Handshake
    #   +++ Execute xxxTicket (E-Z) +++
    ######################################################
    def initialize_iot_device(self, new_ticket: Ticket) -> bool:
        if self.device_type != ticket.IOT_DEVICE:
            logging.debug("ERROR: ONLY IOT_DEVICE CAN DO THIS OPERATION")
            return False

        if self.is_initialized:
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
        self.is_initialized = True
        self.device_priv_key = key_serialization.byte_backto_key(
            device_private_key_byte, key_type="ecc-private-key"
        )
        self.device_pub_key = key_serialization.byte_backto_key(
            device_public_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.mSecureDB.store_device_id(device_private_key_byte, device_public_key_byte)

        ######################################################
        # Update Permission Table (only for IoT Device)
        ######################################################

        # RAM
        self.owner_pub_key = key_serialization.str_backto_key(new_ticket.holder_id)

        # DB
        owner_public_key_byte = key_serialization.str_backto_byte(new_ticket.holder_id)
        self.mSecureDB.store_owner_id(owner_public_key_byte)

        self.display_state()
        return True

    def query(self):
        logging.debug("device_pub_key_str: %s" % self.device_pub_key_str[0:64])
        logging.debug("owner_pub_key_str: %s" % self.owner_pub_key_str[0:64])

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
            self.owner_pub_key = key_serialization.str_backto_key(
                new_ticket.holder_id, key_type="ecc-public-key"
            )

            # DB
            owner_public_key_byte = key_serialization.str_backto_byte(
                new_ticket.holder_id
            )
            self.mSecureDB.store_owner_id(owner_public_key_byte)

        self.display_state()

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

    ######################################################
    # Initilize User Agent or Cloud Server (without using Ticket)
    ######################################################
    def one_time_intialization_command(self) -> bool:
        if self.device_type != ticket.USER_AGENT_OR_CLOUD_SERVER:
            logging.debug(
                "ERROR: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS OPERATION"
            )
            return False

        if self.is_initialized:
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
        self.is_initialized = True
        self.device_priv_key = key_serialization.byte_backto_key(
            device_private_key_byte, key_type="ecc-private-key"
        )
        self.device_pub_key = key_serialization.byte_backto_key(
            device_public_key_byte, key_type="ecc-public-key"
        )

        # DB
        self.mSecureDB.store_device_id(device_private_key_byte, device_public_key_byte)

        self.display_state()
        return True

    ######################################################
    # Reset Device (Teardown - Development Only Function)
    ######################################################
    def reset_device(self) -> bool:
        self.mSecureDB.delete_secure_db()
        return True
