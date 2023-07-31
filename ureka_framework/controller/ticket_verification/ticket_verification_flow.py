from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
import ureka_framework.resource.crypto.key_serialization as key_serialization
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class VerificationFlow:
    # Better not have side effect on device_controller
    def __init__(self, device_controller) -> None:
        self.device_controller = device_controller

    ######################################################
    # Verification Flow
    ######################################################
    def verify_ticket_protocol_verision(self, ticket_in: Ticket) -> None:
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
            # return

    def verify_ticket_type(self, ticket_in: Ticket) -> None:
        # (Z-2) Classify TICKET_TYPE
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            logging.debug("(Z-2) PASS: TYPE_INITIALIZATION_TICKET")

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
        else:
            logging.debug("(Z-2) ERROR: WRONG_TICKET_TYPE")
            # return

    def verify_device_id(self, ticket_in: Ticket, device_pub_key_str: str) -> None:
        # (Z-3) Classify DEVICE_ID
        if (
            ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET
            or ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET
        ):
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(Z-3) PASS: DEVICE_ID")
        elif ticket_in.ticket_type != ticket.TYPE_INITIALIZATION_TICKET:
            if ticket_in.device_id == device_pub_key_str:
                logging.debug("(Z-3) PASS: DEVICE_ID")
            else:
                logging.debug("(Z-3) ERROR: DEVICE_ID")
                # return

    def verify_issuer_signature(
        self,
        ticket_in: Ticket,
        owner_pub_key: ec.EllipticCurvePrivateKey,
        current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> None:
        # (Z-4) Verify ISSUER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                logging.debug("(Z-4) PASS: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
            else:
                logging.debug("(Z-4) ERROR: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
                # return

        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                # (Side Effect)
                self.device_controller.execute_update_current_holder_pub_key(
                    key_serialization.str_backto_key(
                        ticket_in.holder_id, key_type="ecc-public-key"
                    )
                )
                logging.debug(
                    "(Z-4) PASS: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET"
                )
            else:
                logging.debug(
                    "(Z-4) ERROR: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET"
                )
                # return

        # (N) Verify HOLDER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(N-2) PASS: ISSUER_SIGNATURE on CHALLENGE_TICKET")

        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESONSE_TICKET is correct
            if self._verify_issuer_signature_on_ticket(
                ticket_in, current_holder_pub_key
            ):
                logging.debug("(N-3) PASS: ISSUER_SIGNATURE on RESPONSE_TICKET")
            else:
                logging.debug("(N-3) ERROR: ISSUER_SIGNATURE on RESPONSE_TICKET")
                # return

        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.debug("(N-4) PASS: ISSUER_SIGNATURE on KEY_EXCHANGE_TICKET")

    def execute_ticket_operation(
        self, ticket_in: Ticket, device_priv_key: ec.EllipticCurvePrivateKey
    ) -> None:
        # (E-Z) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            logging.debug("(E-Z) EXECUTE: INITIALIZATION_TICKET")
            # (Side Effect)
            self.device_controller.execute_initialize_iot_device(ticket_in)

        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            logging.debug("(E-Z) EXECUTE: MANAGEMENT_TICKET")
            # (Side Effect)
            self.device_controller.execute_ownership_transfer(ticket_in)

        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            logging.debug("(E-Z) EXECUTE: ACCESS_PERMISSION_TICKET")
            # To-Do: Session
            # To-Do: Auto-Generate Challenge Ticket
            logging.debug("generate_challenge_ticket( )...")

        # (E-N) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            logging.debug("(E-N) EXECUTE: CHALLENGE_TICKET")
            # To-Do: Auto-Generate Response Ticket

        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            logging.debug("(E-N) EXECUTE: RESONSE_TICKET")
            # To-Do: Auto-Generate Key Exchange Ticket

        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            logging.debug("(E-N) EXECUTE: KEY_EXCHANGE_TICKET")
            # Generate (temp) session_key (Side Effect)
            self.device_controller.execute_update_current_session_key_byte(
                server_private_key_obj=device_priv_key,
                salt_byte=key_serialization.str_backto_byte(ticket_in.task_scope),
                info_byte=b"",
                peer_public_key_obj=key_serialization.str_backto_key(
                    ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            # To-Do: Auto-Generate Command Ticket
            # To-Do: Session

    ######################################################
    # Verify ECC Signature on Ticket
    ######################################################
    def _verify_issuer_signature_on_ticket(
        self, ticket_in: Ticket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        try:
            # Get Signature on Ticket
            signature_byte = key_serialization.str_backto_byte(
                ticket_in.issuer_signature
            )

            # No need to del issuer_signature in dataclass
            ticket_in.issuer_signature = ""

            message_str = key_serialization.ticket_to_jsonstr(ticket_in)
            message_byte = key_serialization.str_to_byte(message_str)

            # Verify Signature
            return ecc.verify_signature(signature_byte, message_byte, public_key)

        except AttributeError:
            logging.debug("ERROR: NO SIGNATURE")
            return False
