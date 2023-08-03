from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
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
        # Verify TICKET_PROTOCOL_VERSION
        if ticket_in.ticket_protocol_verision == ticket.TICKET_PROTOCOL_VERSION:
            logging.info("-> SUCCESS: TICKET_PROTOCOL_VERSION")
        else:
            logging.error("-> FAILURE: TICKET_PROTOCOL_VERSION")
            # return

    def verify_ticket_type(self, ticket_in: Ticket) -> None:
        # Classify TICKET_TYPE
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            logging.info("-> SUCCESS: TYPE_INITIALIZATION_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            logging.info("-> SUCCESS: TYPE_MANAGEMENT_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            logging.info("-> SUCCESS: TYPE_ACCESS_PERMISSION_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            logging.info("-> SUCCESS: TYPE_CHALLENGE_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            logging.info("-> SUCCESS: TYPE_RESPONSE_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            logging.info("-> SUCCESS: TYPE_KEY_EXCHANGE_TICKET")
        else:
            logging.error("-> FAILURE: TICKET_TYPE")
            # return

    def verify_device_id(self, ticket_in: Ticket, device_pub_key_str: str) -> None:
        # Classify DEVICE_ID
        if (
            ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET
            or ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET
        ):
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info("-> SUCCESS: DEVICE_ID")
        elif ticket_in.ticket_type != ticket.TYPE_INITIALIZATION_TICKET:
            if ticket_in.device_id == device_pub_key_str:
                logging.info("-> SUCCESS: DEVICE_ID")
            else:
                logging.error("-> FAILURE: DEVICE_ID")
                # return

    def verify_issuer_signature(
        self,
        ticket_in: Ticket,
        owner_pub_key: ec.EllipticCurvePrivateKey,
        current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> None:
        # Verify ISSUER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                logging.info("-> SUCCESS: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
            else:
                logging.error("-> FAILURE: ISSUER_SIGNATURE on MANAGEMENT_TICKET")
                # return
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                # (Side Effect)
                self.device_controller.execute_update_current_holder_pub_key(
                    serialization_util.str_to_key(
                        ticket_in.holder_id, key_type="ecc-public-key"
                    )
                )
                logging.info("-> SUCCESS: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET")
            else:
                logging.error(
                    "-> FAILURE: ISSUER_SIGNATURE on ACCESS_PERMISSION_TICKET"
                )
                # return

        # (N) Verify HOLDER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info("-> SUCCESS: ISSUER_SIGNATURE on CHALLENGE_TICKET")
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESPONSE_TICKET is correct
            if self._verify_issuer_signature_on_ticket(
                ticket_in, current_holder_pub_key
            ):
                logging.info("-> SUCCESS: ISSUER_SIGNATURE on RESPONSE_TICKET")
            else:
                logging.error("-> FAILURE: ISSUER_SIGNATURE on RESPONSE_TICKET")
                # return
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info("-> SUCCESS: ISSUER_SIGNATURE on KEY_EXCHANGE_TICKET")

    def execute_ticket_operation(
        self, ticket_in: Ticket, device_priv_key: ec.EllipticCurvePrivateKey
    ) -> None:
        # (E-Z) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # (Side Effect)
            self.device_controller.execute_initialize_iot_device(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            # (Side Effect)
            self.device_controller.execute_ownership_transfer(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            # To-Do: Auto-Generate Challenge Ticket
            pass

        # (E-N) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Auto-Generate Response Ticket
            pass
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Auto-Generate Key Exchange Ticket
            pass
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # (Side Effect)
            self.device_controller.execute_update_current_session_key_byte(
                server_private_key_obj=device_priv_key,
                salt_byte=serialization_util.str_to_byte(ticket_in.task_scope),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            # To-Do: Create Session
            # To-Do: Auto-Generate Command Ticket

    ######################################################
    # Verify ECC Signature on Ticket
    ######################################################
    def _verify_issuer_signature_on_ticket(
        self, ticket_in: Ticket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        try:
            # Get Signature on Ticket
            signature_byte = serialization_util.str_to_byte(ticket_in.issuer_signature)

            # No need to del issuer_signature in dataclass
            ticket_in.issuer_signature = ""

            message_str = serialization_util.ticket_to_jsonstr(ticket_in)
            message_byte = serialization_util.str_to_byte(message_str)

            # Verify Signature
            return ecc.verify_signature(signature_byte, message_byte, public_key)

        except AttributeError:
            logging.error("FAILURE: NO SIGNATURE")
            return False
