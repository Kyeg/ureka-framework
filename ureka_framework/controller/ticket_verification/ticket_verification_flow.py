import copy
import json
from returns.result import Result, Success, Failure
from ureka_framework.data_model.ticket import Ticket
import ureka_framework.data_model.ticket as ticket
import ureka_framework.resource.crypto.serialization_util as serialization_util
import ureka_framework.resource.crypto.ecc as ecc
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from typing import Union


class VerificationFlow:
    # Better not have side effect on device_controller
    def __init__(self, device_controller) -> None:
        self.device_controller = device_controller

    ######################################################
    # Message Verification Flow
    ######################################################
    def verify_ticket_schema(self, arbitrary_json: str) -> Success:
        success_msg = "-> SUCCESS: VERIFY_TICKET_SCHEMA"
        failure_msg = "-> FAILURE: VERIFY_TICKET_SCHEMA"

        try:
            ticket_in: Ticket = serialization_util.jsonstr_to_ticket(arbitrary_json)

            logging.info(success_msg)
            return Success(ticket_in)
        except RuntimeError as error:
            logging.error(f"{failure_msg}: {error}")
            return Failure(RuntimeError(f"{failure_msg}: {error}"))

    def verify_ticket_protocol_version(self, ticket_in: Ticket) -> Success:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_PROTOCOL_VERSION = {ticket_in.ticket_protocol_verision}"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_PROTOCOL_VERSION = {ticket_in.ticket_protocol_verision}"

        if ticket_in.ticket_protocol_verision == ticket.TICKET_PROTOCOL_VERSION:
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_ticket_type(self, ticket_in: Ticket) -> Success:
        success_msg = f"-> SUCCESS: VERIFY_TICKET_TYPE = {ticket_in.ticket_type}"
        failure_msg = f"-> FAILURE: VERIFY_TICKET_TYPE = {ticket_in.ticket_type}"

        if ticket_in.ticket_type in ticket.LEGAL_TICKET_TYPES:
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def verify_device_id(self, ticket_in: Ticket, device_pub_key_str: str) -> Success:
        success_msg = f"-> SUCCESS: VERIFY_DEVICE_ID = {ticket_in.device_id}"
        failure_msg = f"-> FAILURE: VERIFY_DEVICE_ID = {ticket_in.device_id}"

        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # No need to verify DEVICE_ID
            logging.info(success_msg)
            return Success(ticket_in)
        elif (
            ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET
            or ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET
        ):
            # No need to verify DEVICE_ID
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            if ticket_in.device_id == device_pub_key_str:
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))

    def verify_issuer_signature(
        self,
        ticket_in: Ticket,
        owner_pub_key: ec.EllipticCurvePrivateKey,
        current_holder_pub_key: ec.EllipticCurvePublicKey,
    ) -> Union[Success, Failure]:
        success_msg = (
            f"-> SUCCESS: VERIFY_ISSUER_SIGNATURE on {ticket_in.ticket_type} TICKET"
        )
        failure_msg = (
            f"-> FAILURE: VERIFY_ISSUER_SIGNATURE on {ticket_in.ticket_type} TICKET"
        )

        # (Z) Verify ISSUER_SIGNATURE
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # No need to verify ISSUER_SIGNATURE
            logging.info(success_msg)
            return Success(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            if self._verify_issuer_signature_on_ticket(ticket_in, owner_pub_key):
                # (Side Effect)
                self.device_controller.execute_update_current_holder_pub_key(
                    serialization_util.str_to_key(
                        ticket_in.holder_id, key_type="ecc-public-key"
                    )
                )
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                return Failure(RuntimeError(failure_msg))
        # (N) Verify HOLDER_SIGNATURE
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Need to check whether the CHALLENGE in the RESPONSE_TICKET is correct

            # Check the ticket holder is allowed by owner (in access permission ticket)
            if self.device_controller.current_holder_pub_key_str != ticket_in.holder_id:
                logging.error(failure_msg)
                logging.error("-> FAILURE: ERROR HOLDER_ID")
                return Failure(RuntimeError(failure_msg))

            # To-Do: Authenticate the ticket holder
            if self._verify_issuer_signature_on_ticket(
                ticket_in, current_holder_pub_key
            ):
                logging.info(success_msg)
                return Success(ticket_in)
            else:
                logging.error(failure_msg)
                logging.error("-> FAILURE: ERROR AUTHENTICATION")
                return Failure(RuntimeError(failure_msg))
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # To-Do: Return Ticket - to get DEVICE_ID after initialization
            logging.info(success_msg)
            return Success(ticket_in)
        else:
            # Never reach here: Because of verify_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

    def execute_ticket_operation(
        self, ticket_in: Ticket, device_priv_key: ec.EllipticCurvePrivateKey
    ) -> Union[Success, Failure]:
        failure_msg = f"-> FAILURE: WIRED TICKET TYPE {ticket_in.ticket_type}"

        # (E-Z) Execute TICKET
        if ticket_in.ticket_type == ticket.TYPE_INITIALIZATION_TICKET:
            # (Side Effect)
            result = self.device_controller.execute_one_time_initialize_iot_device(
                ticket_in
            )
        elif ticket_in.ticket_type == ticket.TYPE_MANAGEMENT_TICKET:
            # (Side Effect)
            result = self.device_controller.execute_ownership_transfer(ticket_in)
        elif ticket_in.ticket_type == ticket.TYPE_ACCESS_PERMISSION_TICKET:
            # To-Do: Auto-Generate Challenge Ticket
            result = Success(None)
        # (E-N) Execute TICKET
        elif ticket_in.ticket_type == ticket.TYPE_CHALLENGE_TICKET:
            # To-Do: Auto-Generate Response Ticket
            result = Success(None)
        elif ticket_in.ticket_type == ticket.TYPE_RESPONSE_TICKET:
            # To-Do: Auto-Generate Key Exchange Ticket
            result = Success(None)
        elif ticket_in.ticket_type == ticket.TYPE_KEY_EXCHANGE_TICKET:
            # (Side Effect)
            result = self.device_controller.execute_update_current_session_key_byte(
                server_private_key_obj=device_priv_key,
                salt_byte=serialization_util.str_to_byte(ticket_in.task_scope),
                info_byte=b"",
                peer_public_key_obj=serialization_util.str_to_key(
                    ticket_in.device_id, key_type="ecc-public-key"
                ),
            )
            # To-Do: Create Session
            # To-Do: Auto-Generate Command Ticket
        else:
            # Never reach here: Because of verify_ticket_type()
            logging.error(failure_msg)
            return Failure(RuntimeError(failure_msg))

        return result

    ######################################################
    # Verify ECC Signature on Ticket
    ######################################################
    def _verify_issuer_signature_on_ticket(
        self, signed_ticket: Ticket, public_key: ec.EllipticCurvePublicKey
    ) -> bool:
        try:
            # Get Signature on Ticket
            signature_byte = serialization_util.str_to_byte(
                signed_ticket.issuer_signature
            )

            # Verify Signature on Signed Ticket, but Prevent Side Effect on Signed Ticket
            unsigned_ticket = copy.deepcopy(signed_ticket)
            unsigned_ticket.issuer_signature = ""

            unsigned_ticket_str = serialization_util.ticket_to_jsonstr(unsigned_ticket)
            unsigned_ticket_byte = serialization_util.str_to_byte(unsigned_ticket_str)

            # Verify Signature
            return ecc.verify_signature(
                signature_byte, unsigned_ticket_byte, public_key
            )

        # To-Do: Test this case
        except AttributeError:
            logging.error("FAILURE: NO SIGNATURE")
            return False
