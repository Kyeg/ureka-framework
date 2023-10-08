# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from ureka_framework.model.data_model.other_device import OtherDevice

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import (
    UTicket,
    u_ticket_to_jsonstr,
)
import ureka_framework.model.message_model.r_ticket as r_ticket
from ureka_framework.model.message_model.r_ticket import (
    RTicket,
    r_ticket_to_jsonstr,
)

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log


class ReceivedMsgStorer:
    def __init__(self, shared_data: SharedData, simple_storage: SimpleStorage) -> None:
        self.shared_data = shared_data
        self.simple_storage = simple_storage

    ######################################################
    # [STAGE: (SR)] Store Received Message
    ######################################################
    def _store_received_xxx_u_ticket(self, received_u_ticket: UTicket) -> None:
        try:
            received_u_ticket_json = u_ticket_to_jsonstr(received_u_ticket)

            # We store this UTicket in device_table["device_id"]
            if (
                received_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or received_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
            ):
                self.shared_data.device_table[
                    received_u_ticket.device_id
                ] = OtherDevice(
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
                self.shared_data.this_device,
                self.shared_data.device_table,
                self.shared_data.this_person,
                self.shared_data.current_session,
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (VR)
            failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)

    def _store_received_xxx_r_ticket(self, received_r_ticket: RTicket) -> None:
        try:
            received_r_ticket_json = r_ticket_to_jsonstr(received_r_ticket)

            # We store this RTicket (but not verified) in device_table["device_id"]
            if received_r_ticket.r_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                # Create new table by newly-created device public key
                created_device_id = received_r_ticket.device_id
                # Put u_ticket (temporary in device_table["no_id"]) & r_ticket in device_table["created_device_id"]
                self.shared_data.device_table[created_device_id] = OtherDevice(
                    device_id=created_device_id,
                    device_u_ticket=self.shared_data.device_table[
                        "no_id"
                    ].device_u_ticket,
                    device_r_ticket=received_r_ticket_json,
                )
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET:
                # Not create new table, just add r_ticket to existing table
                self.shared_data.device_table[
                    received_r_ticket.device_id
                ].device_r_ticket = received_r_ticket_json
            elif received_r_ticket.r_ticket_type == u_ticket.TYPE_TX_END_UTOKEN:
                # Not create new table, just add r_ticket to existing table
                self.shared_data.device_table[
                    received_r_ticket.device_id
                ].device_r_ticket = received_r_ticket_json
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                simple_log("error", "weird ticket type")

            ######################################################
            # Storage
            ######################################################
            self.simple_storage.store_storage(
                self.shared_data.this_device,
                self.shared_data.device_table,
                self.shared_data.this_person,
                self.shared_data.current_session,
            )

        except RuntimeError:  # pragma: no cover -> FAILURE: (VR)
            failure_msg = f"FAILURE: (VR): classify_message_is_defined_type"
            simple_log("error", failure_msg)

        except:  # pragma: no cover -> Unpredicted Error
            failure_msg = f"FAILURE: UNPREDICTED ERROR"
            simple_log("error", failure_msg)
