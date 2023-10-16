# Data Model (RAM)
from ureka_framework.model.shared_data import SharedData
from ureka_framework.model.data_model.other_device import OtherDevice

# Data Model (Message)
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import jsonstr_to_u_ticket

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log


class GeneratedMsgStorer:
    def __init__(self, shared_data: SharedData, simple_storage: SimpleStorage) -> None:
        self.shared_data = shared_data
        self.simple_storage = simple_storage

    ######################################################
    # [STAGE: (SG)] Store Generated Message
    ######################################################
    def _store_generated_xxx_u_ticket(self, generated_u_ticket_json: str) -> None:
        try:
            # [STAGE: (VR)]
            generated_u_ticket = jsonstr_to_u_ticket(generated_u_ticket_json)

            # Because device hasn't created the id yet,
            #   we temporary store Initialization UTicket in device_table["no_id"]
            #   and the device_table will be updated by its RTicket with newly-created device_id
            if generated_u_ticket.u_ticket_type == u_ticket.TYPE_INITIALIZATION_UTICKET:
                device_id_for_initialization_u_ticket = "no_id"
                self.shared_data.device_table[
                    device_id_for_initialization_u_ticket
                ] = OtherDevice(
                    device_id=device_id_for_initialization_u_ticket,
                    device_u_ticket=generated_u_ticket_json,
                )
            # TODO: RTN
            # Issuer can moreover store this UTicket so that can receive and verify RTicket from holder
            elif (
                generated_u_ticket.u_ticket_type == u_ticket.TYPE_OWNERSHIP_UTICKET
                or generated_u_ticket.u_ticket_type == u_ticket.TYPE_ACCESS_UTICKET
                or generated_u_ticket.u_ticket_type == u_ticket.TYPE_SELFACCESS_UTICKET
            ):
                # Not create new table, just add u_ticket to existing table
                device_id_for_u_ticket = generated_u_ticket.device_id
                self.shared_data.device_table[
                    device_id_for_u_ticket
                ].device_u_ticket = generated_u_ticket_json
            else:  # pragma: no cover -> Never reach here: Because of verify_ticket_type()
                failure_msg = f"Not implemented yet"
                simple_log("error", failure_msg)

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
