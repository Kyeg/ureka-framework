# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket


######################################################
# Test Fixtures
######################################################
def setup_production_environment():
    # RE-GIVEN: Reset the production environment
    SimpleStorage.delete_storage_in_test()


if __name__ == "__main__":
    Environment.DEPLOYMENT_ENV = "PRODUCTION"
    # Environment.DEPLOYMENT_ENV = "DEMO"

    setup_production_environment()

    try:
        # GIVEN: Initialized DM's CS
        cloud_server_dm = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
        )
        if cloud_server_dm.shared_data.this_device.ticket_order == 0:
            cloud_server_dm.executor._execute_one_time_intialize_agent_or_server()
        assert cloud_server_dm.shared_data.this_device.ticket_order == 1
        assert cloud_server_dm.shared_data.this_device.device_priv_key_str != None

        # GIVEN: Bluetooth Service Lifecycle: Connect New Connection
        cloud_server_dm.msg_sender.connect_bluetooth_comm()

        # WHEN: Issuer: DM's CS generate the intialization_u_ticket to herself
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )

        # WHEN: Bluetooth Service Lifecycle: Send U-Ticket in Connection
        # WHEN: Holder: DM's CS forward the intialization_u_ticket to Uninitialized IoTD
        cloud_server_dm.flow_apply_u_ticket.holder_apply_u_ticket(
            id_for_initialization_u_ticket
        )

        # WHEN: Bluetooth Service Lifecycle: Receive R-Ticket & Send U-Ticket in Connection
        cloud_server_dm.msg_receiver._recv_xxx_message()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in cloud_server_dm.shared_data.result_message

        # RE-GIVEN: Bluetooth Service Lifecycle: Close Connection
        cloud_server_dm.msg_sender.close_bluetooth_connection()

    except RuntimeError as error:
        simple_log("error", f"{error}")
