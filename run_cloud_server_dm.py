# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model
from typing import Optional
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket


class AgentOrServer:
    def __init__(self, device_name: str) -> None:
        # GIVEN: Uninitialized UA or CS
        self.agent_or_server = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name=device_name,
        )

        # THEN: Uninitialized UA or CS
        assert self.agent_or_server.shared_data.this_device.ticket_order == 0
        assert self.agent_or_server.shared_data.this_device.device_priv_key_str == None

    def intialize_agent_or_server_through_cli(self) -> None:
        # WHEN: Environment
        Environment.DEPLOYMENT_ENV = "TEST"

        # WHEN: Initialize UA or CS
        if self.agent_or_server.shared_data.this_device.ticket_order == 0:
            self.agent_or_server.executor._execute_one_time_intialize_agent_or_server()

        # THEN: Succeed to initialize UA or CS
        assert self.agent_or_server.shared_data.this_device.ticket_order == 1
        assert self.agent_or_server.shared_data.this_device.device_priv_key_str != None

    def intialize_device_through_bluetooth(self) -> None:
        # WHEN: Environment
        Environment.DEPLOYMENT_ENV = "PRODUCTION"

        # WHEN: Create connection with IoTD
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Issuer: DM's CS generate the intialization_u_ticket to herself
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.agent_or_server.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )

        # WHEN: Holder: DM's CS forward the intialization_u_ticket to Uninitialized IoTD
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            id_for_initialization_u_ticket
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in self.agent_or_server.shared_data.result_message

        # RE-GIVEN: Close Connection with IoTD
        self.agent_or_server.msg_sender.close_bluetooth_connection()


if __name__ == "__main__":
    try:
        # RE-GIVEN:
        SimpleStorage.delete_storage_in_test()

        # WHEN: Production Case
        cloud_server_dm = AgentOrServer(device_name="cloud_server_dm")
        cloud_server_dm.intialize_agent_or_server_through_cli()
        cloud_server_dm.intialize_device_through_bluetooth()

    except RuntimeError as error:
        simple_log("error", f"{error}")
