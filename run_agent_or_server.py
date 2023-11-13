# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model
from typing import Optional, Tuple
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr

# Simulated Communication
from tests.conftest import create_comm_connection, wait_comm_completed


class MenuAgentOrServer:
    def __init__(self, device_name: str) -> None:
        # GIVEN: Uninitialized UA or CS
        self.agent_or_server = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name=device_name,
        )

    def get_agent_or_server(self) -> DeviceController:
        return self.agent_or_server

    def get_target_device_id(self) -> str:
        # For complicated case, show a device list and let user choose
        # show_device_list()...
        # input()...

        # For simple case, just return the first device id
        return list(self.agent_or_server.shared_data.device_table.keys())[0]

    def intialize_agent_or_server_through_cli(self) -> DeviceController:
        # WHEN: Initialize UA or CS
        if self.agent_or_server.shared_data.this_device.ticket_order == 0:
            self.agent_or_server.executor._execute_one_time_intialize_agent_or_server()

        return self.agent_or_server

    def apply_initialization_ticket_through_bluetooth(self) -> DeviceController:
        # WHEN: Create connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
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
        #       & RE-GIVEN: Close Connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_receiver._recv_xxx_message()

        return self.agent_or_server

    def issue_ownership_ticket_through_simulated_comm(
        self, target_device_id: str, user_agent_do: DeviceController
    ) -> None:
        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_comm_connection(self.agent_or_server, user_agent_do)
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{user_agent_do.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(user_agent_do, self.agent_or_server)

    def apply_ownership_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Create connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the ownership_u_ticket to IoTD
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(target_device_id)
        # WHEN: Receive/Send Message in Connection
        #       & RE-GIVEN: Close Connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_receiver._recv_xxx_message()

        return self.agent_or_server

    def issue_access_ticket_through_simulated_comm(
        self, target_device_id: str, cloud_server_ep: DeviceController
    ) -> None:
        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_comm_connection(self.agent_or_server, cloud_server_ep)
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(cloud_server_ep, self.agent_or_server)

    def apply_access_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Create connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-1"
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        #       & RE-GIVEN: Close Connection with IoTD (Finish CR-KE~~)
        self.agent_or_server.msg_receiver._recv_xxx_message()

        return self.agent_or_server

    def apply_cmd_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Create connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-2"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        #       & RE-GIVEN: Close Connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_receiver._recv_xxx_message()

        return self.agent_or_server

    def apply_access_end_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Create connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "ACCESS_END"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command, access_end=True
        )
        # WHEN: Receive/Send Message in Connection
        #       & RE-GIVEN: Close Connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_receiver._recv_xxx_message()

        return self.agent_or_server


if __name__ == "__main__":
    try:
        # ENVIRONMENT
        Environment.DEPLOYMENT_ENV = "PRODUCTION"

        ######################################################

        # # RE-GIVEN:
        # SimpleStorage.delete_storage_in_test()

        # # GIVEN: Uninitialized DM's CS
        # menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")

        # # WHEN: DM's CS initialize UA or CS
        # cloud_server_dm = menu_cloud_server_dm.intialize_agent_or_server_through_cli()

        # # THEN: Succeed to initialize UA or CS
        # assert cloud_server_dm.shared_data.this_device.ticket_order == 1
        # assert cloud_server_dm.shared_data.this_device.device_priv_key_str != None

        ######################################################

        # # GIVEN: Initialized DM's CS
        # menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        # cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

        # # WHEN: Holder: DM's CS apply the initialization_u_ticket to IoTD
        # cloud_server_dm = (
        #     menu_cloud_server_dm.apply_initialization_ticket_through_bluetooth()
        # )

        # # THEN: Succeed to initialize DM's IoTD
        # assert "SUCCESS" in cloud_server_dm.shared_data.result_message

        ######################################################

        # # GIVEN: Initialized DM's CS
        # menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        # cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
        # # GIVEN: Initialized DO's UA
        # menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        # user_agent_do = menu_user_agent_do.intialize_agent_or_server_through_cli()

        # # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        # target_device_id = menu_cloud_server_dm.get_target_device_id()
        # menu_cloud_server_dm.issue_ownership_ticket_through_simulated_comm(
        #     target_device_id=target_device_id,
        #     user_agent_do=user_agent_do,
        # )
        # # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        # target_device_id = menu_user_agent_do.get_target_device_id()
        # user_agent_do = menu_user_agent_do.apply_ownership_ticket_through_bluetooth(
        #     target_device_id=target_device_id
        # )

        # # THEN: Succeed to transfer ownership (& update ticket_order of DO's IoTD)
        # assert "SUCCESS" in user_agent_do.shared_data.result_message

        ######################################################

        # GIVEN: Initialized DO's UA
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        user_agent_do = menu_user_agent_do.get_agent_or_server()
        # GIVEN: Initialized EP's CS
        menu_cloud_server_ep = MenuAgentOrServer(device_name="cloud_server_ep")
        cloud_server_ep = menu_cloud_server_ep.intialize_agent_or_server_through_cli()

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        target_device_id = menu_user_agent_do.get_target_device_id()
        menu_user_agent_do.issue_access_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            cloud_server_ep=cloud_server_ep,
        )
        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        target_device_id = menu_cloud_server_ep.get_target_device_id()
        cloud_server_ep = menu_cloud_server_ep.apply_access_ticket_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: Succeed to allow EP's CS to limitedly access DO's IoTD
        assert "SUCCESS" in cloud_server_ep.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            cloud_server_ep.shared_data.current_session.plaintext_data
            == "DATA: " + cloud_server_ep.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: EP's CS cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        target_device_id = menu_cloud_server_ep.get_target_device_id()
        cloud_server_ep = menu_cloud_server_ep.apply_cmd_token_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: Succeed to allow EP's CS to limitedly access DO's IoTD
        assert "SUCCESS" in cloud_server_ep.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            cloud_server_ep.shared_data.current_session.plaintext_data
            == "DATA: " + cloud_server_ep.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: EP's CS cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        target_device_id = menu_cloud_server_ep.get_target_device_id()
        original_agent_order = cloud_server_ep.shared_data.device_table[
            target_device_id
        ].ticket_order
        cloud_server_ep = menu_cloud_server_ep.apply_access_end_token_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in cloud_server_ep.shared_data.result_message
        assert (
            cloud_server_ep.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

        ######################################################

    except RuntimeError as error:
        simple_log("error", f"{error}")
