# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# Data Model (Message)
import json

# Data Model (RAM)
from typing import Optional, Tuple
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr

# Simulated Communication
from tests.conftest import (
    create_simulated_comm_connection,
    wait_simulated_comm_completed,
)


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
        # WHEN: Connect bluetooth connection with IoTD
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
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def issue_ownership_ticket_through_simulated_comm(
        self, target_device_id: str, user_agent_do: DeviceController
    ) -> None:
        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(self.agent_or_server, user_agent_do)
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{user_agent_do.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_simulated_comm_completed(user_agent_do, self.agent_or_server)

    def apply_ownership_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the ownership_u_ticket to IoTD
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(target_device_id)
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish UT-RT~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_self_access_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Issuer: DM's CS generate the self_access_u_ticket to herself
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.agent_or_server.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_SELFACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.agent_or_server.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )

        # WHEN: Holder: DM's CS forward the self_access_u_ticket to Uninitialized IoTD
        generated_command = "HELLO-1"
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CR-KE~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def issue_access_ticket_through_simulated_comm(
        self, target_device_id: str, cloud_server_ep: DeviceController
    ) -> None:
        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(self.agent_or_server, cloud_server_ep)
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
        wait_simulated_comm_completed(cloud_server_ep, self.agent_or_server)

    def apply_access_ticket_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-1"
        self.agent_or_server.flow_apply_u_ticket.holder_apply_u_ticket(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CR-KE~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_cmd_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "HELLO-2"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def apply_access_end_token_through_bluetooth(
        self, target_device_id: str
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        generated_command = "ACCESS_END"
        self.agent_or_server.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command, access_end=True
        )
        # WHEN: Receive/Send Message in Connection
        self.agent_or_server.msg_receiver._recv_xxx_message()

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish PS~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server

    def return_r_ticket_through_simulated_comm(
        self, target_device_id: str, original_issuer: DeviceController
    ) -> None:
        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        Environment.COMMUNICATION_CHANNEL = "SIMULATED"
        create_simulated_comm_connection(self.agent_or_server, original_issuer)
        self.agent_or_server.flow_issuer_issue_u_ticket.holder_send_r_ticket_to_issuer(
            target_device_id
        )
        wait_simulated_comm_completed(original_issuer, self.agent_or_server)

    def apply_insecure_cmd_through_bluetooth(
        self, option: str = "with_device_id"
    ) -> DeviceController:
        # WHEN: Connect bluetooth connection with IoTD
        Environment.COMMUNICATION_CHANNEL = "BLUETOOTH"
        self.agent_or_server.msg_sender.connect_bluetooth_comm()

        # WHEN: UA or CS send the insecure_cmd to IoTD

        ########################################################################
        # Start Process Measurement
        ########################################################################
        self.agent_or_server.executor.measure_process_start()

        if option == "shortest":
            insecure_cmd_json = "HELLO"
        elif option == "with_device_id":
            insecure_cmd_dict = {
                "protocol_verision": "UREKA-1.0",
                "device_id": "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuWt9xdWLXffJE-CydWYBTH05kv7xFmMGl-L3DT_7-YH2ocgHJWUUAPxQjjRBQGOeITMandJxLDye7jK8W26GmA==",
                "insecure_command": "HELLO",
            }
            insecure_cmd_json = json.dumps(insecure_cmd_dict, indent=4)
        elif option == "u_ticket_size":
            insecure_cmd_dict = {
                "protocol_verision": "UREKA-1.0",
                "device_id": "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuWt9xdWLXffJE-CydWYBTH05kv7xFmMGl-L3DT_7-YH2ocgHJWUUAPxQjjRBQGOeITMandJxLDye7jK8W26GmA==",
                "insecure_command": "HELLO" * 90,
            }
            insecure_cmd_json = json.dumps(insecure_cmd_dict, indent=4)

        self.agent_or_server.shared_data.connection_socket.send_message(
            insecure_cmd_json
        )
        simple_log("cli", f"Sent Command: {insecure_cmd_json}")

        ######################################################
        # End Process Measurement
        ######################################################
        self.agent_or_server.executor.measure_cli_process_time(
            "holder_apply_insecure_cmd"
        )

        # WHEN: UA or CS receive the insecure_data from IoTD
        try:
            ########################################################################
            # Start Comm Measurement
            ########################################################################
            self.agent_or_server.executor.measure_comm_start()

            # This will block until message is received
            insecure_data_json = (
                self.agent_or_server.shared_data.connection_socket.recv_message()
            )

            ########################################################################
            # End Comm Measurement
            ########################################################################
            self.agent_or_server.executor.measure_comm_time(
                "_holder_or_device_recv_u_or_r_ticket"
            )
            self.agent_or_server.executor.measure_message_size(insecure_data_json)
            simple_log("cli", f"Received Data: {insecure_data_json}")

            ########################################################################
            # Start Process Measurement
            ########################################################################
            self.agent_or_server.executor.measure_process_start()

            # WHEN: UA/CS do data processing

            ######################################################
            # End Process Measurement
            ######################################################
            self.agent_or_server.executor.measure_comm_process_time(
                "_holder_recv_insecure_data"
            )

            simple_log("debug", f"+ Finish CMD-DATA~~ (holder)")
        except OSError:
            simple_log("cli", f"")
            simple_log("cli", f"+ Connection is closed by peer.")

        # RE-GIVEN: Close bluetooth connection with IoTD (Finish CMD-DATA~~)
        self.agent_or_server.msg_sender.close_bluetooth_connection()

        return self.agent_or_server


if __name__ == "__main__":
    try:
        ######################################################
        # ENVIRONMENT
        ######################################################
        Environment.DEPLOYMENT_ENV = "PRODUCTION"
        # Environment.DEBUG_LOG = "OPEN"
        Environment.DEBUG_LOG = "CLOSED"
        # Environment.CLI_LOG = "OPEN"
        Environment.CLI_LOG = "CLOSED"
        Environment.MEASURE_LOG = "OPEN"
        # Environment.MEASURE_LOG = "CLOSED"

        # Omit 1st run (Cold-start)
        for times in range(2):
            if times == 0:
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Cold Start")
                simple_log("measure", "*" * 50)
            else:
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Initialize Agent & Device")
                simple_log("measure", "*" * 50)

            ######################################################
            # Unintialized Agent or Server
            ######################################################

            # RE-GIVEN:
            SimpleStorage.delete_storage_in_test()

            ######################################################
            # Initialize Agent or Server
            ######################################################

            # GIVEN: Uninitialized DM's CS
            menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")

            # WHEN: DM's CS initialize UA or CS
            cloud_server_dm = (
                menu_cloud_server_dm.intialize_agent_or_server_through_cli()
            )

            # THEN: Succeed to initialize UA or CS
            assert cloud_server_dm.shared_data.this_device.ticket_order == 1
            assert cloud_server_dm.shared_data.this_device.device_priv_key_str != None

            ######################################################
            # Initialize Device
            ######################################################

            # GIVEN: Initialized DM's CS
            menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
            cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

            # WHEN: Holder: DM's CS generate & apply the initialization_u_ticket to IoTD
            cloud_server_dm = (
                menu_cloud_server_dm.apply_initialization_ticket_through_bluetooth()
            )

            # THEN: Succeed to initialize DM's IoTD
            assert "SUCCESS" in cloud_server_dm.shared_data.result_message

        ######################################################
        # Send Insecure Command
        ######################################################
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            simple_log("measure", "")
            simple_log("measure", "*" * 50)
            simple_log("measure", f"+ Send Insecure Command ({option})")
            simple_log("measure", "*" * 50)

            # GIVEN: Initialized DM's CS
            menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
            cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

            # WHEN: DM's CS apply the insecure_cmd to IoTD
            cloud_server_dm = menu_cloud_server_dm.apply_insecure_cmd_through_bluetooth(
                option=option
            )

        ######################################################
        # Transfer Device Ownership
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Transfer Device Ownership")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized DM's CS
        menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
        # GIVEN: Initialized DO's UA
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        user_agent_do = menu_user_agent_do.intialize_agent_or_server_through_cli()

        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        target_device_id = menu_cloud_server_dm.get_target_device_id()
        menu_cloud_server_dm.issue_ownership_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            user_agent_do=user_agent_do,
        )
        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        target_device_id = menu_user_agent_do.get_target_device_id()
        user_agent_do = menu_user_agent_do.apply_ownership_ticket_through_bluetooth(
            target_device_id=target_device_id
        )
        # WHEN: Holder: DO's UA return the ownership_r_ticket to DM's CS
        menu_user_agent_do.return_r_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            original_issuer=cloud_server_dm,
        )

        # THEN: Succeed to transfer ownership (& update ticket_order of DO's IoTD)
        assert "SUCCESS" in user_agent_do.shared_data.result_message

        ######################################################
        # Grant Device Access Right (to owner herself)
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Grant Device Access Right (to owner herself)")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized DM's CS
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        user_agent_do = menu_user_agent_do.get_agent_or_server()

        # WHEN: Holder: DO's UA generate & apply the self_access_u_ticket to IoTD
        target_device_id = menu_user_agent_do.get_target_device_id()
        user_agent_do = menu_user_agent_do.apply_self_access_ticket_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in user_agent_do.shared_data.result_message
        # THEN: DO's UA can share a private session with DO's IoTD
        assert (
            user_agent_do.shared_data.current_session.plaintext_data
            == "DATA: " + user_agent_do.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: DO's UA cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: DO's UA generate & apply the u_token to IoTD
        target_device_id = menu_user_agent_do.get_target_device_id()
        user_agent_do = menu_user_agent_do.apply_cmd_token_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: Succeed to allow DO's UA to access DO's IoTD
        assert "SUCCESS" in user_agent_do.shared_data.result_message
        # THEN: DO's UA can share a private session with DO's IoTD
        assert (
            user_agent_do.shared_data.current_session.plaintext_data
            == "DATA: " + user_agent_do.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: EP's CS cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS generate & apply the access_end_u_token to IoTD
        target_device_id = menu_user_agent_do.get_target_device_id()
        original_agent_order = user_agent_do.shared_data.device_table[
            target_device_id
        ].ticket_order
        user_agent_do = menu_user_agent_do.apply_access_end_token_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in user_agent_do.shared_data.result_message
        assert (
            user_agent_do.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

        ######################################################
        # Grant Device Access Right (to others)
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Grant Device Access Right (to others)")
        simple_log("measure", "*" * 50)

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

        # WHEN: Holder: EP's CS generate & apply the u_token to IoTD
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

        # WHEN: Holder: EP's CS generate & apply the access_end_u_token to IoTD
        target_device_id = menu_cloud_server_ep.get_target_device_id()
        original_agent_order = cloud_server_ep.shared_data.device_table[
            target_device_id
        ].ticket_order
        cloud_server_ep = menu_cloud_server_ep.apply_access_end_token_through_bluetooth(
            target_device_id=target_device_id
        )
        # WHEN: Holder: EP's CS return the access_end_r_ticket to DO's UA
        menu_cloud_server_ep.return_r_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            original_issuer=user_agent_do,
        )

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in cloud_server_ep.shared_data.result_message
        assert (
            cloud_server_ep.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

    except RuntimeError as error:
        simple_log("error", f"{error}")
