# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_agent_or_server import MenuAgentOrServer

if __name__ == "__main__":
    try:
        ######################################################
        # Unintialized Agent or Server
        ######################################################
        MenuAgentOrServer.set_environment("cli")

        # RE-GIVEN:
        SimpleStorage.delete_storage_in_test()

        ######################################################
        # Initialize Agent or Server
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + Initialize Agent or Server")
        print(f"[   M-REC] : {f'*' * 50}")

        # GIVEN: Uninitialized DM's CS
        menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")

        # WHEN: DM's CS initialize UA or CS
        cloud_server_dm = menu_cloud_server_dm.intialize_agent_or_server_through_cli()

        # THEN: Succeed to initialize UA or CS
        assert cloud_server_dm.shared_data.this_device.ticket_order == 1
        assert cloud_server_dm.shared_data.this_device.device_priv_key_str != None

        ######################################################
        # Initialize Device
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + Initialize Device")
        print(f"[   M-REC] : {f'*' * 50}")

        # GIVEN: Initialized DM's CS
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

        # WHEN: Holder: DM's CS generate & apply the initialization_u_ticket to IoTD
        cloud_server_dm = (
            menu_cloud_server_dm.apply_initialization_ticket_through_bluetooth()
        )

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in cloud_server_dm.shared_data.result_message

        ######################################################
        # Transfer Device Ownership (DM to UA)
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + Transfer Device Ownership (DM to UA)")
        print(f"[   M-REC] : {f'*' * 50}")

        ###########################

        # GIVEN: Initialized DM's CS
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
        # GIVEN: Initialized DO's UA
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        user_agent_do = menu_user_agent_do.intialize_agent_or_server_through_cli()

        ###########################

        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        target_device_id = menu_cloud_server_dm.get_target_device_id()
        menu_cloud_server_dm.issue_ownership_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            new_owner=user_agent_do,
        )

        ###########################

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        target_device_id = menu_user_agent_do.get_target_device_id()
        user_agent_do = menu_user_agent_do.apply_ownership_ticket_through_bluetooth(
            target_device_id=target_device_id
        )

        # THEN: Succeed to transfer ownership (& update ticket_order of DO's IoTD)
        assert "SUCCESS" in user_agent_do.shared_data.result_message

        ###########################

        # WHEN: Holder: DO's UA return the ownership_r_ticket to DM's CS
        menu_user_agent_do.return_r_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            original_issuer=cloud_server_dm,
        )

        # THEN: Issuer: DM's CS know that DO's UA has become the new owner of DO's IoTD (& ticket order++)
        assert "SUCCESS" in cloud_server_dm.shared_data.result_message
        assert cloud_server_dm.shared_data.device_table.get(target_device_id) == None

        ###########################

    except RuntimeError as error:
        simple_log("error", f"{error}")
