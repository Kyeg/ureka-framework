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
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Initialize Agent or Server")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Uninitialized UA or CS
        menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        menu_cloud_server_ep = MenuAgentOrServer(device_name="cloud_server_ep")

        # WHEN: Initialize UA or CS
        cloud_server_dm = menu_cloud_server_dm.intialize_agent_or_server_through_cli()
        user_agent_do = menu_user_agent_do.intialize_agent_or_server_through_cli()
        cloud_server_ep = menu_cloud_server_ep.intialize_agent_or_server_through_cli()

        # THEN: Succeed to initialize UA or CS
        assert cloud_server_dm.shared_data.this_device.ticket_order == 1
        assert cloud_server_dm.shared_data.this_device.device_priv_key_str != None

        ######################################################
        # Initialize Device
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Initialize Device")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Initialized DM's CS
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

        # WHEN: Holder: DM's CS generate & apply the initialization_u_ticket to IoTD
        cloud_server_dm = (
            menu_cloud_server_dm.apply_initialization_ticket_through_bluetooth()
        )

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in cloud_server_dm.shared_data.result_message

        ######################################################
        # Transfer Device Ownership
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Transfer Device Ownership")
        print(f"[   PRINT] : {f'*' * 50}")

        ###########################

        # GIVEN: Initialized DM's CS
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
        # GIVEN: Initialized DO's UA
        user_agent_do = menu_user_agent_do.get_agent_or_server()

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

        ######################################################
        # Send Insecure Command & Receive Insecure Data
        ######################################################
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            print(f"[   PRINT] : ")
            print(f"[   PRINT] : {f'*' * 50}")
            print(f"[   PRINT] : + Insecurely Recv Command & Send Data ({option})")
            print(f"[   PRINT] : {f'*' * 50}")

            # GIVEN: Initialized DM's CS
            cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

            # WHEN: DM's CS apply the insecure_cmd to IoTD
            cloud_server_dm = menu_cloud_server_dm.apply_insecure_cmd_through_bluetooth(
                option=option
            )

        ######################################################
        # Grant Device Access Right (to owner herself)
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Grant Device Access Right (to owner herself)")
        print(f"[   PRINT] : {f'*' * 50}")

        ###########################

        # GIVEN: Initialized DM's CS
        user_agent_do = menu_user_agent_do.get_agent_or_server()

        ###########################

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
        # Grant Device Access Right (to other)
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Grant Device Access Right (to other)")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Initialized DO's UA
        user_agent_do = menu_user_agent_do.get_agent_or_server()
        # GIVEN: Initialized EP's CS
        cloud_server_ep = menu_cloud_server_ep.get_agent_or_server()

        ###########################

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        target_device_id = menu_user_agent_do.get_target_device_id()
        menu_user_agent_do.issue_access_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            new_accessor=cloud_server_ep,
        )

        ###########################

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

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in cloud_server_ep.shared_data.result_message
        assert (
            cloud_server_ep.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

        ###########################

        # WHEN: Holder: EP's CS return the access_end_r_ticket to DO's UA
        menu_cloud_server_ep.return_r_ticket_through_simulated_comm(
            target_device_id=target_device_id,
            original_issuer=user_agent_do,
        )

        # THEN: Issuer: DM's CS know that EP's CS has ended the private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in user_agent_do.shared_data.result_message
        assert (
            user_agent_do.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

        ###########################

    except RuntimeError as error:
        simple_log("error", f"{error}")
