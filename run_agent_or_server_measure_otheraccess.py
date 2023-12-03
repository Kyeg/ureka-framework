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
        for times in range(1):
            if times == 0:
                ######################################################
                # Omit Cold-start
                ######################################################
                print(f"[   PRINT] : ")
                print(f"[   PRINT] : {f'*' * 50}")
                print(f"[   PRINT] : + Omit Cold-start...")
                print(f"[   PRINT] : {f'*' * 50}")

            else:
                ######################################################
                # Grant Device Access Right (to others)
                ######################################################
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Grant Device Access Right (to others)")
                simple_log("measure", "*" * 50)

            ###########################

            # GIVEN: Initialized DO's UA
            menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
            user_agent_do = menu_user_agent_do.get_agent_or_server()
            # GIVEN: Initialized EP's CS
            menu_cloud_server_ep = MenuAgentOrServer(device_name="cloud_server_ep")
            cloud_server_ep = (
                menu_cloud_server_ep.intialize_agent_or_server_through_cli()
            )

            ###########################

            # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
            target_device_id = menu_user_agent_do.get_target_device_id()
            menu_user_agent_do.issue_access_ticket_through_simulated_comm(
                target_device_id=target_device_id,
                cloud_server_ep=cloud_server_ep,
            )

            ###########################

            # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
            target_device_id = menu_cloud_server_ep.get_target_device_id()
            cloud_server_ep = (
                menu_cloud_server_ep.apply_access_ticket_through_bluetooth(
                    target_device_id=target_device_id
                )
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
            cloud_server_ep = (
                menu_cloud_server_ep.apply_access_end_token_through_bluetooth(
                    target_device_id=target_device_id
                )
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

            # THEN: Issuer: DO's UA know that EP's CS has ended the private session with DO's IoTD (& ticket order++)
            assert "SUCCESS" in user_agent_do.shared_data.result_message
            # assert (
            #     user_agent_do.shared_data.device_table[target_device_id].ticket_order
            #     == original_agent_order + 1
            # )

    except RuntimeError as error:
        simple_log("error", f"{error}")
