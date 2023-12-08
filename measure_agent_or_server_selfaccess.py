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
        # Omit 1st run (Cold-start)
        for times in range(2):
            if times == 0:
                ######################################################
                # Omit Cold-start
                ######################################################
                MenuAgentOrServer.set_environment("cold-start")
            else:
                ######################################################
                # Grant Device Access Right (to owner herself)
                ######################################################
                MenuAgentOrServer.set_environment("measurement")
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Grant Device Access Right (to owner herself)")
                simple_log("measure", "*" * 50)

            ###########################

            # GIVEN: Initialized DM's CS
            menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
            user_agent_do = menu_user_agent_do.get_agent_or_server()

            ###########################

            # WHEN: Holder: DO's UA generate & apply the self_access_u_ticket to IoTD
            target_device_id = menu_user_agent_do.get_target_device_id()
            user_agent_do = (
                menu_user_agent_do.apply_self_access_ticket_through_bluetooth(
                    target_device_id=target_device_id
                )
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

    except RuntimeError as error:
        simple_log("error", f"{error}")
