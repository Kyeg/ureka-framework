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
                # Omit Cold-start
                Environment.DEPLOYMENT_ENV = "PRODUCTION"
                Environment.DEBUG_LOG = "CLOSED"
                Environment.CLI_LOG = "CLOSED"
                Environment.MEASURE_LOG = "CLOSED"
                print(f"[   PRINT] : ")
                print(f"[   PRINT] : {f'*' * 50}")
                print(f"[   PRINT] : + Omit Cold-start...")
                print(f"[   PRINT] : {f'*' * 50}")
            else:
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

            ######################################################
            # Unintialized Agent or Server
            ######################################################
            # RE-GIVEN:
            SimpleStorage.delete_storage_in_test()

            ######################################################
            # Initialize Agent or Server
            ######################################################
            simple_log("measure", "")
            simple_log("measure", "*" * 50)
            simple_log("measure", f"+ Initialize Agent or Server")
            simple_log("measure", "*" * 50)

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
            simple_log("measure", "")
            simple_log("measure", "*" * 50)
            simple_log("measure", f"+ Initialize Device")
            simple_log("measure", "*" * 50)

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

    except RuntimeError as error:
        simple_log("error", f"{error}")
