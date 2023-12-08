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
        MenuAgentOrServer.set_environment("cold-start")

        option = "shortest"
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
        # Send Insecure Command & Receive Insecure Data
        ######################################################
        MenuAgentOrServer.set_environment("measurement")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            for times in range(5):
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Send Insecure Command ({option})")
                simple_log("measure", "*" * 50)

                # GIVEN: Initialized DM's CS
                menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
                cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                cloud_server_dm = (
                    menu_cloud_server_dm.apply_insecure_cmd_through_bluetooth(
                        option=option
                    )
                )

    except RuntimeError as error:
        simple_log("error", f"{error}")
