# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_iot_device import MenuIoTDevice


if __name__ == "__main__":
    try:
        # Omit 1st run (Cold-start)
        MenuIoTDevice.set_environment("cold-start")

        option = "shortest"
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Send Insecure Command ({option})")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: DM's CS apply the insecure_cmd to IoTD
        iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
            option=option
        )

        ######################################################
        # Receive Insecure Command & Send Insecure Data
        ######################################################
        MenuIoTDevice.set_environment("measurement")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            for times in range(5):
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Send Insecure Command ({option})")
                simple_log("measure", "*" * 50)

                # GIVEN: Initialized IoTD
                menu_iot_device = MenuIoTDevice(device_name="iot_device")
                iot_device = menu_iot_device.get_iot_device()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
                    option=option
                )

    except RuntimeError as error:
        simple_log("error", f"{error}")
