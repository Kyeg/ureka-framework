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
        for times in range(2):
            if times == 0:
                ######################################################
                # Omit Cold-start
                ######################################################
                MenuIoTDevice.set_environment("cold-start")
            else:
                ######################################################
                # Intialize Device & Change Device Ownership
                ######################################################
                MenuIoTDevice.set_environment("measurement")
                simple_log("measure", "")
                simple_log("measure", "*" * 50)
                simple_log("measure", f"+ Grant Device Access Right (to owner herself)")
                simple_log("measure", "*" * 50)

            ######################################################
            # Unintialized Device
            ######################################################

            # RE-GIVEN:
            SimpleStorage.delete_storage_in_test()

            ######################################################
            # Intialize Device
            ######################################################
            simple_log("measure", "")
            simple_log("measure", "*" * 50)
            simple_log("measure", f"+ Initialize Device")
            simple_log("measure", "*" * 50)

            # GIVEN: Uninitialized IoTD
            menu_iot_device = MenuIoTDevice(device_name="iot_device")

            # WHEN: Holder: DM's CS apply the initialization_u_ticket to IoTD
            iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

            # THEN: Succeed to initialize DM's IoTD
            assert "SUCCESS" in iot_device.shared_data.result_message
            assert iot_device.shared_data.this_device.ticket_order == 1
            assert iot_device.shared_data.this_device.device_priv_key_str != None

        ######################################################
        # Receive Insecure Command & Send Insecure Data
        ######################################################
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
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

            # THEN: ...

        ######################################################
        # Transfer Device Ownership
        ######################################################
        simple_log("measure", "")
        simple_log("measure", "*" * 50)
        simple_log("measure", f"+ Transfer Device Ownership")
        simple_log("measure", "*" * 50)

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.owner_pub_key_str != None

    except RuntimeError as error:
        simple_log("error", f"{error}")
