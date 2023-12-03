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

            # GIVEN: Initialized IoTD
            menu_iot_device = MenuIoTDevice(device_name="iot_device")
            iot_device = menu_iot_device.get_iot_device()

            # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
            iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

            # THEN: Succeed to share a private session with DO's IoTD
            assert "SUCCESS" in iot_device.shared_data.result_message
            # THEN: EP's CS can share a private session with DO's IoTD
            assert (
                iot_device.shared_data.current_session.plaintext_data
                == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
            )

            ###########################

            # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

            # WHEN: Holder: EP's CS apply the u_token to IoTD
            iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

            # THEN: Succeed to share a private session with DO's IoTD
            assert "SUCCESS" in iot_device.shared_data.result_message
            # THEN: EP's CS can share a private session with DO's IoTD
            assert (
                iot_device.shared_data.current_session.plaintext_data
                == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
            )

            ###########################

            # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

            # WHEN: Holder: EP's CS apply the access_end_u_token to IoTD
            original_device_order = iot_device.shared_data.this_device.ticket_order
            iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

            # THEN: Succeed to share a private session with DO's IoTD
            assert "SUCCESS" in iot_device.shared_data.result_message
            assert (
                iot_device.shared_data.this_device.ticket_order
                == original_device_order + 1
            )

    except RuntimeError as error:
        simple_log("error", f"{error}")
