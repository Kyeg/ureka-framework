# Environment
from ureka_framework.environment import Environment

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_iot_device import MenuIoTDevice

# Measurement Statistics
import copy
import json

if __name__ == "__main__":
    try:
        ######################################################
        # Grant Device Access Right (to others)
        ######################################################
        MenuIoTDevice.set_environment("measurement")

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")

        # Repeatly measure the overhead
        times = 0
        measurement_statistics = list()
        # TO-DO: If blocked I/O is detected, times should be larger than MEASUREMENT_REPEAT_TIMES
        # while times < Environment.MEASUREMENT_REPEAT_TIMES:
        while True:
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Grant Device Access Right (to owner herself)")
            print(f"[   M-REC] : {f'*' * 50}")

            ###########################

            # GIVEN: Initialized IoTD
            # menu_iot_device = MenuIoTDevice(device_name="iot_device")
            iot_device = menu_iot_device.get_iot_device()

            # WHEN: Holder: EP's CS apply the self_access_u_ticket to IoTD
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

            ######################################################
            # Print Measurement Raw Data (iot_device)
            ######################################################
            print(
                f"[   M-REC] : "
                f"measure_rec = {json.dumps(iot_device.shared_data.measure_rec, indent=4)}"
            )

            ######################################################
            # Complete Collecting Measurement Raw Data
            ######################################################
            times = times + 1
            print(f"[   M-REC] : " f"Complete Collecting Measurement Raw Data")

    except RuntimeError as error:
        simple_log("error", f"{error}")
