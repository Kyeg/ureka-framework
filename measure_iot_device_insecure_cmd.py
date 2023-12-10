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
        # Insecurely Recv Command & Send Insecure Data
        ######################################################
        MenuIoTDevice.set_environment("measurement")

        # GIVEN: Initialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            times = 0
            measurement_statistics = list()
            # TO-DO: If blocked I/O is detected, times should be larger than MEASUREMENT_REPEAT_TIMES
            # while times < Environment.MEASUREMENT_REPEAT_TIMES:
            while True:
                print(f"[   M-REC] : ")
                print(f"[   M-REC] : {f'*' * 50}")
                print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
                print(f"[   M-REC] : {f'*' * 50}")

                # GIVEN: Initialized IoTD
                iot_device = menu_iot_device.get_iot_device()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
                    option=option
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
