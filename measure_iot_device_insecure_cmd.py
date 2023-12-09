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
        # Insecurely Recv Command & Send Insecure Data
        ######################################################
        MenuIoTDevice.set_environment("measurement")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            for times in range(Environment.MEASUREMENT_REPEAT_TIMES):
                print(f"[   M-REC] : ")
                print(f"[   M-REC] : {f'*' * 50}")
                print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
                print(f"[   M-REC] : {f'*' * 50}")

                # GIVEN: Initialized IoTD
                menu_iot_device = MenuIoTDevice(device_name="iot_device")
                iot_device = menu_iot_device.get_iot_device()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
                    option=option
                )

                # Do Not Collect Too Large Overhead (I/O Peak)
                if (
                    iot_device.shared_data.measure_rec["_device_recv_insecure_cmd"][
                        "msg_blocked_time"
                    ]
                    > Environment.IO_BLOCKING_TOLERANCE_TIME
                ):
                    print(f"[ WARNING] : " f"+ PROC I/O MAYBE BLOCKED TOO LONG...")
                    continue

                # Print Measurement Record
                # print(
                #     f"[   M-REC] : "
                #     f"measure_rec = {iot_device.shared_data.measure_rec}"
                # )
                print(
                    f"[   M-REC] : "
                    f"_device_recv_insecure_cmd: message_size = \n\t\t"
                    f"{iot_device.shared_data.measure_rec['_device_recv_insecure_cmd']['message_size']} bytes",
                )
                print(
                    f"[   M-REC] : "
                    f"_device_recv_insecure_cmd: msg_perf_time = \n\t\t"
                    f"{iot_device.shared_data.measure_rec['_device_recv_insecure_cmd']['msg_perf_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                )
                print(
                    f"[   M-REC] : "
                    f"_device_recv_insecure_cmd: msg_blocked_time = \n\t\t"
                    f"{iot_device.shared_data.measure_rec['_device_recv_insecure_cmd']['msg_blocked_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                )

    except RuntimeError as error:
        simple_log("error", f"{error}")
