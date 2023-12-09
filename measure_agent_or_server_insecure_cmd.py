# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_agent_or_server import MenuAgentOrServer

# Memory Management
import copy

if __name__ == "__main__":
    try:
        # Omit 1st run (Cold-start)
        MenuAgentOrServer.set_environment("cold-start")

        option = "shortest"

        # GIVEN: Initialized DM's CS
        menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

        # WHEN: DM's CS apply the insecure_cmd to IoTD
        cloud_server_dm = menu_cloud_server_dm.apply_insecure_cmd_through_bluetooth(
            option=option
        )

        ######################################################
        # Insecurely Recv Command & Send Insecure Data
        ######################################################
        MenuAgentOrServer.set_environment("measurement")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            times = 0
            measurement_statistics = list()
            while times < Environment.MEASUREMENT_REPEAT_TIMES:
                print(f"[   M-REC] : ")
                print(f"[   M-REC] : {f'*' * 50}")
                print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
                print(f"[   M-REC] : {f'*' * 50}")

                # GIVEN: Initialized DM's CS
                # menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
                cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                cloud_server_dm = (
                    menu_cloud_server_dm.apply_insecure_cmd_through_bluetooth(
                        option=option
                    )
                )

                # Do Not Collect Too Large Overhead (I/O Peak)
                if (
                    cloud_server_dm.shared_data.measure_rec[
                        "_holder_recv_insecure_data"
                    ]["comm_time"]
                    > Environment.COMM_BLOCKING_TOLERANCE_TIME
                ):
                    print(f"[ WARNING] : " f"+ COMM I/O MAYBE BLOCKED TOO LONG...")
                    continue
                if (
                    cloud_server_dm.shared_data.measure_rec[
                        "holder_apply_insecure_cmd"
                    ]["cli_blocked_time"]
                    > Environment.IO_BLOCKING_TOLERANCE_TIME
                    or cloud_server_dm.shared_data.measure_rec[
                        "_holder_recv_insecure_data"
                    ]["msg_blocked_time"]
                    > Environment.IO_BLOCKING_TOLERANCE_TIME
                ):
                    print(f"[ WARNING] : " f"+ PROC I/O MAYBE BLOCKED TOO LONG...")
                    continue

                # Collect Measurement Raw Data
                tmp = copy.deepcopy(cloud_server_dm.shared_data.measure_rec)
                measurement_statistics.append(tmp)
                times = times + 1
                print(f"[   M-REC] : " f"Complete Collecting Measurement Raw Data")

                # Print Measurement Raw Data

                # print(
                #     f"[   M-REC] : "
                #     f"measure_rec = {cloud_server_dm.shared_data.measure_rec}"
                # )

                # print(
                #     f"[   M-REC] : "
                #     f"holder_apply_insecure_cmd: cli_perf_time = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['holder_apply_insecure_cmd']['cli_perf_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                # )
                # print(
                #     f"[   M-REC] : "
                #     f"holder_apply_insecure_cmd: cli_blocked_time = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['holder_apply_insecure_cmd']['cli_blocked_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                # )
                # print(
                #     f"[   M-REC] : "
                #     f"_holder_recv_insecure_data: comm_time = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['_holder_recv_insecure_data']['comm_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                # )
                # print(
                #     f"[   M-REC] : "
                #     f"_holder_recv_insecure_data: message_size = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['_holder_recv_insecure_data']['message_size']} bytes",
                # )
                # print(
                #     f"[   M-REC] : "
                #     f"_holder_recv_insecure_data: msg_perf_time = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['_holder_recv_insecure_data']['msg_perf_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                # )
                # print(
                #     f"[   M-REC] : "
                #     f"_holder_recv_insecure_data: msg_blocked_time = \n\t\t"
                #     f"{cloud_server_dm.shared_data.measure_rec['_holder_recv_insecure_data']['msg_blocked_time']:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
                # )

            # Print Measurement Statistics
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Measurement Statistics")
            print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
            print(f"[   M-REC] : {f'*' * 50}")

            filtered_data = [
                data["holder_apply_insecure_cmd"]["cli_perf_time"]
                for data in measurement_statistics
            ]
            average = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"holder_apply_insecure_cmd: cli_perf_time = \n\t\t"
                f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

            filtered_data = [
                data["holder_apply_insecure_cmd"]["cli_blocked_time"]
                for data in measurement_statistics
            ]
            average = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"holder_apply_insecure_cmd: cli_blocked_time = \n\t\t"
                f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

            filtered_data = [
                data["_holder_recv_insecure_data"]["comm_time"]
                for data in measurement_statistics
            ]
            average = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: comm_time = \n\t\t"
                f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

            filtered_data = [
                data["_holder_recv_insecure_data"]["message_size"]
                for data in measurement_statistics
            ]
            average = int(sum(filtered_data) / len(filtered_data))
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: message_size = \n\t\t"
                f"{average} bytes",
            )

            filtered_data = [
                data["_holder_recv_insecure_data"]["msg_perf_time"]
                for data in measurement_statistics
            ]
            average = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: msg_perf_time = \n\t\t"
                f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

            filtered_data = [
                data["_holder_recv_insecure_data"]["msg_blocked_time"]
                for data in measurement_statistics
            ]
            average = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: msg_blocked_time = \n\t\t"
                f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

    except RuntimeError as error:
        simple_log("error", f"{error}")
