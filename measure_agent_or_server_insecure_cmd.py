# Environment
from ureka_framework.environment import Environment

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_agent_or_server import MenuAgentOrServer

# Measurement Statistics
import copy
import json

if __name__ == "__main__":
    try:
        # Omit 1st run (Cold-start)
        MenuAgentOrServer.set_environment("cold-start")

        option = "shortest"

        # GIVEN: Initialized DM's CS
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")
        user_agent_do = menu_user_agent_do.get_agent_or_server()

        # WHEN: DM's CS apply the insecure_cmd to IoTD
        user_agent_do = menu_user_agent_do.apply_insecure_cmd_through_bluetooth(
            option=option
        )

        ######################################################
        # Insecurely Recv Command & Send Insecure Data
        ######################################################
        MenuAgentOrServer.set_environment("measurement")

        diff_option_statistics = dict()
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            # Repeatly measure the overhead
            times = 0
            measurement_statistics = list()
            while times < Environment.MEASUREMENT_REPEAT_TIMES:
                print(f"[   M-REC] : ")
                print(f"[   M-REC] : {f'*' * 50}")
                print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
                print(f"[   M-REC] : {f'*' * 50}")

                ###########################

                # GIVEN: Initialized DM's CS
                user_agent_do = menu_user_agent_do.get_agent_or_server()

                # WHEN: DM's CS apply the insecure_cmd to IoTD
                user_agent_do = menu_user_agent_do.apply_insecure_cmd_through_bluetooth(
                    option=option
                )

                ######################################################
                # Do Not Collect Too Large Overhead (I/O Peak)
                ######################################################
                if (
                    user_agent_do.shared_data.measure_rec["_holder_recv_insecure_data"][
                        "comm_time"
                    ]
                    > Environment.COMM_BLOCKING_TOLERANCE_TIME
                ):
                    print(f"[ WARNING] : " f"+ COMM I/O MAYBE BLOCKED TOO LONG...")
                    continue
                if (
                    user_agent_do.shared_data.measure_rec["holder_apply_insecure_cmd"][
                        "cli_blocked_time"
                    ]
                    > Environment.IO_BLOCKING_TOLERANCE_TIME
                    or user_agent_do.shared_data.measure_rec[
                        "_holder_recv_insecure_data"
                    ]["msg_blocked_time"]
                    > Environment.IO_BLOCKING_TOLERANCE_TIME
                ):
                    print(f"[ WARNING] : " f"+ PROC I/O MAYBE BLOCKED TOO LONG...")
                    continue

                ######################################################
                # Collect Measurement Raw Data
                ######################################################
                user_agent_do_measure_rec = copy.deepcopy(
                    user_agent_do.shared_data.measure_rec
                )
                measurement_statistics.append(user_agent_do_measure_rec)

                ######################################################
                # Print Measurement Raw Data
                ######################################################
                print(
                    f"[   M-REC] : "
                    f"measure_rec = {json.dumps(user_agent_do.shared_data.measure_rec, indent=4)}"
                )

                ######################################################
                # Complete Collecting Measurement Raw Data
                ######################################################
                times = times + 1
                print(f"[   M-REC] : " f"Complete Collecting Measurement Raw Data")

            ######################################################
            # Print Measurement Statistics
            ######################################################
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Measurement Statistics")
            print(f"[   M-REC] : + Insecurely Recv Command & Send Data ({option})")
            print(f"[   M-REC] : {f'*' * 50}")

            # CMD=DATA
            print(f"[   M-REC] : ")
            filtered_data = [
                data["holder_apply_insecure_cmd"]["cli_perf_time"]
                for data in measurement_statistics
            ]
            average_cmd_p0 = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"holder_apply_insecure_cmd: cli_perf_time = \n\t\t"
                f"{average_cmd_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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

            # =DATA
            print(f"[   M-REC] : ")
            filtered_data = [
                data["_holder_recv_insecure_data"]["comm_time"]
                for data in measurement_statistics
            ]
            average_cmd_data_c1 = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: comm_time = \n\t\t"
                f"{average_cmd_data_c1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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
            average_cmd_data_p1 = sum(filtered_data) / len(filtered_data)
            print(
                f"[   M-REC] : "
                f"_holder_recv_insecure_data: msg_perf_time = \n\t\t"
                f"{average_cmd_data_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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

            ######################################################
            # Collect Measurement Statistics
            ######################################################
            diff_option_statistics[option] = (
                average_cmd_p0 + average_cmd_data_c1 + average_cmd_data_p1
            )

        ######################################################
        # Print Measurement Summary
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + [Summarize] Measurement Statistics")
        print(f"[   M-REC] : + Insecurely Recv Command & Send Data")
        print(f"[   M-REC] : {f'*' * 50}")

        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            print(f"[   M-REC] : ")
            print(
                f"[   M-REC] : "
                f"Total CMD-DATA Response Time ({option})= \n\t\t"
                f"{diff_option_statistics[option]:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
            )

    except RuntimeError as error:
        simple_log("error", f"{error}")
