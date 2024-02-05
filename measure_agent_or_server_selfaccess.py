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
        ######################################################
        # Grant Device Access Right (to owner herself)
        ######################################################
        MenuAgentOrServer.set_environment("measurement")

        # GIVEN: Initialized DO's UA
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")

        # Repeatly measure the overhead
        times = 0
        measurement_statistics = list()
        while times < Environment.MEASUREMENT_REPEAT_TIMES:
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Grant Device Access Right (to owner herself)")
            print(f"[   M-REC] : {f'*' * 50}")

            ###########################

            # GIVEN: Initialized DO's UA
            user_agent_do = menu_user_agent_do.get_agent_or_server()

            ###########################

            # WHEN: Holder: DO's UA generate & apply the self_access_u_ticket to IoTD
            target_device_id = menu_user_agent_do.get_target_device_id()
            user_agent_do = (
                menu_user_agent_do.apply_self_access_ticket_through_bluetooth(
                    target_device_id=target_device_id
                )
            )

            # THEN: Succeed to initialize DM's IoTD
            assert "SUCCESS" in user_agent_do.shared_data.result_message
            # THEN: DO's UA can share a private session with DO's IoTD
            assert (
                user_agent_do.shared_data.current_session.plaintext_data
                == "DATA: " + user_agent_do.shared_data.current_session.plaintext_cmd
            )

            ###########################

            # GIVEN: DO's UA cannot be rebooted, because the state & session is non-volatile

            # WHEN: Holder: DO's UA generate & apply the u_token to IoTD
            target_device_id = menu_user_agent_do.get_target_device_id()
            user_agent_do = menu_user_agent_do.apply_cmd_token_through_bluetooth(
                target_device_id=target_device_id
            )

            # THEN: Succeed to allow DO's UA to access DO's IoTD
            assert "SUCCESS" in user_agent_do.shared_data.result_message
            # THEN: DO's UA can share a private session with DO's IoTD
            assert (
                user_agent_do.shared_data.current_session.plaintext_data
                == "DATA: " + user_agent_do.shared_data.current_session.plaintext_cmd
            )

            ###########################

            # GIVEN: EP's CS cannot be rebooted, because the state & session is non-volatile

            # WHEN: Holder: EP's CS generate & apply the access_end_u_token to IoTD
            target_device_id = menu_user_agent_do.get_target_device_id()
            original_agent_order = user_agent_do.shared_data.device_table[
                target_device_id
            ].ticket_order
            user_agent_do = menu_user_agent_do.apply_access_end_token_through_bluetooth(
                target_device_id=target_device_id
            )

            # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
            assert "SUCCESS" in user_agent_do.shared_data.result_message
            assert (
                user_agent_do.shared_data.device_table[target_device_id].ticket_order
                == original_agent_order + 1
            )

            ######################################################
            # Do Not Collect Too Large Overhead (I/O Peak)
            ######################################################
            # UT=CRKE-1
            if (
                user_agent_do.shared_data.measure_rec["holder_apply_u_ticket"][
                    "cli_blocked_time"
                ]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue
            # =CRKE-1=CRKE-2
            if (
                user_agent_do.shared_data.measure_rec[
                    "_holder_recv_cr_ke_1_and_send_cr_ke_2"
                ]["comm_time"]
                > Environment.COMM_BLOCKING_TOLERANCE_TIME
            ):
                continue
            if (
                user_agent_do.shared_data.measure_rec[
                    "_holder_recv_cr_ke_1_and_send_cr_ke_2"
                ]["msg_blocked_time"]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue
            # =CRKE-3
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_cr_ke_3"][
                    "comm_time"
                ]
                > Environment.COMM_BLOCKING_TOLERANCE_TIME
            ):
                continue
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_cr_ke_3"][
                    "msg_blocked_time"
                ]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue
            # CMD=DATA/RT
            if (
                user_agent_do.shared_data.measure_rec["holder_send_cmd"][
                    "cli_blocked_time"
                ]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue
            # =DATA
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_data"]["comm_time"]
                > Environment.COMM_BLOCKING_TOLERANCE_TIME
            ):
                continue
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_data"][
                    "msg_blocked_time"
                ]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue
            # =RT
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_r_ticket"][
                    "comm_time"
                ]
                > Environment.COMM_BLOCKING_TOLERANCE_TIME
            ):
                continue
            if (
                user_agent_do.shared_data.measure_rec["_holder_recv_r_ticket"][
                    "msg_blocked_time"
                ]
                > Environment.IO_BLOCKING_TOLERANCE_TIME
            ):
                continue

            ######################################################
            # Collect Measurement Raw Data (user_agent_do)
            ######################################################
            user_agent_do_measure_rec = copy.deepcopy(
                user_agent_do.shared_data.measure_rec
            )
            measurement_statistics.append(user_agent_do_measure_rec)

            ######################################################
            # Print Measurement Raw Data (user_agent_do)
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
        print(f"[   M-REC] : + Grant Device Access Right (to owner herself)")
        print(f"[   M-REC] : {f'*' * 50}")

        # UT (can be pre-generated or dynamically generated when self-access)
        print(f"[   M-REC] : ")
        filtered_data = [
            data["issuer_issue_u_ticket_to_herself"]["cli_perf_time"]
            for data in measurement_statistics
        ]
        average_gen_ut_p0 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"issuer_issue_u_ticket_to_herself: cli_perf_time = \n\t\t"
            f"{average_gen_ut_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["issuer_issue_u_ticket_to_herself"]["cli_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"issuer_issue_u_ticket_to_herself: cli_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # UT=CRKE-1
        print(f"[   M-REC] : ")
        filtered_data = [
            data["holder_apply_u_ticket"]["cli_perf_time"]
            for data in measurement_statistics
        ]
        average_crke_p0 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_apply_u_ticket: cli_perf_time = \n\t\t"
            f"{average_crke_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["holder_apply_u_ticket"]["cli_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_apply_u_ticket: cli_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # =CRKE-1=CRKE-2
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_cr_ke_1_and_send_cr_ke_2"]["comm_time"]
            for data in measurement_statistics
        ]
        average_crke_c1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_1_and_send_cr_ke_2: comm_time = \n\t\t"
            f"{average_crke_c1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_1_and_send_cr_ke_2"]["message_size"]
            for data in measurement_statistics
        ]
        average = int(sum(filtered_data) / len(filtered_data))
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_1_and_send_cr_ke_2: message_size = \n\t\t"
            f"{average} bytes",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_1_and_send_cr_ke_2"]["msg_perf_time"]
            for data in measurement_statistics
        ]
        average_crke_p1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_1_and_send_cr_ke_2: msg_perf_time = \n\t\t"
            f"{average_crke_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_1_and_send_cr_ke_2"]["msg_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_1_and_send_cr_ke_2: msg_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # =CRKE-3
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_cr_ke_3"]["comm_time"] for data in measurement_statistics
        ]
        average_crke_c3 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_3: comm_time = \n\t\t"
            f"{average_crke_c3:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_3"]["message_size"]
            for data in measurement_statistics
        ]
        average = int(sum(filtered_data) / len(filtered_data))
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_3: message_size = \n\t\t"
            f"{average} bytes",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_3"]["msg_perf_time"]
            for data in measurement_statistics
        ]
        average_crke_p3 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_3: msg_perf_time = \n\t\t"
            f"{average_crke_p3:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_cr_ke_3"]["msg_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_cr_ke_3: msg_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # CMD=DATA/RT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["holder_send_cmd"]["cli_perf_time"] for data in measurement_statistics
        ]
        average_cmd_p0 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_send_cmd: cli_perf_time = \n\t\t"
            f"{average_cmd_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["holder_send_cmd"]["cli_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_send_cmd: cli_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # =DATA
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_data"]["comm_time"] for data in measurement_statistics
        ]
        average_cmd_data_c1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_data: comm_time = \n\t\t"
            f"{average_cmd_data_c1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_data"]["message_size"] for data in measurement_statistics
        ]
        average = int(sum(filtered_data) / len(filtered_data))
        print(
            f"[   M-REC] : "
            f"_holder_recv_data: message_size = \n\t\t"
            f"{average} bytes",
        )

        filtered_data = [
            data["_holder_recv_data"]["msg_perf_time"]
            for data in measurement_statistics
        ]
        average_cmd_data_p1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_data: msg_perf_time = \n\t\t"
            f"{average_cmd_data_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_data"]["msg_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_data: msg_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        # =RT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_r_ticket"]["comm_time"]
            for data in measurement_statistics
        ]
        average_cmd_rt_c1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: comm_time = \n\t\t"
            f"{average_cmd_rt_c1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_r_ticket"]["message_size"]
            for data in measurement_statistics
        ]
        average = int(sum(filtered_data) / len(filtered_data))
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: message_size = \n\t\t"
            f"{average} bytes",
        )

        filtered_data = [
            data["_holder_recv_r_ticket"]["msg_perf_time"]
            for data in measurement_statistics
        ]
        average_cmd_rt_p1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: msg_perf_time = \n\t\t"
            f"{average_cmd_rt_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["_holder_recv_r_ticket"]["msg_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: msg_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        ######################################################
        # Print Measurement Summary
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + [Summarize] Measurement Statistics")
        print(f"[   M-REC] : + Grant Device Access Right (to owner herself)")
        print(f"[   M-REC] : {f'*' * 50}")

        print(f"[   M-REC] : ")
        print(
            f"[   M-REC] : "
            f"Total GEN-UT Response Time = \n\t\t"
            f"{average_gen_ut_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        print(f"[   M-REC] : ")
        print(
            f"[   M-REC] : "
            f"Total CRKE Response Time = \n\t\t"
            f"{average_crke_p0  + average_crke_c1 + average_crke_p1 + average_crke_c3 + average_crke_p3:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        print(f"[   M-REC] : ")
        print(
            f"[   M-REC] : "
            f"Total CMD-DATA Response Time = \n\t\t"
            f"{average_cmd_p0 + average_cmd_data_c1 + average_cmd_data_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        print(f"[   M-REC] : ")
        print(
            f"[   M-REC] : "
            f"Total CMD-RT Response Time = \n\t\t"
            f"{average_cmd_p0 + average_cmd_rt_c1 + average_cmd_rt_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

    except RuntimeError as error:
        simple_log("error", f"{error}")
