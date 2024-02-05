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
        # Transfer Device Ownership
        ######################################################
        MenuAgentOrServer.set_environment("measurement")

        # GIVEN: Initialized DO's UA
        menu_cloud_server_dm = MenuAgentOrServer(device_name="cloud_server_dm")
        menu_user_agent_do = MenuAgentOrServer(device_name="user_agent_do")

        # Repeatly measure the overhead
        times = 0
        measurement_statistics = list()
        while times < Environment.MEASUREMENT_REPEAT_TIMES:
            ######################################################
            # Transfer Device Ownership (Back: UA to DM)
            ######################################################
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Transfer Device Ownership (Back: UA to DM)")
            print(f"[   M-REC] : {f'*' * 50}")

            ###########################

            # GIVEN: Initialized DM's CS
            cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
            # GIVEN: Initialized DO's UA
            user_agent_do = menu_user_agent_do.get_agent_or_server()

            ###########################

            # WHEN: Issuer: DO's UA generate & send the ownership_u_ticket to DM's CS
            target_device_id = menu_user_agent_do.get_target_device_id()
            menu_user_agent_do.issue_ownership_ticket_through_simulated_comm(
                target_device_id=target_device_id,
                new_owner=cloud_server_dm,
            )

            ###########################

            # WHEN: Holder: DM's CS apply the ownership_u_ticket to IoTD
            target_device_id = menu_cloud_server_dm.get_target_device_id()
            cloud_server_dm = (
                menu_cloud_server_dm.apply_ownership_ticket_through_bluetooth(
                    target_device_id=target_device_id
                )
            )

            # THEN: Succeed to transfer ownership (& update ticket_order of DO's IoTD)
            assert "SUCCESS" in cloud_server_dm.shared_data.result_message

            ###########################

            # WHEN: Holder:  DM's CS return the ownership_r_ticket to DO's UA
            menu_cloud_server_dm.return_r_ticket_through_simulated_comm(
                target_device_id=target_device_id,
                original_issuer=user_agent_do,
            )

            # THEN: Issuer: DM's CS know that DO's UA has become the new owner of DO's IoTD (& ticket order++)
            assert "SUCCESS" in user_agent_do.shared_data.result_message
            assert user_agent_do.shared_data.device_table.get(target_device_id) == None

            ######################################################
            # Transfer Device Ownership (DM to UA)
            ######################################################
            print(f"[   M-REC] : ")
            print(f"[   M-REC] : {f'*' * 50}")
            print(f"[   M-REC] : + Transfer Device Ownership (DM to UA)")
            print(f"[   M-REC] : {f'*' * 50}")

            ###########################

            # GIVEN: Initialized DM's CS
            cloud_server_dm = menu_cloud_server_dm.get_agent_or_server()
            # GIVEN: Initialized DO's UA
            user_agent_do = menu_user_agent_do.intialize_agent_or_server_through_cli()

            ###########################

            # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
            target_device_id = menu_cloud_server_dm.get_target_device_id()
            menu_cloud_server_dm.issue_ownership_ticket_through_simulated_comm(
                target_device_id=target_device_id,
                new_owner=user_agent_do,
            )

            ###########################

            # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
            target_device_id = menu_user_agent_do.get_target_device_id()
            user_agent_do = menu_user_agent_do.apply_ownership_ticket_through_bluetooth(
                target_device_id=target_device_id
            )

            # THEN: Succeed to transfer ownership (& update ticket_order of DO's IoTD)
            assert "SUCCESS" in user_agent_do.shared_data.result_message

            ###########################

            # WHEN: Holder: DO's UA return the ownership_r_ticket to DM's CS
            menu_user_agent_do.return_r_ticket_through_simulated_comm(
                target_device_id=target_device_id,
                original_issuer=cloud_server_dm,
            )

            # THEN: Issuer: DM's CS know that DO's UA has become the new owner of DO's IoTD (& ticket order++)
            assert "SUCCESS" in cloud_server_dm.shared_data.result_message
            assert (
                cloud_server_dm.shared_data.device_table.get(target_device_id) == None
            )

            ######################################################
            # Do Not Collect Too Large Overhead (I/O Peak)
            ######################################################
            # CMD=DATA/RT
            if (
                user_agent_do.shared_data.measure_rec["holder_apply_u_ticket"][
                    "cli_blocked_time"
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
        print(f"[   M-REC] : + Transfer Device Ownership")
        print(f"[   M-REC] : {f'*' * 50}")

        # =UT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_u_ticket"]["message_size"]
            for data in measurement_statistics
        ]
        average = int(sum(filtered_data) / len(filtered_data))
        print(
            f"[   M-REC] : "
            f"_holder_recv_u_ticket: message_size = \n\t\t"
            f"{average} bytes",
        )

        # UT=RT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["holder_apply_u_ticket"]["cli_perf_time"]
            for data in measurement_statistics
        ]
        average_ut_rt_p0 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_apply_u_ticket: cli_perf_time = \n\t\t"
            f"{average_ut_rt_p0:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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

        # =RT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["_holder_recv_r_ticket"]["comm_time"]
            for data in measurement_statistics
        ]
        average_ut_rt_c1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: comm_time = \n\t\t"
            f"{average_ut_rt_c1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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
        average_ut_rt_p1 = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"_holder_recv_r_ticket: msg_perf_time = \n\t\t"
            f"{average_ut_rt_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
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

        # RT=RT
        print(f"[   M-REC] : ")
        filtered_data = [
            data["holder_send_r_ticket_to_issuer"]["cli_perf_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_send_r_ticket_to_issuer: cli_perf_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        filtered_data = [
            data["holder_send_r_ticket_to_issuer"]["cli_blocked_time"]
            for data in measurement_statistics
        ]
        average = sum(filtered_data) / len(filtered_data)
        print(
            f"[   M-REC] : "
            f"holder_send_r_ticket_to_issuer: cli_blocked_time = \n\t\t"
            f"{average:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

        ######################################################
        # Print Measurement Summary
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + [Summarize] Measurement Statistics")
        print(f"[   M-REC] : + Transfer Device Ownership")
        print(f"[   M-REC] : {f'*' * 50}")

        print(f"[   M-REC] : ")
        print(
            f"[   M-REC] : "
            f"Total UT-RT Response Time = \n\t\t"
            f"{average_ut_rt_p0  + average_ut_rt_c1 + average_ut_rt_p1:{Environment.MEASUREMENT_TIME_PRECISION}} seconds",
        )

    except RuntimeError as error:
        simple_log("error", f"{error}")
