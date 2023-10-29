from ureka_framework.environment import Environment
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    create_comm_connection,
    enterprise_provider_server_and_her_session,
    wait_comm_completed,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
    attacker_server,
)
from ureka_framework.resource.logger.simple_logger import simple_log
from ureka_framework.resource.logger.simple_measurer import (
    start_simple_timer,
    get_process_time,
    simple_size_calculator,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr
import time, timeit


def setup():
    # RE-GIVEN: Reset the test environment
    current_setup_log()
    SimpleStorage.delete_storage_in_test()


def teardown():
    # RE-GIVEN: Reset the test environment
    current_teardown_log()
    SimpleStorage.delete_storage_in_test()


def test_computing_time():
    simple_log("demo", f"\n\n\n")

    start_timer = timeit.default_timer()
    simple_log("demo", f"start_timer: {start_timer}")
    start_perf_counter = time.perf_counter()
    simple_log("demo", f"start_perf_counter: {start_perf_counter}")
    start_process_time = time.process_time()
    simple_log("demo", f"start_process_time: {start_process_time}")

    simple_log("demo", f"\nsleeping...")
    time.sleep(3)
    simple_log("demo", f"wake up...\n")

    simple_log("demo", f"\ncomputing...")
    result = sum(i**2**3 for i in range(1, 3 * 10**7))
    simple_log("demo", f"computing result = {result}...\n")

    end_timer = timeit.default_timer()
    simple_log("demo", f"end_timer: {end_timer}")
    end_perf_counter = time.perf_counter()
    simple_log("demo", f"end_perf_counter: {end_perf_counter}")
    end_process_time = time.process_time()
    simple_log("demo", f"end_process_time: {end_process_time}")

    simple_log("demo", f"elapsed_timer (with sleep) = {end_timer - start_timer}")
    simple_log(
        "demo",
        f"elapsed_perf_counter (with sleep) = {end_perf_counter - start_perf_counter}",
    )
    simple_log(
        "demo",
        f"elapsed_process_time (without sleep) = {end_process_time - start_process_time}",
    )

    return end_process_time - start_process_time


def test_computing_and_print_time():
    simple_log("demo", f"\n\n\n")

    start_timer = timeit.default_timer()
    simple_log("demo", f"start_timer: {start_timer}")
    start_perf_counter = time.perf_counter()
    simple_log("demo", f"start_perf_counter: {start_perf_counter}")
    start_process_time = time.process_time()
    simple_log("demo", f"start_process_time: {start_process_time}")

    simple_log("demo", f"\nsleeping...")
    time.sleep(3)
    simple_log("demo", f"wake up...\n")

    simple_log("demo", f"\ncomputing...")
    result = sum(i**2**3 for i in range(1, 3 * 10**7))
    for i in range(1, 10**6):
        print(f"P", end="")
    simple_log("demo", f"computing result = {result}...\n")

    end_timer = timeit.default_timer()
    simple_log("demo", f"end_timer: {end_timer}")
    end_perf_counter = time.perf_counter()
    simple_log("demo", f"end_perf_counter: {end_perf_counter}")
    end_process_time = time.process_time()
    simple_log("demo", f"end_process_time: {end_process_time}")

    simple_log("demo", f"elapsed_timer (with sleep) = {end_timer - start_timer}")
    simple_log(
        "demo",
        f"elapsed_perf_counter (with sleep) = {end_perf_counter - start_perf_counter}",
    )
    simple_log(
        "demo",
        f"elapsed_process_time (without sleep) = {end_process_time - start_process_time}",
    )

    return end_process_time - start_process_time


def test_script():
    current_test_given_log()

    ######################################################
    # GIVEN:
    ######################################################
    simple_log("demo", "\n")
    simple_log("demo", "*" * 50)
    simple_log("demo", f"Preparing for the demo...")
    simple_log("demo", "*" * 50)
    simple_log("demo", "\n")

    ######################################################
    # GIVEN: Initialized DO's UA and DO's IoTD
    ######################################################
    input("\nPress Enter to continue...")
    start_simple_timer()
    (user_agent_do, iot_device) = device_owner_agent_and_her_device()
    process_time_init_agent_and_device: float = get_process_time()
    simple_log("demo", f"\n+++DO's UA and DO's IoTD are Initialized+++")

    ######################################################
    # GIVEN: Initialized EP's CS
    ######################################################
    input("\nPress Enter to continue...")
    start_simple_timer()
    cloud_server_ep = enterprise_provider_server()
    process_time_init_agent: float = get_process_time()
    simple_log("demo", f"\n+++EP's CS is Initialized+++")

    ######################################################
    # WHEN:
    ######################################################
    simple_log("demo", "\n")
    simple_log("demo", "*" * 50)
    simple_log("demo", f"Demo...")
    simple_log("demo", "*" * 50)
    simple_log("demo", "\n")

    input("\nPress Enter to continue...")
    current_test_when_and_then_log()

    ######################################################
    # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
    ######################################################
    create_comm_connection(user_agent_do, cloud_server_ep)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
    generated_request: dict = {
        "device_id": f"{owned_device_id}",
        "holder_id": f"{cloud_server_ep.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
        "task_scope": f"{generated_task_scope}",
    }
    start_simple_timer()
    user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
        device_id=owned_device_id, arbitrary_dict=generated_request
    )
    wait_comm_completed(cloud_server_ep, user_agent_do)
    process_time_issuer_issue_u_ticket_to_holder: float = get_process_time()
    simple_log("demo", f"\n+++EP's CS get an access ticket from DO's UA+++")

    ######################################################
    # WHEN: Holder: EP's CS forward the access_u_ticket
    ######################################################
    create_comm_connection(cloud_server_ep, iot_device)
    # generated_command = "HELLO-1"
    generated_command = input("\nEP's CS enter 1st command to DO's IoTD: ")
    start_simple_timer()
    cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
        owned_device_id, generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)
    process_time_holder_apply_u_ticket: float = get_process_time()

    ######################################################
    # WHEN: Holder: EP's CS forward the u_token
    ######################################################
    create_comm_connection(cloud_server_ep, iot_device)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    # generated_command = "HELLO-2"
    generated_command = input("\nEP's CS enter 2nd command to DO's IoTD: ")
    start_simple_timer()
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=owned_device_id, cmd=generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)
    process_time_holder_send_cmd_2: float = get_process_time()

    ######################################################
    # WHEN: Holder: EP's CS forward the u_token
    ######################################################
    create_comm_connection(cloud_server_ep, iot_device)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    # generated_command = "HELLO-3"
    generated_command = input("\nEP's CS enter 3rd command to DO's IoTD: ")
    start_simple_timer()
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=owned_device_id, cmd=generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)
    process_time_holder_send_cmd_3: float = get_process_time()
    message_size_holder_send_cmd_3: int = simple_size_calculator(
        iot_device.shared_data.received_message_json
    )

    ######################################################
    # THEN: Response Time + Data Size Measurement
    ######################################################
    simple_log("demo", "\n")
    simple_log("demo", "*" * 50)
    simple_log("demo", f"Measurement result for demo...")
    simple_log("demo", "*" * 50)
    simple_log("demo", "\n")

    # THEN: Response Time Measurement
    simple_log(
        "demo",
        f"process_time_init_agent_and_device = {process_time_init_agent_and_device:.4f} seconds",
    )
    simple_log(
        "demo",
        f"process_time_init_agent = {process_time_init_agent:.4f} seconds",
    )
    simple_log(
        "demo",
        f"process_time_issuer_issue_u_ticket_to_holder = {process_time_issuer_issue_u_ticket_to_holder:.4f} seconds",
    )
    simple_log(
        "demo",
        f"process_time_holder_apply_u_ticket = {process_time_holder_apply_u_ticket:.4f} seconds",
    )
    simple_log(
        "demo",
        f"process_time_holder_send_cmd_2 = {process_time_holder_send_cmd_2:.4f} seconds",
    )
    simple_log(
        "demo",
        f"process_time_holder_send_cmd_3 = {process_time_holder_send_cmd_3:.4f} seconds",
    )

    # THEN: Data Size Measurement
    simple_log("demo", "\n")
    simple_log(
        "demo",
        f"message_holder_send_cmd_3 = \n{iot_device.shared_data.received_message_json}",
    )
    simple_log(
        "demo",
        f"message_size_holder_send_cmd_3 = {message_size_holder_send_cmd_3} bytes",
    )


if __name__ == "__main__":
    # Environment.DEPLOYMENT_ENV = "PRODUCTION"
    Environment.DEPLOYMENT_ENV = "DEMO"

    setup()

    # # Print cost is little, but it is not zero
    # simple_log(
    #     "demo",
    #     f"Print cost = {test_computing_time() - test_computing_and_print_time()}",
    # )

    test_script()

    teardown()
