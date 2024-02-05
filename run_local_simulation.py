######################################################
# Test Fixtures
######################################################
from ureka_framework.environment import Environment
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
)
from tests.conftest import (
    create_simulated_comm_connection,
    wait_simulated_comm_completed,
)
from tests.conftest import (
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
    device_owner_agent,
    device_owner_agent_and_her_device,
    device_owner_agent_and_her_session,
    enterprise_provider_server,
    enterprise_provider_server_and_her_session,
    attacker_server,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

######################################################
# Import
######################################################
from ureka_framework.resource.logger.simple_logger import simple_log
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr


def setup():
    # RE-GIVEN: Reset the test environment
    current_setup_log()
    SimpleStorage.delete_storage_in_test()


def teardown():
    # RE-GIVEN: Reset the test environment
    current_teardown_log()
    SimpleStorage.delete_storage_in_test()


def simulation_script():
    current_test_given_log()

    ######################################################
    # GIVEN:
    ######################################################
    simple_log("cli", "")
    simple_log("cli", "*" * 50)
    simple_log("cli", f"Preparing for the Local Simulation...")
    simple_log("cli", "*" * 50)
    simple_log("cli", "")

    ######################################################
    # GIVEN: Initialized DO's UA and DO's IoTD
    ######################################################
    simple_log("cli", "")
    input("[     CLI] : Press Enter to continue...")
    (user_agent_do, iot_device) = device_owner_agent_and_her_device()
    simple_log("cli", "")
    simple_log("cli", f"+++DO's UA and DO's IoTD are Initialized+++")

    ######################################################
    # GIVEN: Initialized EP's CS
    ######################################################
    simple_log("cli", "")
    input("[     CLI] : Press Enter to continue...")
    cloud_server_ep = enterprise_provider_server()
    simple_log("cli", "")
    simple_log("cli", f"+++EP's CS is Initialized+++")

    ######################################################
    # WHEN:
    ######################################################
    simple_log("cli", "")
    simple_log("cli", "*" * 50)
    simple_log("cli", f"Start Local Simulation...")
    simple_log("cli", "*" * 50)
    simple_log("cli", "")

    simple_log("cli", "")
    input("[     CLI] : Press Enter to continue...")
    current_test_when_and_then_log()

    ######################################################
    # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
    ######################################################
    create_simulated_comm_connection(user_agent_do, cloud_server_ep)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
    generated_request: dict = {
        "device_id": f"{target_device_id}",
        "holder_id": f"{cloud_server_ep.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
        "task_scope": f"{generated_task_scope}",
    }
    user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
        device_id=target_device_id, arbitrary_dict=generated_request
    )
    wait_simulated_comm_completed(cloud_server_ep, user_agent_do)
    simple_log("cli", "")
    simple_log("cli", f"+++EP's CS get an access ticket from DO's UA+++")

    ######################################################
    # WHEN: Holder: EP's CS forward the access_u_ticket
    ######################################################
    # generated_command = "HELLO-1"
    simple_log("cli", "")
    generated_command = input("[     CLI] : EP's CS enter 1st command to DO's IoTD: ")
    create_simulated_comm_connection(cloud_server_ep, iot_device)
    cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
        target_device_id, generated_command
    )
    wait_simulated_comm_completed(cloud_server_ep, iot_device)

    ######################################################
    # WHEN: Holder: EP's CS forward the u_token
    ######################################################
    # generated_command = "HELLO-2"
    simple_log("cli", "")
    generated_command = input("[     CLI] : EP's CS enter 2nd command to DO's IoTD: ")
    create_simulated_comm_connection(cloud_server_ep, iot_device)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=target_device_id, cmd=generated_command
    )
    wait_simulated_comm_completed(cloud_server_ep, iot_device)

    ######################################################
    # WHEN: Holder: EP's CS forward the u_token
    ######################################################
    # generated_command = "HELLO-3"
    simple_log("cli", "")
    generated_command = input("[     CLI] : EP's CS enter 3rd command to DO's IoTD: ")
    create_simulated_comm_connection(cloud_server_ep, iot_device)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=target_device_id, cmd=generated_command
    )
    wait_simulated_comm_completed(cloud_server_ep, iot_device)

    ######################################################
    # THEN: Show Response Time + Data Size Measurement
    ######################################################
    simple_log("cli", "")
    simple_log("cli", "*" * 50)
    simple_log("cli", f"Finish Local Simulation")
    simple_log("cli", "*" * 50)
    simple_log("cli", "")


if __name__ == "__main__":
    ######################################################
    # ENVIRONMENT
    ######################################################
    Environment.DEPLOYMENT_ENV = "PRODUCTION"
    Environment.DEBUG_LOG = "OPEN"
    Environment.CLI_LOG = "OPEN"
    Environment.MEASURE_LOG = "CLOSED"
    Environment.MORE_MEASURE_WORKER_LOG = "CLOSED"
    Environment.MORE_MEASURE_RESOURCE_LOG = "CLOSED"

    setup()

    simulation_script()

    teardown()
