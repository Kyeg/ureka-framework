from ureka_framework.environment import Environment
from ureka_framework.resource.logger.simple_logger import simple_log
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
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    dict_to_jsonstr,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage


def setup():
    # RE-GIVEN: Reset the test environment
    current_setup_log()
    SimpleStorage.delete_storage_in_test()


def teardown():
    # RE-GIVEN: Reset the test environment
    current_teardown_log()
    SimpleStorage.delete_storage_in_test()


def test_script():
    current_test_given_log()
    simple_log("demo", "*" * 50)
    simple_log("demo", f"Preparing for the demo...")
    simple_log("demo", "*" * 50)
    input("\nPress Enter to continue...")

    # GIVEN: Initialized DO's UA and DO's IoTD
    (
        user_agent_do,
        iot_device,
    ) = device_owner_agent_and_her_device()
    simple_log("demo", f"\n+++DO's UA and DO's IoTD are Initialized+++")
    input("\nPress Enter to continue...")

    # GIVEN: Initialized EP's CS
    cloud_server_ep = enterprise_provider_server()
    simple_log("demo", f"\n+++EP's CS is Initialized+++")
    input("\nPress Enter to continue...")

    # WHEN:
    current_test_when_and_then_log()

    # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
    create_comm_connection(user_agent_do, cloud_server_ep)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    resource_tree = dict_to_jsonstr(
        {
            "SAY-HELLO": "allow",
            "SAY-GOOD-MORNING": "allow",
            "SAY-GOOD-NIGHT": "forbid",
        }
    )
    generated_task_scope = dict_to_jsonstr(
        {u_ticket.TASK_SCOPE_RESOURCE_TREE: resource_tree}
    )
    generated_request: dict = {
        "device_id": f"{owned_device_id}",
        "holder_id": f"{cloud_server_ep.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
        "task_scope": f"{generated_task_scope}",
    }
    user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
        device_id=owned_device_id, arbitrary_dict=generated_request
    )
    wait_comm_completed(cloud_server_ep, user_agent_do)
    simple_log("demo", f"\n+++EP's CS get an access ticket from DO's UA+++")

    # WHEN: Holder: EP's CS forward the access_u_ticket
    create_comm_connection(cloud_server_ep, iot_device)
    # generated_command = "HELLO"
    generated_command = input("\nEP's CS enter 1st command to DO's IoTD: ")
    cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
        owned_device_id, generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)

    # WHEN:
    current_test_when_and_then_log()

    # WHEN: Holder: EP's CS forward the u_token
    create_comm_connection(cloud_server_ep, iot_device)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    # generated_command = "HELLO-2"
    generated_command = input("\nEP's CS enter 2nd command to DO's IoTD: ")
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=owned_device_id, cmd=generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)

    # WHEN: Holder: EP's CS forward the u_token
    create_comm_connection(cloud_server_ep, iot_device)
    owned_device_id = iot_device.shared_data.this_device.device_pub_key_str
    # generated_command = "HELLO-3"
    generated_command = input("\nEP's CS enter 3rd command to DO's IoTD: ")
    cloud_server_ep.flow_issue_u_token.holder_send_cmd(
        device_id=owned_device_id, cmd=generated_command
    )
    wait_comm_completed(cloud_server_ep, iot_device)


if __name__ == "__main__":
    # Environment.DEPLOYMENT_ENV = "PRODUCTION"
    Environment.DEPLOYMENT_ENV = "DEMO"

    setup()
    test_script()
    teardown()
