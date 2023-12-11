import inspect
from ureka_framework.resource.logger.simple_logger import simple_log

from typing import Tuple
from ureka_framework.logic.device_controller import DeviceController
from ureka_framework.model.message_model import u_ticket
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr


######################################################
# Helper Functions
######################################################
def get_current_class_name() -> str:
    # Get Current Class Name
    for frame_info in inspect.stack():
        frame_locals = frame_info.frame.f_locals
        if "self" in frame_locals:
            return frame_locals["self"].__class__.__name__


def get_current_function_name() -> str:
    # Get Current Function Name called by the test
    for frame_info in inspect.stack():
        frame_locals = frame_info.frame.f_locals
        if "self" in frame_locals:
            return frame_info.function


def current_setup_log() -> None:
    # Log
    simple_log("info", "")
    if get_current_class_name() != None:
        simple_log("info", "*" * 100)
        simple_log("info", f"Setup: {get_current_class_name()}")
        simple_log("info", "*" * 100)


def current_test_given_log() -> None:
    # Log
    if (
        get_current_function_name() != "_hookexec"
        and get_current_function_name() != None
    ):
        simple_log("info", "*" * 50)
        simple_log("info", f"Given: {get_current_function_name()}")
        simple_log("info", "*" * 50)


def current_test_when_and_then_log() -> None:
    # Log
    if (
        get_current_function_name() != "_hookexec"
        and get_current_function_name() != None
    ):
        simple_log("info", "*" * 50)
        simple_log("info", f"When & Then: {get_current_function_name()}")
        simple_log("info", "*" * 50)


def current_teardown_log() -> None:
    # Log
    if get_current_class_name() != None:
        simple_log("info", "*" * 100)
        simple_log("info", f"Teardown: {get_current_class_name()}")
        simple_log("info", "*" * 100)


######################################################
# Helper Functions (Simulated Comm)
######################################################
def create_simulated_comm_connection(end1: DeviceController, end2: DeviceController):
    # # Re-open the sender/receiver
    # end1.msg_sender.start_simulated_comm()
    # end2.msg_sender.start_simulated_comm()

    # Set Sender (on Main Thread) & Start Reciever Thread
    end1.msg_receiver.create_simulated_comm_connection(end2)
    end2.msg_receiver.create_simulated_comm_connection(end1)

    simple_log(
        "info",
        f"+ Connection between {end1.shared_data.this_device.device_name} and {end2.shared_data.this_device.device_name} is started...",
    )


def wait_simulated_comm_completed(end1: DeviceController, end2: DeviceController):
    # Wait for all sender/receiver to finish their works (block last 1st make log beautiful)
    end1.msg_sender.wait_simulated_comm_completed()
    end2.msg_sender.wait_simulated_comm_completed()

    simple_log(
        "info",
        f"+ Connection between {end1.shared_data.this_device.device_name} and {end2.shared_data.this_device.device_name} is completed...",
    )
    simple_log("info", "")
    simple_log("info", "")
    simple_log("info", "")


######################################################
# Helper Functions (Reusable Test Data)
######################################################
def device_manufacturer_server() -> DeviceController:
    # GIVEN: Initialized DM's CS
    cloud_server_dm = DeviceController(
        device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_dm",
    )
    cloud_server_dm.executor._execute_one_time_intialize_agent_or_server()

    return cloud_server_dm


def device_manufacturer_server_and_her_device() -> (
    Tuple[DeviceController, DeviceController]
):
    # GIVEN: Initialized DM's CS
    cloud_server_dm = device_manufacturer_server()

    # GIVEN: Uninitialized IoTD
    iot_device = DeviceController(
        device_type=this_device.IOT_DEVICE,
        device_name="iot_device",
    )

    # WHEN: Issuer: DM's CS generate & send the intialization_u_ticket to Uninitialized IoTD
    create_simulated_comm_connection(cloud_server_dm, iot_device)
    id_for_initialization_u_ticket = "no_id"
    generated_request: dict = {
        "device_id": f"{id_for_initialization_u_ticket}",
        "holder_id": f"{cloud_server_dm.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
    }
    cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
        device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
    )
    cloud_server_dm.flow_apply_u_ticket.holder_apply_u_ticket(
        id_for_initialization_u_ticket
    )
    wait_simulated_comm_completed(cloud_server_dm, iot_device)

    return (cloud_server_dm, iot_device)


def device_owner_agent() -> DeviceController:
    # GIVEN: Initialized DM's CS
    user_agent_do = DeviceController(
        device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
        device_name="user_agent_do",
    )
    user_agent_do.executor._execute_one_time_intialize_agent_or_server()

    return user_agent_do


def device_owner_agent_and_her_device() -> Tuple[DeviceController, DeviceController]:
    # GIVEN: Initialized DM's CS and DM's IoTD
    (
        cloud_server_dm,
        iot_device,
    ) = device_manufacturer_server_and_her_device()

    # GIVEN: Initialized DO's UA
    user_agent_do = device_owner_agent()

    # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
    create_simulated_comm_connection(cloud_server_dm, user_agent_do)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_request: dict = {
        "device_id": f"{target_device_id}",
        "holder_id": f"{user_agent_do.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
    }
    cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
        device_id=target_device_id, arbitrary_dict=generated_request
    )
    wait_simulated_comm_completed(user_agent_do, cloud_server_dm)

    # WHEN: Holder: DO's UA forward the ownership_u_ticket
    create_simulated_comm_connection(user_agent_do, iot_device)
    user_agent_do.flow_apply_u_ticket.holder_apply_u_ticket(target_device_id)
    wait_simulated_comm_completed(user_agent_do, iot_device)

    return (user_agent_do, iot_device)


def device_owner_agent_and_her_session() -> Tuple[DeviceController, DeviceController]:
    # GIVEN: Initialized DO's UA and DO's IoTD
    (
        user_agent_do,
        iot_device,
    ) = device_owner_agent_and_her_device()

    # WHEN:
    current_test_when_and_then_log()

    # WHEN: Issuer: DO's UA generate the self_access_u_ticket to herself
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
    generated_request: dict = {
        "device_id": f"{target_device_id}",
        "holder_id": f"{user_agent_do.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_SELFACCESS_UTICKET}",
        "task_scope": f"{generated_task_scope}",
    }
    user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
        device_id=target_device_id, arbitrary_dict=generated_request
    )

    # WHEN: Holder: DO's UA forward the self_access_u_ticket
    create_simulated_comm_connection(user_agent_do, iot_device)
    generated_command = "HELLO-1"
    user_agent_do.flow_apply_u_ticket.holder_apply_u_ticket(
        target_device_id, generated_command
    )
    wait_simulated_comm_completed(user_agent_do, iot_device)

    return (user_agent_do, iot_device)


def enterprise_provider_server() -> DeviceController:
    # GIVEN: Initialized EP's CS
    cloud_server_ep = DeviceController(
        device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_ep",
    )
    cloud_server_ep.executor._execute_one_time_intialize_agent_or_server()

    return cloud_server_ep


def enterprise_provider_server_and_her_session() -> (
    Tuple[DeviceController, DeviceController, DeviceController]
):
    # GIVEN: Initialized DO's UA and DO's IoTD
    (
        user_agent_do,
        iot_device,
    ) = device_owner_agent_and_her_device()

    # GIVEN: Initialized EP's CS
    cloud_server_ep = enterprise_provider_server()

    # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
    create_simulated_comm_connection(user_agent_do, cloud_server_ep)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
    generated_request: dict = {
        "device_id": f"{target_device_id}",
        "holder_id": f"{cloud_server_ep.shared_data.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
        "task_scope": f"{generated_task_scope}",
    }
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

    # WHEN: Holder: EP's CS forward the access_u_ticket
    create_simulated_comm_connection(cloud_server_ep, iot_device)
    generated_command = "HELLO-1"
    cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
        target_device_id, generated_command
    )
    wait_simulated_comm_completed(cloud_server_ep, iot_device)

    return (user_agent_do, cloud_server_ep, iot_device)


def enterprise_provider_server_and_her_limited_session() -> (
    Tuple[DeviceController, DeviceController, DeviceController]
):
    # GIVEN: Initialized DO's UA and DO's IoTD
    (
        user_agent_do,
        iot_device,
    ) = device_owner_agent_and_her_device()

    # GIVEN: Initialized EP's CS
    cloud_server_ep = enterprise_provider_server()

    # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
    create_simulated_comm_connection(user_agent_do, cloud_server_ep)
    target_device_id = iot_device.shared_data.this_device.device_pub_key_str
    generated_task_scope = dict_to_jsonstr(
        {
            "SAY-HELLO-1": "allow",
            "SAY-HELLO-2": "allow",
            "SAY-HELLO-3": "forbid",
        }
    )
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

    # WHEN: Holder: EP's CS forward the access_u_ticket
    create_simulated_comm_connection(cloud_server_ep, iot_device)
    generated_command = "HELLO-1"
    cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
        target_device_id, generated_command
    )
    wait_simulated_comm_completed(cloud_server_ep, iot_device)

    return (user_agent_do, cloud_server_ep, iot_device)


def attacker_server() -> DeviceController:
    # GIVEN: Initialized ATK's CS
    cloud_server_atk = DeviceController(
        device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_atk",
    )
    cloud_server_atk.executor._execute_one_time_intialize_agent_or_server()

    return cloud_server_atk


######################################################
# Fixtures (Reusable Test Data without Logging)
######################################################
