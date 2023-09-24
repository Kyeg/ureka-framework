import inspect
import logging
from ureka_framework.logic.device_controller import DeviceController
from ureka_framework.data_model import u_ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel
from typing import Tuple


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
    logging.info("")
    if get_current_class_name() != None:
        logging.info("*" * 100)
        logging.info(f"Setup: {get_current_class_name()}")
        logging.info("*" * 100)


def current_test_given_log() -> None:
    # Log
    if (
        get_current_function_name() != "_hookexec"
        and get_current_function_name() != None
    ):
        logging.info("*" * 50)
        logging.info(f"Given: {get_current_function_name()}")
        logging.info("*" * 50)


def current_test_when_and_then_log() -> None:
    # Log
    if (
        get_current_function_name() != "_hookexec"
        and get_current_function_name() != None
    ):
        logging.info("*" * 50)
        logging.info(f"When & Then: {get_current_function_name()}")
        logging.info("*" * 50)


def current_teardown_log() -> None:
    # Log
    if get_current_class_name() != None:
        logging.info("*" * 100)
        logging.info(f"Teardown: {get_current_class_name()}")
        logging.info("*" * 100)


######################################################
# Helper Functions (Reusable Test Data)
######################################################
def create_comm_connection(end1: DeviceController, end2: DeviceController):
    fake_comm_ch = FakeCommChannel(ends=[end1, end2])
    end1._connect(fake_comm_ch)
    end2._connect(fake_comm_ch)


def device_manufacturer_server() -> DeviceController:
    # GIVEN: Initialized DM's CS
    cloud_server_dm = DeviceController(
        device_type=u_ticket.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_dm",
    )
    cloud_server_dm._execute_one_time_intialize_agent_or_server()

    return cloud_server_dm


def device_owner_agent() -> DeviceController:
    # GIVEN: Initialized DM's CS
    user_agent_do = DeviceController(
        device_type=u_ticket.USER_AGENT_OR_CLOUD_SERVER,
        device_name="user_agent_do",
    )
    user_agent_do._execute_one_time_intialize_agent_or_server()

    return user_agent_do


def device_manufacturer_server_and_her_device() -> (
    Tuple[DeviceController, DeviceController]
):
    # GIVEN: Initialized DM's CS
    cloud_server_dm = device_manufacturer_server()

    # GIVEN: Uninitialized IoTD
    iot_device = DeviceController(
        device_type=u_ticket.IOT_DEVICE,
        device_name="iot_device",
    )

    # WHEN: Issuer: DM's CS generate & send the intialization_u_ticket to Uninitialized IoTD
    create_comm_connection(cloud_server_dm, iot_device)
    id_for_initialization_u_ticket = "no_id"
    generated_request: dict = {
        "device_id": f"{id_for_initialization_u_ticket}",
        "holder_id": f"{cloud_server_dm.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        "task_scope": f"",
    }
    cloud_server_dm.issuer_issue_consent_to_herself(
        device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
    )
    cloud_server_dm.holder_access_device(id_for_initialization_u_ticket)

    # WHEN: Device: DO's IoTD receive the intialization_u_ticket
    iot_device.device_be_accessed()

    # WHEN: Holder: DM's CS receive the intialization_r_ticket
    cloud_server_dm.holder_receive_r_ticket()

    return (cloud_server_dm, iot_device)


def device_owner_agent_and_her_device() -> Tuple[DeviceController, DeviceController]:
    # GIVEN: Initialized DM's CS and DM's IoTD
    (
        cloud_server_dm,
        iot_device,
    ) = device_manufacturer_server_and_her_device()

    # GIVEN: Initialized DO's UA
    user_agent_do = device_owner_agent()

    # WHEN: Issuer: DM's CS generate & send the management_u_ticket to DO's UA
    create_comm_connection(cloud_server_dm, user_agent_do)
    owned_device_id = iot_device.this_device.device_pub_key_str
    generated_request: dict = {
        "device_id": f"{owned_device_id}",
        "holder_id": f"{user_agent_do.this_person.person_pub_key_str}",
        "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
        "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.TASK_SCOPE_MANAGEMENT: u_ticket.MANAGEMENT_OWNER})}",
    }
    cloud_server_dm.issuer_issue_consent_to_holder(
        device_id=owned_device_id, arbitrary_dict=generated_request
    )

    # WHEN: Holder: DO's UA receive & store the management_u_ticket
    user_agent_do.holder_receive_consent()

    # WHEN: Holder: DO's UA forward the management_u_ticket
    create_comm_connection(user_agent_do, iot_device)
    user_agent_do.holder_access_device(iot_device.this_device.device_pub_key_str)

    # WHEN: Device: DO's IoTD receive the management_u_ticket
    iot_device.device_be_accessed()

    # WHEN: Holder: DO's UA receive the management_r_ticket
    user_agent_do.holder_receive_r_ticket()

    return (user_agent_do, iot_device)


def enterprise_provider_server() -> DeviceController:
    # GIVEN: Initialized EP's CS
    cloud_server_ep = DeviceController(
        device_type=u_ticket.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_ep",
    )
    cloud_server_ep._execute_one_time_intialize_agent_or_server()

    return cloud_server_ep


def attacker_server() -> DeviceController:
    # GIVEN: Initialized ATK's CS
    cloud_server_atk = DeviceController(
        device_type=u_ticket.USER_AGENT_OR_CLOUD_SERVER,
        device_name="cloud_server_atk",
    )
    cloud_server_atk._execute_one_time_intialize_agent_or_server()

    return cloud_server_atk


def device_owner_agent_and_her_device_and_attacker() -> (
    Tuple[DeviceController, DeviceController, DeviceController]
):
    # GIVEN: Initialized DO's UA and DO's IoTD
    (
        user_agent_do,
        iot_device,
    ) = device_owner_agent_and_her_device()

    # GIVEN: Initialized ATK's CS
    cloud_server_atk = attacker_server()

    return (user_agent_do, iot_device, cloud_server_atk)


######################################################
# Fixtures (Reusable Test Data without Logging)
######################################################
