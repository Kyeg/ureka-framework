import logging
from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    create_comm_connection,
    device_owner_agent,
    device_manufacturer_server_and_her_device,
    device_owner_agent_and_her_device,
    attacker_server,
)
from ureka_framework.data_model.other_device import OtherDevice
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestTransferOwnershipDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

    def test_apply_management_u_ticket_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate & send the management_u_ticket to DO's UA
        create_comm_connection(self.cloud_server_dm, self.user_agent_do)
        generated_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        self.cloud_server_dm.issuer_issue_consent_to_holder(generated_request)

        # WHEN: Holder: DO's UA receive & store the management_u_ticket
        self.user_agent_do.holder_receive_consent()

        # WHEN: Holder: DO's UA forward the management_u_ticket
        create_comm_connection(self.user_agent_do, self.iot_device)
        self.user_agent_do.holder_access_device(
            self.iot_device.this_device.device_pub_key_str
        )

        # WHEN: Device: DO's IoTD receive the management_u_ticket
        self.iot_device.device_be_accessed()

        # WHEN: Holder: DO's UA receive the management_r_ticket
        self.user_agent_do.holder_receive_r_ticket()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket_wrong_owner_failed_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_management_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # WHEN: Issuer: ATK's CS pretend she own the device (in her device_table)
        target_device_id = self.iot_device.this_device.device_pub_key_str
        self.cloud_server_atk.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_name="device_id's name",
            device_u_ticket="not important",
        )
        # WHEN: Issuer: ATK's CS generate & send the management_u_ticket by her person_pub_key
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        self.cloud_server_atk.issuer_issue_consent_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )

        # WHEN: Holder: ATK's CS forward the management_u_ticket
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        self.cloud_server_atk.holder_access_device(
            self.iot_device.this_device.device_pub_key_str
        )

        # WHEN: Device: DO's IoTD receive the management_u_ticket
        self.iot_device.device_be_accessed()

        # WHEN: Holder: ATK's CS receive the management_r_ticket
        self.cloud_server_atk.holder_receive_r_ticket()

        # THEN: Fail to transfer ownership (still DO's IoTD)
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket_with_storage_and_comm(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer:
        # WHEN: DM's CS generate & send the management_u_ticket for DO's UA
        create_comm_connection(self.cloud_server_dm, self.user_agent_do)
        generated_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        generated_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(
            generated_request
        )
        logging.debug(f"Generated UTicket: {generated_u_ticket}")
        self.cloud_server_dm._send_xxx_message(generated_u_ticket)

        # WHEN: Holder:
        # WHEN: DO's UA receive & store the management_u_ticket
        received_u_ticket: str = self.user_agent_do._recv_xxx_message()
        device_id = self.user_agent_do._store_recieved_xxx_u_ticket(received_u_ticket)
        logging.debug(f"Recveived UTicket: {received_u_ticket}")

        # WHEN: Holder:
        # WHEN: DO's UA forward the management_u_ticket
        create_comm_connection(self.user_agent_do, self.iot_device)
        stored_u_ticket: str = self.user_agent_do.device_table[
            device_id
        ].device_u_ticket
        logging.debug(f"Stored & Forwarded UTicket: {stored_u_ticket}")
        self.user_agent_do._send_xxx_message(stored_u_ticket)

        # WHEN: Device:
        # WHEN: DO's IoTD receive the management_u_ticket
        recveived_u_ticket: str = self.iot_device._recv_xxx_message()
        self.user_agent_do._store_recieved_xxx_u_ticket(recveived_u_ticket)
        result = self.iot_device._verify_xxx_u_ticket(recveived_u_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS allow DO's UA to apply_management_u_ticket() on DM's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        test_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket_with_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # WHEN: Reboot the DO's IoTD
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still is successful to transfer ownership (become DO's IoTD)
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_management_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        test_u_ticket: str = self.cloud_server_atk._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Fail to transfer ownership (still DO's IoTD)
        assert type(result) == Failure
        assert (
            result.failure().args[0]
            == "-> FAILURE: VERIFY_ISSUER_SIGNATURE on MANAGEMENT UTICKET"
        )
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
