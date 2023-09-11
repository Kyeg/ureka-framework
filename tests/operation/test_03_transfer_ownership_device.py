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
        # WHEN: Issuer [RVEGTS]: DM's CS generate & send the management_u_ticket to DO's UA
        create_comm_connection(self.cloud_server_dm, self.user_agent_do)
        generated_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        generated_u_ticket = self.cloud_server_dm.issuer_issue_consent_to_holder(
            generated_request
        )
        logging.debug(f"Generated UTicket: {generated_u_ticket}")

        # WHEN: Holder [RVEGTS]: DO's UA receive & store the management_u_ticket
        received_u_ticket = self.user_agent_do.holder_receive_consent()
        logging.debug(f"Recveived UTicket: {received_u_ticket}")

        # WHEN: Holder [RVEGTS]: DO's UA forward the management_u_ticket
        create_comm_connection(self.user_agent_do, self.iot_device)
        stored_u_ticket = self.user_agent_do.holder_access_device(
            self.iot_device.this_device.device_pub_key_str
        )
        logging.debug(f"Stored UTicket: {stored_u_ticket}")

        # WHEN: Device [RVEGTS]: DO's IoTD receive the management_u_ticket
        forwarded_u_ticket = self.iot_device.device_be_accessed()
        logging.debug(f"Forwarded UTicket: {forwarded_u_ticket}")

        # THEN: Succeed to transfer ownership (become DO's IoTD)
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
        # WHEN: Issuer: [RVEGTS]
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
        self.cloud_server_dm._send_xxx_u_ticket(generated_u_ticket)

        # WHEN: Holder: [RVEGTS]
        # WHEN: DO's UA receive & store the management_u_ticket
        received_u_ticket: str = self.user_agent_do._recv_xxx_u_ticket()
        self.user_agent_do._store_recieved_xxx_u_ticket(received_u_ticket)
        logging.debug(f"Recveived UTicket: {received_u_ticket}")

        # WHEN: Holder: [RVEGTS]
        # WHEN: DO's UA forward the management_u_ticket
        create_comm_connection(self.user_agent_do, self.iot_device)
        stored_u_ticket: str = self.user_agent_do.device_table[
            self.iot_device.this_device.device_pub_key_str
        ].device_u_ticket
        logging.debug(f"Stored UTicket: {stored_u_ticket}")
        self.user_agent_do._send_xxx_u_ticket(stored_u_ticket)

        # WHEN: Device: [RVEGTS]
        # WHEN: DO's IoTD receive the management_u_ticket
        forwarded_u_ticket: str = self.iot_device._recv_xxx_u_ticket()
        self.user_agent_do._store_recieved_xxx_u_ticket(forwarded_u_ticket)
        logging.debug(f"Forwarded UTicket: {forwarded_u_ticket}")
        result = self.iot_device._verify_xxx_u_ticket(forwarded_u_ticket)

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
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
