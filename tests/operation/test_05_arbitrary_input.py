import logging
from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device_and_attacker,
    enterprise_provider_server,
)
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.simple_storage import SimpleStorage
import ureka_framework.data_model.u_ticket as u_ticket
from typing import Iterator


class TestArbitraryInput:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized ATK's CS
        current_test_given_log()
        (
            self.user_agent_do,
            self.iot_device,
            self.cloud_server_atk,
        ) = device_owner_agent_and_her_device_and_attacker()

        # WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

    def test_apply_wrong_json_schema(self) -> None:
        # WHEN: Not fit with json format '{"key": "value"}'
        current_test_when_and_then_log()
        test_u_ticket: str = "WRONG-JSON-SCHEMA"
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Raise the RuntimeError (Invalid JSON)
        assert type(result) == Failure

    def test_generate_wrong_u_ticket_schema_undefined_type(self) -> None:
        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: Wrong u_ticket schema type
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": 123,
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        with pytest.raises(RuntimeError) as generate_xxx_u_ticket_error_info:
            test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)

        # THEN: Raise the RuntimeError (Input should be a valid string)
        assert (
            str(generate_xxx_u_ticket_error_info.value)
            == "-> FAILURE: GENERATE_UTICKET"
        )

    def test_generate_wrong_u_ticket_schema_undefined_field(self) -> None:
        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: All other formats are correct (e.g., a legal management u_ticket here), but exist undefined u_ticket field in UTicket
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
            "undefined_u_ticket_field": "UNDEFINED-UTICKET-FIELD",
        }
        with pytest.raises(RuntimeError) as generate_xxx_u_ticket_error_info:
            test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)
            logging.debug(f"test_u_ticket = {test_u_ticket}")

        # THEN: Raise the RuntimeError
        assert (
            str(generate_xxx_u_ticket_error_info.value)
            == "-> FAILURE: GENERATE_UTICKET"
        )

    def test_apply_wrong_u_ticket_schema_undefined_field(self) -> None:
        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: All other formats are correct (e.g., a legal management u_ticket here)
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)
        logging.debug(f"test_u_ticket = {test_u_ticket}")

        # WHEN: Issuer bypasses the legal u_ticket generator & adds undefined u_ticket field in UTicket (& add signature)
        modified_test_u_ticket: str = (
            test_u_ticket[0:-2]
            + ",\n"
            + '\t"undefined_u_ticket_field": "UNDEFINED-UTICKET-FIELD"'
            + test_u_ticket[-2:]
        )
        logging.debug(f"modified_test_u_ticket = {modified_test_u_ticket}")

        # WHEN: Verify the modified u_ticket
        result = self.iot_device._verify_xxx_u_ticket(modified_test_u_ticket)

        # THEN: Raise the RuntimeError (Extra inputs are not permitted)
        assert type(result) == Failure
        assert (
            result.failure().args[0]
            == "-> FAILURE: VERIFY_JSON_SCHEMA: NOT VALID JSON or VALID SCHEMA"
        )

    def test_apply_wrong_protocol_version(self) -> None:
        # WHEN: Wrong u_ticket protocol version
        current_test_when_and_then_log()
        test_u_ticket: str = '{"protocol_verision": "WRONG-PROTOCOL-VERSION"}'
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    def test_apply_wrong_u_ticket_type(self) -> None:
        # WHEN: Wrong u_ticket type
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"",
            "u_ticket_type": f"WRONG-UTICKET-TYPE",
            "task_scope": f"",
        }
        test_u_ticket: str = self.cloud_server_atk._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    def test_apply_wrong_device_id(self) -> None:
        # WHEN: Wrong u_ticket type
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"WRONG-DEVICE-ID",
            "holder_id": f"",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"",
        }
        test_u_ticket: str = self.cloud_server_atk._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    @pytest.mark.skip(reason="Not implemented yet")
    def test_apply_no_signature(self) -> None:
        # WHEN: ...
        current_test_when_and_then_log()
