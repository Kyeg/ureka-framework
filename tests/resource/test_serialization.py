import copy
import logging
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.data_model import ticket
from ureka_framework.data_model.ticket import (
    Ticket,
    jsonstr_to_ticket,
    ticket_to_jsonstr,
)
from ureka_framework.data_model.this_device import (
    jsonstr_to_this_device,
    this_device_to_jsonstr,
)
from ureka_framework.data_model.other_device import (
    jsonstr_to_device_table,
)
from ureka_framework.data_model.this_person import (
    jsonstr_to_this_person,
    this_person_to_jsonstr,
)
from ureka_framework.resource.crypto import ecdh
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    byte_backto_str,
    jsonstr_to_dict,
    key_to_str,
    str_to_key,
)
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestSerialization:
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

    def test_device_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()
        # logging.warning(f"device-befo = {self.cloud_server_dm.this_device}")
        json_str = this_device_to_jsonstr(self.cloud_server_dm.this_device)
        # logging.warning(f"json_str = {json_str}")

        obj = jsonstr_to_this_device(json_str)
        # logging.warning(f"device-befo = {self.cloud_server_dm.this_device}")
        # logging.warning(f"device-aftr = {obj}")

        # THEN: The result of serialization/deserialization should be the same
        # logging.warning(
        #     f"key-befo.str = {self.cloud_server_dm.this_device.device_pub_key_str}"
        # )
        # logging.warning(f"key-aftr.str = {obj.device_pub_key_str}")
        assert (
            self.cloud_server_dm.this_device.device_pub_key == obj.device_pub_key
        )  # but device_priv_key maybe not the same!?
        assert (
            self.cloud_server_dm.this_device.device_pub_key_str
            == obj.device_pub_key_str
        )
        assert (
            self.cloud_server_dm.this_device.device_priv_key_str
            == obj.device_priv_key_str
        )

    def test_person_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()
        # logging.warning(f"person-befo = {self.cloud_server_dm.this_person}")
        json_str = this_person_to_jsonstr(self.cloud_server_dm.this_person)
        # logging.warning(f"json_str = {json_str}")

        obj = jsonstr_to_this_person(json_str)
        # logging.warning(f"person-befo = {self.cloud_server_dm.this_person}")
        # logging.warning(f"person-aftr = {obj}")

        # THEN: The result of serialization/deserialization should be the same
        # logging.warning(
        #     f"key-befo.str = {self.cloud_server_dm.this_person.person_pub_key_str}"
        # )
        # logging.warning(f"key-aftr.str = {obj.person_pub_key_str}")
        assert (
            self.cloud_server_dm.this_person.person_pub_key == obj.person_pub_key
        )  # but device_priv_key maybe not the same!?
        assert (
            self.cloud_server_dm.this_person.person_pub_key_str
            == obj.person_pub_key_str
        )
        assert (
            self.cloud_server_dm.this_person.person_priv_key_str
            == obj.person_priv_key_str
        )

    def test_ticket_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        test_request: dict = {
            "device_id": f"device_id",
            "holder_id": f"",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"",
        }
        ticket_json_befo: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        # logging.warning(f"ticket_json_befo = {ticket_json_befo}")

        ticket_obj: Ticket = jsonstr_to_ticket(ticket_json_befo)
        # logging.warning(f"ticket_obj = {ticket_obj}")

        ticket_json_aftr: str = ticket_to_jsonstr(ticket_obj)
        # logging.warning(f"ticket_json_aftr = {ticket_json_aftr}")

        # THEN: The result of serialization/deserialization should be the same
        assert f"device_id" == ticket_obj.device_id
        assert f"{ticket.TYPE_MANAGEMENT_TICKET}" == ticket_obj.ticket_type

    def test_json_serialization_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Not a valid json
        wrong_json_schema: str = "WRONG-JSON-SCHEMA"

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        # WHEN: Try to serialize/deserialize an invalid json
        with pytest.raises(RuntimeError) as jsonstr_to_dict_error_info:
            dict: str = jsonstr_to_dict(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_ticket_error_info:
            this_device: str = jsonstr_to_ticket(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_this_device_error_info:
            this_device: str = jsonstr_to_this_device(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_other_device_error_info:
            other_device: str = jsonstr_to_device_table(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_this_person_error_info:
            this_person: str = jsonstr_to_this_person(wrong_json_schema)

        # THEN: Failed to serialize/deserialize an invalid json
        assert str(jsonstr_to_dict_error_info.value) == "NOT VALID JSON"
        assert (
            str(jsonstr_to_ticket_error_info.value) == "NOT VALID JSON or VALID SCHEMA"
        )
        assert str(jsonstr_to_this_device_error_info.value) == "NOT VALID JSON"
        assert str(jsonstr_to_other_device_error_info.value) == "NOT VALID JSON"
        assert str(jsonstr_to_this_person_error_info.value) == "NOT VALID JSON"

    def test_byte_serialization_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Not some byte or string
        arbitrary_byte = ecdh.generate_random_byte(32)
        arbitrary_str: str = "asdfghjkl;"

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        # WHEN: Try to serialize/deserialize invalid byte or string
        with pytest.raises(RuntimeError) as byte_backto_str_error_info:
            string: str = byte_backto_str(arbitrary_byte)
        with pytest.raises(RuntimeError) as base64str_backto_byte_error_info:
            byte: bytes = base64str_backto_byte(arbitrary_str)

        # THEN: Failed to serialize/deserialize an invalid json
        assert (
            str(byte_backto_str_error_info.value)
            == "NOT Any Byte can be decoded to UTF-8"
        )
        assert (
            str(base64str_backto_byte_error_info.value)
            == "NOT Any String is Base64 string which can be decoded to Byte"
        )

    def test_key_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        pub_key_str: str = key_to_str(
            self.cloud_server_dm.this_device.device_pub_key, "ecc-public-key"
        )
        # logging.warning(f"pub_key_str = {pub_key_str}")
        pub_key_obj: ec.EllipticCurvePublicKey = str_to_key(
            pub_key_str, "ecc-public-key"
        )
        # logging.warning(f"pub_key_obj = {pub_key_obj}")

        # THEN: The result of serialization/deserialization should be the same
        assert self.cloud_server_dm.this_device.device_pub_key_str == pub_key_str
        assert self.cloud_server_dm.this_device.device_pub_key == pub_key_obj

    def test_key_serialization_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        with pytest.raises(RuntimeError) as key_to_str_error_info:
            pub_key_str: str = key_to_str(
                self.cloud_server_dm.this_device.device_pub_key, "not-a-key-type"
            )

        with pytest.raises(RuntimeError) as str_to_key_error_info:
            pub_key_obj: ec.EllipticCurvePublicKey = str_to_key(
                self.cloud_server_dm.this_device.device_pub_key_str, "not-a-key-type"
            )

        # THEN: Failed to serialize/deserialize
        assert (
            str(key_to_str_error_info.value)
            == "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        )
        assert (
            str(str_to_key_error_info.value)
            == "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        )

    def test_ticket_comparison(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Generate two tickets and compare
        current_test_when_and_then_log()

        test_request_1: dict = {
            "device_id": f"device_id",
            "holder_id": f"",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"",
        }
        ticket_json_1: str = self.cloud_server_dm.generate_xxx_ticket(test_request_1)
        logging.warning(f"ticket_json_1 = {ticket_json_1}")
        ticket_obj_1: Ticket = jsonstr_to_ticket(ticket_json_1)
        logging.warning(f"ticket_obj_1 = {ticket_obj_1}")

        ticket_json_copy_1 = copy.deepcopy(ticket_json_1)
        logging.warning(f"ticket_json_copy_1 = {ticket_json_copy_1}")
        ticket_obj_copy_1 = copy.deepcopy(ticket_obj_1)
        logging.warning(f"ticket_obj_copy_1 = {ticket_obj_copy_1}")

        test_request_2: dict = {
            "device_id": f"device_id",
            "holder_id": f"",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"",
        }
        ticket_json_2: str = self.cloud_server_dm.generate_xxx_ticket(test_request_2)
        logging.warning(f"ticket_json_2 = {ticket_json_2}")
        ticket_obj_2: Ticket = jsonstr_to_ticket(ticket_json_2)
        logging.warning(f"ticket_obj_2 = {ticket_obj_2}")

        # THEN: Every ticket will have different unique ticket_id
        assert ticket_obj_1 != "!@#"
        assert ticket_json_1 == ticket_json_copy_1
        assert ticket_obj_1 == ticket_obj_copy_1
        assert ticket_json_1 != ticket_json_2
        assert ticket_obj_1 != ticket_obj_2
