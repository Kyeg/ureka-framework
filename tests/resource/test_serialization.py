######################################################
# Test Fixtures
######################################################
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################
import copy
from ureka_framework.model.message_model.message import jsonstr_to_message
from ureka_framework.resource.logger.simple_logger import simple_log
from ureka_framework.model.message_model import u_ticket
from ureka_framework.model.message_model.r_ticket import (
    RTicket,
    jsonstr_to_r_ticket,
    r_ticket_to_jsonstr,
)
from ureka_framework.model.message_model.u_ticket import (
    UTicket,
    jsonstr_to_u_ticket,
    u_ticket_to_jsonstr,
)
from ureka_framework.model.data_model.this_device import (
    jsonstr_to_this_device,
    this_device_to_jsonstr,
)
from ureka_framework.model.data_model.other_device import (
    jsonstr_to_device_table,
)
from ureka_framework.model.data_model.this_person import (
    jsonstr_to_this_person,
    this_person_to_jsonstr,
)
from ureka_framework.model.data_model.current_session import (
    jsonstr_to_current_session,
)
from ureka_framework.resource.crypto.serialization_util import (
    base64str_backto_byte,
    byte_backto_str,
    jsonstr_to_dict,
    key_to_str,
    str_to_key,
)
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import ecdh


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
        # simple_log("debug",f"device-befo = {self.cloud_server_dm.shared_data.this_device}")
        json_str = this_device_to_jsonstr(self.cloud_server_dm.shared_data.this_device)
        # simple_log("debug",f"json_str = {json_str}")

        obj = jsonstr_to_this_device(json_str)
        # simple_log("debug",f"device-befo = {self.cloud_server_dm.shared_data.this_device}")
        # simple_log("debug",f"device-aftr = {obj}")

        # THEN: The result of serialization/deserialization should be the same
        # simple_log("debug",
        #     f"key-befo.str = {self.cloud_server_dm.shared_data.this_device.device_pub_key_str}"
        # )
        # simple_log("debug",f"key-aftr.str = {obj.device_pub_key_str}")
        # assert (
        #     self.cloud_server_dm.shared_data.this_device.device_pub_key
        #     == obj.device_pub_key
        # )  # but device_priv_key maybe not the same!?
        assert (
            self.cloud_server_dm.shared_data.this_device.device_pub_key_str
            == obj.device_pub_key_str
        )
        assert (
            self.cloud_server_dm.shared_data.this_device.device_priv_key_str
            == obj.device_priv_key_str
        )

    def test_person_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()
        # simple_log("debug",f"person-befo = {self.cloud_server_dm.shared_data.this_person}")
        json_str = this_person_to_jsonstr(self.cloud_server_dm.shared_data.this_person)
        # simple_log("debug",f"json_str = {json_str}")

        obj = jsonstr_to_this_person(json_str)
        # simple_log("debug",f"person-befo = {self.cloud_server_dm.shared_data.this_person}")
        # simple_log("debug",f"person-aftr = {obj}")

        # THEN: The result of serialization/deserialization should be the same
        # simple_log("debug",
        #     f"key-befo.str = {self.cloud_server_dm.shared_data.this_person.person_pub_key_str}"
        # )
        # simple_log("debug",f"key-aftr.str = {obj.person_pub_key_str}")
        # assert (
        #     self.cloud_server_dm.shared_data.this_person.person_pub_key
        #     == obj.person_pub_key
        # )  # but device_priv_key maybe not the same!?
        assert (
            self.cloud_server_dm.shared_data.this_person.person_pub_key_str
            == obj.person_pub_key_str
        )
        assert (
            self.cloud_server_dm.shared_data.this_person.person_priv_key_str
            == obj.person_priv_key_str
        )

    def test_u_ticket_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        test_request: dict = {
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        u_ticket_json_befo: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(test_request)
        )
        # simple_log("debug",f"u_ticket_json_befo = {u_ticket_json_befo}")

        u_ticket_obj: UTicket = jsonstr_to_u_ticket(u_ticket_json_befo)
        # simple_log("debug",f"u_ticket_obj = {u_ticket_obj}")

        u_ticket_json_aftr: str = u_ticket_to_jsonstr(u_ticket_obj)
        # simple_log("debug",f"u_ticket_json_aftr = {u_ticket_json_aftr}")

        # THEN: The result of serialization/deserialization should be the same
        assert f"{u_ticket.TYPE_INITIALIZATION_UTICKET}" == u_ticket_obj.u_ticket_type

    def test_r_ticket_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()
        test_request: dict = {
            "r_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
            "result": f"Success/Failure",
        }
        r_ticket_json_befo: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_r_ticket(test_request)
        )
        simple_log("debug", f"r_ticket_json_befo = {r_ticket_json_befo}")

        r_ticket_obj: RTicket = jsonstr_to_r_ticket(r_ticket_json_befo)
        simple_log("debug", f"r_ticket_obj = {r_ticket_obj}")

        r_ticket_json_aftr: str = r_ticket_to_jsonstr(r_ticket_obj)
        simple_log("debug", f"r_ticket_json_aftr = {r_ticket_json_aftr}")

        # THEN: The result of serialization/deserialization should be the same
        assert f"{u_ticket.TYPE_OWNERSHIP_UTICKET}" == r_ticket_obj.r_ticket_type

    def test_json_serialization_should_fail(self) -> None:
        current_test_given_log()

        # GIVEN: Not a valid json
        wrong_json_schema: str = "WRONG-JSON-SCHEMA"

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        # WHEN: Try to serialize/deserialize an invalid json
        with pytest.raises(RuntimeError) as jsonstr_to_dict_error_info:
            dict: str = jsonstr_to_dict(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_message_error_info:
            message: str = jsonstr_to_message(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_u_ticket_error_info:
            u_ticket: str = jsonstr_to_u_ticket(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_r_ticket_error_info:
            r_ticket: str = jsonstr_to_r_ticket(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_this_device_error_info:
            this_device: str = jsonstr_to_this_device(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_other_device_error_info:
            other_device: str = jsonstr_to_device_table(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_this_person_error_info:
            this_person: str = jsonstr_to_this_person(wrong_json_schema)
        with pytest.raises(RuntimeError) as jsonstr_to_current_session_error_info:
            current_session: str = jsonstr_to_current_session(wrong_json_schema)

        # THEN: Failed to serialize/deserialize an invalid json
        assert str(jsonstr_to_dict_error_info.value) == "NOT VALID JSON"
        assert (
            str(jsonstr_to_message_error_info.value)
            == "NOT VALID JSON or VALID MESSAGE SCHEMA"
        )
        assert (
            str(jsonstr_to_u_ticket_error_info.value)
            == "NOT VALID JSON or VALID UTICKET SCHEMA"
        )
        assert (
            str(jsonstr_to_r_ticket_error_info.value)
            == "NOT VALID JSON or VALID RTICKET SCHEMA"
        )
        assert (
            str(jsonstr_to_this_device_error_info.value)
            == "NOT VALID JSON or VALID SCHEMA"
        )
        assert (
            str(jsonstr_to_other_device_error_info.value)
            == "NOT VALID JSON or VALID SCHEMA"
        )
        assert (
            str(jsonstr_to_this_person_error_info.value)
            == "NOT VALID JSON or VALID SCHEMA"
        )
        assert (
            str(jsonstr_to_current_session_error_info.value)
            == "NOT VALID JSON or VALID SCHEMA"
        )

    def test_byte_serialization_should_fail(self) -> None:
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
            self.cloud_server_dm.shared_data.this_device.device_pub_key,
            "ecc-public-key",
        )
        # simple_log("debug",f"pub_key_str = {pub_key_str}")
        pub_key_obj: ec.EllipticCurvePublicKey = str_to_key(
            pub_key_str, "ecc-public-key"
        )
        # simple_log("debug",f"pub_key_obj = {pub_key_obj}")

        # THEN: The result of serialization/deserialization should be the same
        assert (
            self.cloud_server_dm.shared_data.this_device.device_pub_key_str
            == pub_key_str
        )
        # assert (
        #     self.cloud_server_dm.shared_data.this_device.device_pub_key == pub_key_obj
        # )

    def test_key_serialization_should_fail(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        with pytest.raises(RuntimeError) as key_to_str_error_info:
            pub_key_str: str = key_to_str(
                self.cloud_server_dm.shared_data.this_device.device_pub_key,
                "not-a-key-type",
            )

        with pytest.raises(RuntimeError) as str_to_key_error_info:
            pub_key_obj: ec.EllipticCurvePublicKey = str_to_key(
                self.cloud_server_dm.shared_data.this_device.device_pub_key_str,
                "not-a-key-type",
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

    def test_u_ticket_comparison(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: Generate two u_tickets and compare
        current_test_when_and_then_log()

        test_request_1: dict = {
            "device_id": f"{self.iot_device.shared_data.this_device.device_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        u_ticket_json_1: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(test_request_1)
        )
        simple_log("debug", f"u_ticket_json_1 = {u_ticket_json_1}")
        u_ticket_obj_1: UTicket = jsonstr_to_u_ticket(u_ticket_json_1)
        simple_log("debug", f"u_ticket_obj_1 = {u_ticket_obj_1}")

        u_ticket_json_copy_1 = copy.deepcopy(u_ticket_json_1)
        simple_log("debug", f"u_ticket_json_copy_1 = {u_ticket_json_copy_1}")
        u_ticket_obj_copy_1 = copy.deepcopy(u_ticket_obj_1)
        simple_log("debug", f"u_ticket_obj_copy_1 = {u_ticket_obj_copy_1}")

        test_request_2: dict = {
            "device_id": f"{self.iot_device.shared_data.this_device.device_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        u_ticket_json_2: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(test_request_2)
        )
        simple_log("debug", f"u_ticket_json_2 = {u_ticket_json_2}")
        u_ticket_obj_2: UTicket = jsonstr_to_u_ticket(u_ticket_json_2)
        simple_log("debug", f"u_ticket_obj_2 = {u_ticket_obj_2}")

        # THEN: Two u_tickets which have the same content will have the same u_ticket_id (Hash-based)
        # THEN: But the signature will be always different
        assert u_ticket_obj_1 != "!@#"
        assert u_ticket_json_1 == u_ticket_json_copy_1
        assert u_ticket_obj_1 == u_ticket_obj_copy_1
        assert u_ticket_json_1 != u_ticket_json_2
        assert u_ticket_obj_1 == u_ticket_obj_2

    def test_r_ticket_comparison(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: Generate two r_tickets and compare
        current_test_when_and_then_log()

        test_request_1: dict = {
            "r_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
            "result": f"Success/Failure",
        }
        r_ticket_json_1: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_r_ticket(test_request_1)
        )
        simple_log("debug", f"r_ticket_json_1 = {r_ticket_json_1}")
        r_ticket_obj_1: RTicket = jsonstr_to_r_ticket(r_ticket_json_1)
        simple_log("debug", f"r_ticket_obj_1 = {r_ticket_obj_1}")

        r_ticket_json_copy_1 = copy.deepcopy(r_ticket_json_1)
        simple_log("debug", f"r_ticket_json_copy_1 = {r_ticket_json_copy_1}")
        r_ticket_obj_copy_1 = copy.deepcopy(r_ticket_obj_1)
        simple_log("debug", f"r_ticket_obj_copy_1 = {r_ticket_obj_copy_1}")

        test_request_2: dict = {
            "r_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
            "result": f"Success/Failure",
        }
        r_ticket_json_2: str = (
            self.cloud_server_dm.msg_generator._generate_xxx_r_ticket(test_request_2)
        )
        simple_log("debug", f"r_ticket_json_2 = {r_ticket_json_2}")
        r_ticket_obj_2: RTicket = jsonstr_to_r_ticket(r_ticket_json_2)
        simple_log("debug", f"r_ticket_obj_2 = {r_ticket_obj_2}")

        # THEN: Two r_tickets which have the same content will have the same r_ticket_id (Hash-based)
        # THEN: But the signature will be always different
        assert r_ticket_obj_1 != "!@#"
        assert r_ticket_json_1 == r_ticket_json_copy_1
        assert r_ticket_obj_1 == r_ticket_obj_copy_1
        assert r_ticket_json_1 != r_ticket_json_2
        assert r_ticket_obj_1 == r_ticket_obj_2
