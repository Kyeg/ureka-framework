import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.data_model import ticket
from ureka_framework.data_model.ticket import Ticket
from ureka_framework.data_model.this_device import (
    jsonstr_to_this_device,
    this_device_to_jsonstr,
)
from ureka_framework.data_model.this_person import (
    jsonstr_to_this_person,
    this_person_to_jsonstr,
)
from ureka_framework.resource.crypto.serialization_util import key_to_str, str_to_key
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.storage.secure_db import SecureDB
from typing import Iterator


class TestSerialization:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

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
            "device_id": f"WRONG-DEVICE-ID",
            "holder_id": f"",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"",
        }
        ticket_json_befo: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        # logging.warning(f"ticket_json_befo = {ticket_json_befo}")

        ticket_obj: Ticket = ticket.jsonstr_to_ticket(ticket_json_befo)
        # logging.warning(f"ticket_obj = {ticket_obj}")

        ticket_json_aftr: str = ticket.ticket_to_jsonstr(ticket_obj)
        # logging.warning(f"ticket_json_aftr = {ticket_json_aftr}")

        # THEN: The result of serialization/deserialization should be the same
        assert f"WRONG-DEVICE-ID" == ticket_obj.device_id
        assert f"{ticket.TYPE_MANAGEMENT_TICKET}" == ticket_obj.ticket_type

    def test_ticket_serialization_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

        with pytest.raises(RuntimeError) as ticket_to_jsonstr_error_info:
            ticket_json: str = ticket.ticket_to_jsonstr("not-a-ticket-obj")

        # THEN: Failed to serialize/deserialize
        assert str(ticket_to_jsonstr_error_info.value) == "NOT VALID TICKET"

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
