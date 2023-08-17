import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
)
from ureka_framework.resource.crypto import ecc, serialization_util
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestCrypto:
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

    def test_ecc_signature(self) -> None:
        current_test_given_log()

        # GIVEN: A pair of ECC keys
        (priv_key, pub_key) = ecc.generate_key_pair()

        # WHEN: Sign & Verify a message
        current_test_when_and_then_log()
        message = serialization_util.str_to_byte("Hello World")
        signature_byte = ecc.sign_signature(message, priv_key)
        result = ecc.verify_signature(signature_byte, message, pub_key)

        # THEN: The message can be verified
        assert result == True

    def test_ecc_signature_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Two pair of ECC keys
        (priv_key, pub_key) = ecc.generate_key_pair()
        (priv_key2, pub_key2) = ecc.generate_key_pair()

        # WHEN: Sign & Verify a message
        current_test_when_and_then_log()
        message = serialization_util.str_to_byte("Hello World")
        signature_byte = ecc.sign_signature(message, priv_key)
        result = ecc.verify_signature(signature_byte, message, pub_key2)

        # THEN: The message can be verified
        assert result == False
