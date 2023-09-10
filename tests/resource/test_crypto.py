import logging
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
)
from ureka_framework.resource.crypto import ecc, serialization_util
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.exceptions import InvalidTag
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
        (priv_key1, pub_key1) = ecc.generate_key_pair()
        (priv_key2, pub_key2) = ecc.generate_key_pair()

        # WHEN: Sign & Verify a message
        current_test_when_and_then_log()
        message = serialization_util.str_to_byte("Hello World")
        signature_byte = ecc.sign_signature(message, priv_key1)
        result = ecc.verify_signature(signature_byte, message, pub_key2)

        # THEN: The message can be verified
        assert result == False

    def test_ecdh_and_cbc_aes(self) -> None:
        current_test_given_log()

        # GIVEN: Two pair of ECC keys
        (priv_key1, pub_key1) = ecc.generate_key_pair()
        (priv_key2, pub_key2) = ecc.generate_key_pair()

        # GIVEN: Shared info and salt for Key Exchange
        shared_info = b""
        shared_salt = ecdh.generate_random_byte(32)

        # WHEN: Key Exchange
        current_test_when_and_then_log()
        session_key1: bytes = ecdh.generate_ecdh_key(
            priv_key1, shared_salt, shared_info, pub_key2
        )
        logging.debug(
            "session_key1: " + serialization_util.byte_to_base64str(session_key1)
        )
        session_key2: bytes = ecdh.generate_ecdh_key(
            priv_key2, shared_salt, shared_info, pub_key1
        )
        logging.debug(
            "session_key2: " + serialization_util.byte_to_base64str(session_key2)
        )

        # WHEN: Message Encryption
        plaintext: bytes = serialization_util.str_to_byte("message to be encrypted")
        logging.debug("plaintext: " + serialization_util.byte_backto_str(plaintext))
        (ciphertext, shared_iv) = ecdh.cbc_encrypt(plaintext, session_key1)
        logging.debug("ciphertext: " + serialization_util.byte_to_base64str(ciphertext))

        # WHEN: Transfer the Ciphertext || HMAC (or signature in UTicket) || 16-byte Shared_IV
        # WHEN: Message Decryption
        decrypted_plaintext = ecdh.cbc_decrypt(ciphertext, session_key2, shared_iv)
        logging.debug(
            "decrypted_plaintext: "
            + serialization_util.byte_backto_str(decrypted_plaintext)
        )

        # THEN: The session key & the encrypted message can be shared
        assert session_key1 == session_key2
        assert plaintext == decrypted_plaintext

    def test_ecdh_and_gcm_aes(self) -> None:
        current_test_given_log()

        # GIVEN: Two pair of ECC keys
        (priv_key1, pub_key1) = ecc.generate_key_pair()
        (priv_key2, pub_key2) = ecc.generate_key_pair()

        # GIVEN: Shared info and salt for Key Exchange
        shared_info = b""
        shared_salt = ecdh.generate_random_byte(32)

        # WHEN: Key Exchange
        current_test_when_and_then_log()
        session_key1: bytes = ecdh.generate_ecdh_key(
            priv_key1, shared_salt, shared_info, pub_key2
        )
        logging.debug(
            "session_key1: " + serialization_util.byte_to_base64str(session_key1)
        )
        session_key2: bytes = ecdh.generate_ecdh_key(
            priv_key2, shared_salt, shared_info, pub_key1
        )
        logging.debug(
            "session_key2: " + serialization_util.byte_to_base64str(session_key2)
        )

        # WHEN: Message Encryption
        plaintext: bytes = serialization_util.str_to_byte(
            "message to be encrypted and authenticated"
        )
        associated_plaintext: bytes = serialization_util.str_to_byte(
            "message not to be encrypted but to be authenticated"
        )
        logging.debug("plaintext: " + serialization_util.byte_backto_str(plaintext))
        logging.debug(
            "associated_plaintext: "
            + serialization_util.byte_backto_str(associated_plaintext)
        )
        (ciphertext, gcm_authentication_tag, shared_iv) = ecdh.gcm_encrypt(
            plaintext, associated_plaintext, session_key1
        )
        logging.debug("ciphertext: " + serialization_util.byte_to_base64str(ciphertext))
        logging.debug(
            "gcm_authentication_tag: "
            + serialization_util.byte_to_base64str(gcm_authentication_tag)
        )
        logging.debug("shared_iv: " + serialization_util.byte_to_base64str(shared_iv))

        # WHEN: Transfer the Ciphertext || Associated_plaintext || HMAC (or authentication_tag in GCM) || 16-byte Shared_IV
        # WHEN: Message Decryption
        try:
            right_tag: bytes = gcm_authentication_tag
            authenticated_and_decrypted_plaintext = ecdh.gcm_decrypt(
                ciphertext, associated_plaintext, right_tag, session_key2, shared_iv
            )
            with_right_tag = "Message passes Authentication."
            logging.debug(
                "authenticated_and_decrypted_plaintext: "
                + serialization_util.byte_backto_str(
                    authenticated_and_decrypted_plaintext
                )
            )
        except InvalidTag:
            with_right_tag = "Message does not pass Authentication."

        # WHEN: Message Decryption (with wrong tag)
        try:
            wrong_tag: bytes = b"wrong_tagggggggg"
            authenticated_and_decrypted_plaintext = ecdh.gcm_decrypt(
                ciphertext, associated_plaintext, wrong_tag, session_key2, shared_iv
            )
            with_wrong_tag = "Message passes Authentication."
        except InvalidTag:
            with_wrong_tag = "Message does not pass Authentication."

        # THEN: The session key & the encrypted message can be shared
        logging.debug("")
        logging.debug("Check: The session key & the encrypted message can be shared")
        assert session_key1 == session_key2
        logging.debug("session_key1 == session_key2")
        assert plaintext == authenticated_and_decrypted_plaintext
        logging.debug("plaintext == authenticated_and_decrypted_plaintext")
        assert with_right_tag == "Message passes Authentication."
        logging.debug(with_right_tag)
        assert with_wrong_tag == "Message does not pass Authentication."
        logging.debug(with_wrong_tag)

        # WHEN: Message Encryption (with the same plaintext)
        (ciphertext2, gcm_authentication_tag2, shared_iv2) = ecdh.gcm_encrypt(
            plaintext, associated_plaintext, session_key1
        )
        logging.debug(
            "ciphertext2: " + serialization_util.byte_to_base64str(ciphertext2)
        )
        logging.debug(
            "gcm_authentication_tag2: "
            + serialization_util.byte_to_base64str(gcm_authentication_tag2)
        )
        logging.debug("shared_iv2: " + serialization_util.byte_to_base64str(shared_iv2))

        # WHEN: Transfer the Ciphertext || Associated_plaintext || HMAC (or authentication_tag in GCM) || 16-byte Shared_IV
        # WHEN: Message Decryption
        try:
            right_tag: bytes = gcm_authentication_tag2
            authenticated_and_decrypted_plaintext2 = ecdh.gcm_decrypt(
                ciphertext2, associated_plaintext, right_tag, session_key2, shared_iv2
            )
            with_right_tag = "Message passes Authentication."
            logging.debug(
                "authenticated_and_decrypted_plaintext2: "
                + serialization_util.byte_backto_str(
                    authenticated_and_decrypted_plaintext2
                )
            )
        except InvalidTag:
            with_right_tag = "Message does not pass Authentication."

        # THEN: Because "the IV is randomly generated",
        #       even the plaintext is the same, the ciphertext, authentication_tag, and shared_iv are different
        logging.debug("")
        logging.debug(
            "Check: Even the plaintext is the same, the ciphertext, authentication_tag, and shared_iv are different"
        )
        assert plaintext == authenticated_and_decrypted_plaintext2
        logging.debug("plaintext == authenticated_and_decrypted_plaintext2")
        assert ciphertext != ciphertext2
        logging.debug("ciphertext != ciphertext2")
        assert gcm_authentication_tag != gcm_authentication_tag2
        logging.debug("gcm_authentication_tag != gcm_authentication_tag2")
        assert shared_iv != shared_iv2
        logging.debug("shared_iv != shared_iv2")
