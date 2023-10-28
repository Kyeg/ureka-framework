######################################################
# Test Fixtures
######################################################
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
)
from ureka_framework.resource.crypto.serialization_util import (
    str_to_byte,
    byte_backto_str,
    byte_to_base64str,
    byte_backto_str,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################
from ureka_framework.resource.logger.simple_logger import simple_log
import ureka_framework.resource.crypto.ecc as ecc
import ureka_framework.resource.crypto.ecdh as ecdh
from cryptography.exceptions import InvalidTag




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

        # WHEN: Sign & Verify some messages
        current_test_when_and_then_log()

        message = str_to_byte("Hello World")
        signature_byte = ecc.sign_signature(message, priv_key)
        simple_log("debug", f"signature_byte: {signature_byte}")
        result = ecc.verify_signature(signature_byte, message, pub_key)

        # Notice that even the signature is different every time, the verification can still pass
        #   Verification of ECC signatures takes into account the use of a nonce,
        #   and it does not require knowledge of the nonce itself (!?).
        message = str_to_byte("Hello World")
        signature_byte = ecc.sign_signature(message, priv_key)
        simple_log("debug", f"signature_byte: {signature_byte}")
        result = ecc.verify_signature(signature_byte, message, pub_key)

        # THEN: The message can be verified
        assert result == True

    def test_ecc_signature_should_fail(self) -> None:
        current_test_given_log()

        # GIVEN: Two pair of ECC keys
        (priv_key1, pub_key1) = ecc.generate_key_pair()
        (priv_key2, pub_key2) = ecc.generate_key_pair()

        # WHEN: Sign & Verify a message
        current_test_when_and_then_log()
        message = str_to_byte("Hello World")
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
        shared_info = None
        shared_salt = ecdh.generate_random_byte(32)

        # WHEN: Key Exchange
        current_test_when_and_then_log()
        session_key1: bytes = ecdh.generate_ecdh_key(
            priv_key1, shared_salt, shared_info, pub_key2
        )
        simple_log(
            "debug",
            "session_key1: " + byte_to_base64str(session_key1),
        )
        session_key2: bytes = ecdh.generate_ecdh_key(
            priv_key2, shared_salt, shared_info, pub_key1
        )
        simple_log(
            "debug",
            "session_key2: " + byte_to_base64str(session_key2),
        )

        # WHEN: Message Encryption
        plaintext: bytes = str_to_byte("message to be encrypted")
        simple_log("debug", "plaintext: " + byte_backto_str(plaintext))
        (ciphertext, shared_iv) = ecdh.cbc_encrypt(plaintext, session_key1)
        simple_log("debug", "ciphertext: " + byte_to_base64str(ciphertext))

        # WHEN: Transfer the Ciphertext || HMAC (or signature in UTicket) || 16-byte Shared_IV
        # WHEN: Message Decryption
        decrypted_plaintext = ecdh.cbc_decrypt(ciphertext, session_key2, shared_iv)
        simple_log(
            "debug",
            "decrypted_plaintext: " + byte_backto_str(decrypted_plaintext),
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
        shared_info = None
        shared_salt = ecdh.generate_random_byte(32)

        # WHEN: Key Exchange
        current_test_when_and_then_log()
        session_key1: bytes = ecdh.generate_ecdh_key(
            priv_key1, shared_salt, shared_info, pub_key2
        )
        simple_log(
            "debug",
            "session_key1: " + byte_to_base64str(session_key1),
        )
        session_key2: bytes = ecdh.generate_ecdh_key(
            priv_key2, shared_salt, shared_info, pub_key1
        )
        simple_log(
            "debug",
            "session_key2: " + byte_to_base64str(session_key2),
        )

        # WHEN: Message Encryption
        plaintext: bytes = str_to_byte("message to be encrypted and authenticated")
        associated_plaintext: bytes = str_to_byte(
            "message not to be encrypted but to be authenticated"
        )
        simple_log("debug", "plaintext: " + byte_backto_str(plaintext))
        simple_log(
            "debug",
            "associated_plaintext: " + byte_backto_str(associated_plaintext),
        )

        shared_iv = ecdh.gcm_gen_iv()
        (ciphertext, gcm_authentication_tag) = ecdh.gcm_encrypt(
            plaintext, associated_plaintext, session_key1, shared_iv
        )
        simple_log("debug", "ciphertext: " + byte_to_base64str(ciphertext))
        simple_log(
            "debug",
            "gcm_authentication_tag: " + byte_to_base64str(gcm_authentication_tag),
        )
        simple_log("debug", "shared_iv: " + byte_to_base64str(shared_iv))

        # WHEN: Transfer the Ciphertext || Associated_plaintext || HMAC (or authentication_tag in GCM) || 16-byte Shared_IV
        # WHEN: Message Decryption
        try:
            right_tag: bytes = gcm_authentication_tag
            authenticated_and_decrypted_plaintext = ecdh.gcm_decrypt(
                ciphertext, associated_plaintext, right_tag, session_key2, shared_iv
            )
            with_right_tag = "Message passes Authentication."
            simple_log(
                "debug",
                "authenticated_and_decrypted_plaintext: "
                + byte_backto_str(authenticated_and_decrypted_plaintext),
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
        simple_log("debug", "")
        simple_log(
            "debug", "Check: The session key & the encrypted message can be shared"
        )
        assert session_key1 == session_key2
        simple_log("debug", "session_key1 == session_key2")
        assert plaintext == authenticated_and_decrypted_plaintext
        simple_log("debug", "plaintext == authenticated_and_decrypted_plaintext")
        assert with_right_tag == "Message passes Authentication."
        simple_log("debug", with_right_tag)
        assert with_wrong_tag == "Message does not pass Authentication."
        simple_log("debug", with_wrong_tag)

        # WHEN: Message Encryption (with the same plaintext)
        shared_iv2 = ecdh.gcm_gen_iv()
        (ciphertext2, gcm_authentication_tag2) = ecdh.gcm_encrypt(
            plaintext, associated_plaintext, session_key1, shared_iv2
        )
        simple_log("debug", "ciphertext2: " + byte_to_base64str(ciphertext2))
        simple_log(
            "debug",
            "gcm_authentication_tag2: " + byte_to_base64str(gcm_authentication_tag2),
        )
        simple_log("debug", "shared_iv2: " + byte_to_base64str(shared_iv2))

        # WHEN: Transfer the Ciphertext || Associated_plaintext || HMAC (or authentication_tag in GCM) || 16-byte Shared_IV
        # WHEN: Message Decryption
        try:
            right_tag: bytes = gcm_authentication_tag2
            authenticated_and_decrypted_plaintext2 = ecdh.gcm_decrypt(
                ciphertext2, associated_plaintext, right_tag, session_key2, shared_iv2
            )
            with_right_tag = "Message passes Authentication."
            simple_log(
                "debug",
                "authenticated_and_decrypted_plaintext2: "
                + byte_backto_str(authenticated_and_decrypted_plaintext2),
            )
        except InvalidTag:
            with_right_tag = "Message does not pass Authentication."

        # THEN: Because "the IV is randomly generated",
        #       even the plaintext is the same, the ciphertext, authentication_tag, and shared_iv are different
        simple_log("debug", "")
        simple_log(
            "debug",
            "Check: Even the plaintext is the same, the ciphertext, authentication_tag, and shared_iv are different",
        )
        assert plaintext == authenticated_and_decrypted_plaintext2
        simple_log("debug", "plaintext == authenticated_and_decrypted_plaintext2")
        assert ciphertext != ciphertext2
        simple_log("debug", "ciphertext != ciphertext2")
        assert gcm_authentication_tag != gcm_authentication_tag2
        simple_log("debug", "gcm_authentication_tag != gcm_authentication_tag2")
        assert shared_iv != shared_iv2
        simple_log("debug", "shared_iv != shared_iv2")

    def test_hash(self) -> None:
        current_test_given_log()

        # GIVEN: str to hash
        message_str_1: str = "Hello World_1"
        message_str_2: str = "Hello World_1"
        message_str_3: str = "Hello World_1"
        message_str_4: str = "Hello World_4"

        # WHEN: Hash the str
        current_test_when_and_then_log()

        message_bytes_1: bytes = str_to_byte(message_str_1)
        generated_hash_bytes_1: bytes = ecdh.generate_sha256_hash_bytes(message_bytes_1)
        generated_hash_str_1: str = byte_to_base64str(generated_hash_bytes_1)
        simple_log("debug", f"Digest_1 str: {generated_hash_str_1}")

        message_bytes_2: bytes = str_to_byte(message_str_2)
        generated_hash_bytes_2: bytes = ecdh.generate_sha256_hash_bytes(message_bytes_2)
        generated_hash_str_2: str = byte_to_base64str(generated_hash_bytes_2)
        simple_log("debug", f"Digest_2 str: {generated_hash_str_2}")

        generated_hash_str_3 = ecdh.generate_sha256_hash_str(message_str_3)
        simple_log("debug", f"Digest_3 str: {generated_hash_str_3}")

        message_bytes_4: bytes = str_to_byte(message_str_4)
        generated_hash_bytes_4: bytes = ecdh.generate_sha256_hash_bytes(message_bytes_4)
        generated_hash_str_4: str = byte_to_base64str(generated_hash_bytes_4)
        simple_log("debug", f"Digest_4 str: {generated_hash_str_4}")

        # THEN: The hash of the same message will be the same, and the other will be extremely different
        assert generated_hash_str_1 == generated_hash_str_2 == generated_hash_str_3
        assert generated_hash_str_1 != generated_hash_str_4
