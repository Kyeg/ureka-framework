# ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

# ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)

import ureka_framework.resource.crypto.key_serialization as key_serialization
from typing import Tuple


######################################################
# ECC Key Factory
######################################################
def generate_key_pair() -> Tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_byte = key_serialization.key_to_byte(
        private_key, key_type="ecc-private-key"
    )

    public_key = private_key.public_key()
    public_key_byte = key_serialization.key_to_byte(
        public_key, key_type="ecc-public-key"
    )

    return (private_key_byte, public_key_byte)


######################################################
# Sign ECC Signature
######################################################
def sign_signature(messageIn: bytes, privateKey: _EllipticCurvePrivateKey) -> bytes:
    return privateKey.sign(messageIn, ec.ECDSA(hashes.SHA256()))


######################################################
# Verify ECC Signature
######################################################
def verify_signature(
    signatureIn: bytes, messageIn: bytes, publicKey: _EllipticCurvePublicKey
) -> bool:
    try:
        publicKey.verify(signatureIn, messageIn, ec.ECDSA(hashes.SHA256()))
        # logging.debug ("Valid Signature.")
        return True
    except InvalidSignature:
        # logging.debug ("Invalid Signature.")
        return False


######################################################
# Testing
#
#  ECC_Key_obj
#      |
#      |
#      v
#   DER_byte
#      |
#      |
#      v
#   JSON_str
######################################################
# # Generate Key
# (private_key_byte, public_key_byte) = generate_key_pair()   # (135, 88)

# # Test key_serialization
# private_key = key_serialization.byte_backto_key(private_key_byte, key_type = 'ecc-private-key')
# public_key = key_serialization.byte_backto_key(public_key_byte, key_type = 'ecc-public-key')

# # Test key_serialization
# logging.debug('readable_private_key_str: ' + key_serialization.byte_to_str(private_key_byte))
# logging.debug('readable_public_key_str: ' + key_serialization.byte_to_str(public_key_byte))

# # Test key_serialization
# logging.debug(key_serialization.key_to_byte(private_key, key_type = 'ecc-private-key') == private_key_byte)
# logging.debug(key_serialization.key_to_byte(public_key, key_type = 'ecc-public-key') == public_key_byte)
# logging.debug("")


######################################################
# Testing
#
#     Message_byte -> Signature_byte
#         ^
#         |                | (BASE64)
#         | (UTF-8)        | (UTF-8)
#                          v
#     Message_str     Signature_str
#
######################################################
# message_str = 'message to be signed'
# message_byte = key_serialization.str_to_byte(message_str)
# logging.debug('message_byte: ' + str(message_byte))

# # Test key_serialization
# logging.debug(key_serialization.byte_backto_str(message_byte) == message_str)
# logging.debug("")

# # Sign message
# signature_byte = sign_signature(message_byte, private_key)
# logging.debug('signature_byte: ' + str(signature_byte))
# logging.debug('readable_signature_str: ' + key_serialization.byte_to_str(signature_byte))

# # Verify signature on message
# if(verify_signature(signature_byte, message_byte, public_key)):
#     logging.debug('Valid Signature for ' + str(message_byte))
# else:
#     logging.debug('Invalid Signature')

# # Test key_serialization
# logging.debug(key_serialization.str_backto_byte(key_serialization.byte_to_str(signature_byte)) == signature_byte)
