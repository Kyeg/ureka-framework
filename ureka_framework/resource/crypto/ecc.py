# ECC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

import ureka_framework.resource.crypto.serialization_util as serialization_util
from typing import Tuple


######################################################
# ECC Key Factory
######################################################
def generate_key_pair() -> Tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_byte = serialization_util.key_to_byte(
        private_key, key_type="ecc-private-key"
    )

    public_key = private_key.public_key()
    public_key_byte = serialization_util.key_to_byte(
        public_key, key_type="ecc-public-key"
    )

    return (private_key_byte, public_key_byte)


######################################################
# Sign ECC Signature
######################################################
def sign_signature(message_in: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.sign(message_in, ec.ECDSA(hashes.SHA256()))


######################################################
# Verify ECC Signature
######################################################
def verify_signature(
    signatureIn: bytes, message_in: bytes, public_key: ec.EllipticCurvePublicKey
) -> bool:
    try:
        public_key.verify(signatureIn, message_in, ec.ECDSA(hashes.SHA256()))
        # logging.info ("Valid Signature.")
        return True
    except InvalidSignature:
        # logging.info ("Invalid Signature.")
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

# # Test serialization_util
# private_key = serialization_util.byte_to_key(private_key_byte, key_type = 'ecc-private-key')
# public_key = serialization_util.byte_to_key(public_key_byte, key_type = 'ecc-public-key')

# # Test serialization_util
# logging.info('readable_private_key_str: ' + serialization_util.byte_to_str(private_key_byte))
# logging.info('readable_public_key_str: ' + serialization_util.byte_to_str(public_key_byte))

# # Test serialization_util
# logging.info(serialization_util.key_to_byte(private_key, key_type = 'ecc-private-key') == private_key_byte)
# logging.info(serialization_util.key_to_byte(public_key, key_type = 'ecc-public-key') == public_key_byte)
# logging.info("")


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
# message_byte = serialization_util.str_to_byte(message_str)
# logging.info('message_byte: ' + str(message_byte))

# # Test serialization_util
# logging.info(serialization_util.byte_to_str(message_byte) == message_str)
# logging.info("")

# # Sign message
# signature_byte = sign_signature(message_byte, private_key)
# logging.info('signature_byte: ' + str(signature_byte))
# logging.info('readable_signature_str: ' + serialization_util.byte_to_str(signature_byte))

# # Verify signature on message
# if(verify_signature(signature_byte, message_byte, public_key)):
#     logging.info('Valid Signature for ' + str(message_byte))
# else:
#     logging.info('Invalid Signature')

# # Test serialization_util
# logging.info(serialization_util.str_to_byte(serialization_util.byte_to_str(signature_byte)) == signature_byte)
