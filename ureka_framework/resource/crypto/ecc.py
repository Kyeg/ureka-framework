# ECC
import logging
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
def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return (private_key, public_key)


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
        return True
    except InvalidSignature:
        # failure_msg = "FAILURE: INVALID SIGNATURE"
        # logging.error(failure_msg)
        return False
