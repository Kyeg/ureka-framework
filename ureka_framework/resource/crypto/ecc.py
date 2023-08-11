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
