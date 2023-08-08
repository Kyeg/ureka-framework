from dataclasses import dataclass

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import serialization_util


######################################################
# Data Model (User Agent or Cloud Server only)
######################################################
@dataclass
class ThisPerson:
    # Generate Person Key after Intialization (UA or CS only)
    person_priv_key: ec.EllipticCurvePrivateKey = None
    person_pub_key: ec.EllipticCurvePublicKey = None

    @property
    def person_priv_key_str(self) -> str:
        if self.person_priv_key is None:
            return ""
        return serialization_util.key_to_str(
            self.person_priv_key, key_type="ecc-private-key"
        )

    @property
    def person_pub_key_str(self) -> str:
        if self.person_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.person_pub_key, key_type="ecc-public-key"
        )
