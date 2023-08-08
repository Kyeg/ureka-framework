from dataclasses import dataclass

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import serialization_util

######################################################
# Device Type (can be refactored by Inheritance)
######################################################
USER_AGENT_OR_CLOUD_SERVER: str = "USER-AGENT-OR-CLOUD-SERVER"
IOT_DEVICE: str = "IOT_DEVICE"


######################################################
# Data Model
######################################################
@dataclass
class ThisDevice:
    # Device Type (Device can be User Agent, Cloud Server, or IoT Device...)
    device_type: str = ""
    device_name: str = ""
    has_device_type: bool = False

    # Generate Device Key after Intialization
    is_initialized: bool = False
    device_priv_key: ec.EllipticCurvePrivateKey = None
    device_pub_key: ec.EllipticCurvePublicKey = None

    # Generate Owner Key after Intialization
    owner_pub_key: ec.EllipticCurvePublicKey = None

    # Current Session (RAM-only)
    current_holder_pub_key: ec.EllipticCurvePublicKey = None
    current_session_key_byte: bytes = b""

    @property
    def device_priv_key_str(self) -> str:
        if self.device_priv_key is None:
            return ""
        return serialization_util.key_to_str(
            self.device_priv_key, key_type="ecc-private-key"
        )

    @property
    def device_pub_key_str(self) -> str:
        if self.device_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.device_pub_key, key_type="ecc-public-key"
        )

    @property
    def owner_pub_key_str(self) -> str:
        if self.owner_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.owner_pub_key, key_type="ecc-public-key"
        )

    @property
    def current_holder_pub_key_str(self) -> str:
        if self.current_holder_pub_key is None:
            return ""
        return serialization_util.key_to_str(
            self.current_holder_pub_key, key_type="ecc-public-key"
        )
