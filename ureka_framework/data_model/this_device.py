from dataclasses import dataclass
import json
from typing import Dict

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_str,
    key_to_str,
    str_to_byte,
    str_to_key,
)

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


################################################################################
#                                < Device_obj >                                #
#                                      ^                                       #
#           self-defined serilaization ||                                      #
#                                      || self-defined serilaization           #
#                                      || (including ECC_Key_obj, bytes, etc.) #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                      ^                                       #
#                        json.loads(.) ||                                      #
#                                      || json.dumps(.)                        #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def _dict_to_this_device(this_device_dict):
    this_device_obj = ThisDevice()

    # JSON Serializable
    this_device_obj.__dict__.update(this_device_dict)

    # Not JSON Serializable
    if this_device_dict["device_priv_key"] != None:
        this_device_obj.device_priv_key = str_to_key(
            this_device_dict["device_priv_key"], "ecc-private-key"
        )
    if this_device_dict["device_pub_key"] != None:
        this_device_obj.device_pub_key = str_to_key(
            this_device_dict["device_pub_key"], "ecc-public-key"
        )
    if this_device_dict["owner_pub_key"] != None:
        this_device_obj.owner_pub_key = str_to_key(
            this_device_dict["owner_pub_key"], "ecc-public-key"
        )
    if this_device_dict["current_holder_pub_key"] != None:
        this_device_obj.current_holder_pub_key = str_to_key(
            this_device_dict["current_holder_pub_key"], "ecc-public-key"
        )
    if this_device_dict["current_session_key_byte"] == None:
        this_device_obj.current_session_key_byte = b""
    else:
        this_device_obj.current_session_key_byte = str_to_byte(
            this_device_dict["current_session_key_byte"]
        )

    return this_device_obj


def _this_device_to_dict(this_device_obj: ThisDevice) -> Dict[str, str]:
    # Prevent side effect on this_device_obj
    # However, cannot deepcopy key object, so we need to handle it separately
    this_device_dict = {}

    # JSON Serializable
    this_device_dict["device_type"] = this_device_obj.device_type
    this_device_dict["device_name"] = this_device_obj.device_name
    this_device_dict["has_device_type"] = this_device_obj.has_device_type
    this_device_dict["is_initialized"] = this_device_obj.is_initialized

    # Not JSON Serializable
    if this_device_obj.device_priv_key == None:
        this_device_dict["device_priv_key"] = None
    else:
        this_device_dict["device_priv_key"] = key_to_str(
            this_device_obj.device_priv_key, "ecc-private-key"
        )
    if this_device_obj.device_pub_key == None:
        this_device_dict["device_pub_key"] = None
    else:
        this_device_dict["device_pub_key"] = key_to_str(
            this_device_obj.device_pub_key, "ecc-public-key"
        )
    if this_device_obj.owner_pub_key == None:
        this_device_dict["owner_pub_key"] = None
    else:
        this_device_dict["owner_pub_key"] = key_to_str(
            this_device_obj.owner_pub_key, "ecc-public-key"
        )
    if this_device_obj.current_holder_pub_key == None:
        this_device_dict["current_holder_pub_key"] = None
    else:
        this_device_dict["current_holder_pub_key"] = key_to_str(
            this_device_obj.current_holder_pub_key, "ecc-public-key"
        )
    if this_device_obj.current_session_key_byte == b"":
        this_device_dict["current_session_key_byte"] = None
    else:
        this_device_dict["current_session_key_byte"] = byte_to_str(
            this_device_obj.current_session_key_byte
        )

    return this_device_dict


def jsonstr_to_this_device(json_str: str) -> ThisDevice:
    try:
        return json.loads(json_str, object_hook=_dict_to_this_device)
    except json.JSONDecodeError:
        # logging.error("NOT VALID JSON")
        raise RuntimeError("NOT VALID JSON")


def this_device_to_jsonstr(this_device_obj: ThisDevice) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    if type(this_device_obj) == ThisDevice:
        return json.dumps(
            this_device_obj, indent=4, default=_this_device_to_dict, sort_keys=True
        )
    else:
        # logging.error("NOT VALID DEVICE")
        raise RuntimeError("NOT VALID DEVICE")
