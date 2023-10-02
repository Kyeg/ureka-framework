from dataclasses import dataclass
import json
from typing import Optional, Union, Dict

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_base64str,
    key_to_str,
    base64str_backto_byte,
    str_to_key,
)

######################################################
# Device Type (can be refactored by Inheritance)
######################################################
USER_AGENT_OR_CLOUD_SERVER: str = "USER-AGENT-OR-CLOUD-SERVER"
IOT_DEVICE: str = "IOT_DEVICE"

######################################################
# Device State
######################################################
# USER_AGENT_OR_CLOUD_SERVER
STATE_WAIT_FOR_UT: str = "STATE_WAIT_FOR_UT"
STATE_WAIT_FOR_RT: str = "STATE_WAIT_FOR_RT"
STATE_WAIT_FOR_CRKE1: str = "STATE_WAIT_FOR_CRKE1"
STATE_WAIT_FOR_CRKE3: str = "STATE_WAIT_FOR_CRKE3"
STATE_WAIT_FOR_DATA: str = "STATE_WAIT_FOR_DATA"
# IOT_DEVICE
# STATE_WAIT_FOR_UT: str = "STATE_WAIT_FOR_UT"
STATE_WAIT_FOR_CRKE2: str = "STATE_WAIT_FOR_CRKE2"
STATE_WAIT_FOR_CMD: str = "STATE_WAIT_FOR_CMD"


######################################################
# Data Model
######################################################
@dataclass
class ThisDevice:
    # Device Type (Device can be User Agent, Cloud Server, or IoT Device...)
    device_type: None | str = None
    device_name: None | str = None
    has_device_type: None | bool = False

    # Generate Device Key after Intialization
    is_initialized: None | bool = False
    device_priv_key: None | ec.EllipticCurvePrivateKey = None
    device_pub_key: None | ec.EllipticCurvePublicKey = None

    # Generate Owner Key after Intialization
    owner_pub_key: None | ec.EllipticCurvePublicKey = None

    # # Current Session (RAM-only)
    # current_holder_pub_key: None | ec.EllipticCurvePublicKey = None
    # current_session_key_byte: None | bytes = None

    @property
    def device_priv_key_str(self) -> None | str:
        if self.device_priv_key is None:
            return None
        return key_to_str(self.device_priv_key, key_type="ecc-private-key")

    @property
    def device_pub_key_str(self) -> None | str:
        if self.device_pub_key is None:
            return None
        return key_to_str(self.device_pub_key, key_type="ecc-public-key")

    @property
    def owner_pub_key_str(self) -> None | str:
        if self.owner_pub_key is None:
            return None
        return key_to_str(self.owner_pub_key, key_type="ecc-public-key")

    # @property
    # def current_holder_pub_key_str(self) -> None | str:
    #     if self.current_holder_pub_key is None:
    #         return None
    #     return key_to_str(
    #         self.current_holder_pub_key, key_type="ecc-public-key"
    #     )


################################################################################
#                                < Device_obj >                                #
#                                       | self-defined serilaization           #
#                                       | (including ECC_Key_obj, bytes, etc.) #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
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
    # if this_device_obj.current_holder_pub_key == None:
    #     this_device_dict["current_holder_pub_key"] = None
    # else:  # pragma: no cover -> Never reach here: Because the current_holder_pub_key is not persistently stored
    #     this_device_dict["current_holder_pub_key"] = key_to_str(
    #         this_device_obj.current_holder_pub_key, "ecc-public-key"
    #     )
    # if this_device_obj.current_session_key_byte == None:
    #     this_device_dict["current_session_key_byte"] = None
    # else:  # pragma: no cover -> Never reach here: Because the current_session_key_byte is not persistently stored
    #     this_device_dict["current_session_key_byte"] = byte_to_base64str(
    #         this_device_obj.current_session_key_byte
    #     )

    return this_device_dict


def _dict_to_this_device(
    this_device_dict: Dict[str, Optional[Union[str, bool]]]
) -> ThisDevice:
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
    # if (
    #     this_device_dict["current_holder_pub_key"] != None
    # ):  # pragma: no cover -> Never reach here: Because the current_holder_pub_key is not persistently stored
    #     this_device_obj.current_holder_pub_key = str_to_key(
    #         this_device_dict["current_holder_pub_key"], "ecc-public-key"
    #     )
    # if this_device_dict["current_session_key_byte"] == None:
    #     this_device_obj.current_session_key_byte = None
    # else:  # pragma: no cover
    #     # Never reach here: Because the current_session_key_byte is not persistently stored
    #     this_device_obj.current_session_key_byte = base64str_backto_byte(
    #         this_device_dict["current_session_key_byte"]
    #     )

    return this_device_obj


def this_device_to_jsonstr(this_device_obj: ThisDevice) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    return json.dumps(
        this_device_obj, indent=4, default=_this_device_to_dict, sort_keys=True
    )


def jsonstr_to_this_device(json_str: str) -> ThisDevice:
    try:
        return json.loads(json_str, object_hook=_dict_to_this_device)
    except json.JSONDecodeError:
        failure_msg = "NOT VALID JSON"
        # simple_log("error",failure_msg)
        raise RuntimeError(failure_msg)
