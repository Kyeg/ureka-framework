import copy
import logging
import json
import base64
from typing import Dict, Union
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    PrivateFormat,
    PublicFormat,
    Encoding,
    NoEncryption,
)
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.ticket import Ticket


################################################################################
#                    < Arbitrary_Byte (Signature / Salt) >                     #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(not always success...)               #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
################################################################################
#                    < Arbitrary_Byte (Signature / Salt) >                     #
#                                      ^                                       #
#          base64.urlsafe_b64decode(.) ||                                      #
#                                      || base64.urlsafe_b64encode(.)          #
#                                       v                                      #
#                     < BASE64_byte (Printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      || (always success due to BASE64!!)     #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def byte_to_str(byte: bytes) -> str:
    base64_byte = base64.urlsafe_b64encode(byte)
    return base64_byte.decode("UTF-8")


def str_to_byte(string: str) -> bytes:
    base64_byte = string.encode("UTF-8")
    return base64.urlsafe_b64decode(base64_byte)


################################################################################
#                                < ECC_Key_obj >                               #
#                                      ^                                       #
#       load_der_public/private_key(.) ||                                      #
#                                      || public/private_bytes(.)              #
#                                       v                                      #
#                           < DER_byte (in File/DB) >                          #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      || (always success due to BASE64!!)     #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def key_to_byte(
    key_obj: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey],
    key_type: str,
) -> bytes:
    if key_type == "ecc-public-key":
        return key_obj.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    elif key_type == "ecc-private-key":
        return key_obj.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    else:
        failure_msg = "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        logging.error(failure_msg)
        raise RuntimeError(failure_msg)


def byte_to_key(
    key_byte: bytes, key_type: str
) -> Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
    if key_type == "ecc-public-key":
        return load_der_public_key(key_byte, backend=default_backend())
    elif key_type == "ecc-private-key":
        return load_der_private_key(key_byte, password=None, backend=default_backend())
    else:
        failure_msg = "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        logging.error(failure_msg)
        raise RuntimeError(failure_msg)


def key_to_str(
    key_obj: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey],
    key_type: str = "ecc-public-key",
) -> bytes:
    return byte_to_str(key_to_byte(key_obj, key_type=key_type))


def str_to_key(
    key_str: str, key_type: str = "ecc-public-key"
) -> ec.EllipticCurvePublicKey:
    key_byte = str_to_byte(key_str)
    return byte_to_key(key_byte, key_type=key_type)


################################################################################
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                      ^                                       #
#                        json.loads(.) ||                                      #
#                                      || json.dumps(.)                        #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def jsonstr_to_dict(json_str: str) -> Dict[str, str]:
    return json.loads(json_str)


def dict_to_jsonstr(dict_obj: Dict[str, str]) -> str:
    return json.dumps(dict_obj, sort_keys=True)


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
    try:
        return json.dumps(
            this_device_obj, indent=4, default=_this_device_to_dict, sort_keys=True
        )
    except TypeError:
        # logging.error("NOT VALID DEVICE")
        raise RuntimeError("NOT VALID DEVICE")


################################################################################
#                                < Ticket_obj >                                #
#                                      ^                                       #
#           self-defined serilaization ||                                      #
#                                      || self-defined serilaization           #
#                                      || (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                      ^                                       #
#                        json.loads(.) ||                                      #
#                                      || json.dumps(.)                        #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def _dict_to_ticket(ticket_dict):
    ticket_obj = Ticket()
    ticket_obj.__dict__.update(ticket_dict)
    return ticket_obj


def _ticket_to_dict(ticket_obj: Ticket) -> Dict[str, str]:
    # Prevent side effect on ticket_obj
    ticket_dict = copy.deepcopy(ticket_obj.__dict__)
    return ticket_dict


def jsonstr_to_ticket(json_str: str) -> Ticket:
    try:
        return json.loads(json_str, object_hook=_dict_to_ticket)
    except json.JSONDecodeError:
        # logging.error("NOT VALID JSON")
        raise RuntimeError("NOT VALID JSON")


def ticket_to_jsonstr(ticket_obj: Ticket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    try:
        return json.dumps(ticket_obj, indent=4, default=_ticket_to_dict, sort_keys=True)
    except TypeError:
        # logging.error("NOT VALID TICKET")
        raise RuntimeError("NOT VALID TICKET")
