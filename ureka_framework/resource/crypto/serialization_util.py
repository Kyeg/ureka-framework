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
