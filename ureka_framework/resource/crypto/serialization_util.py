# ECC Serialization
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

import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import logging
import json
import base64
from typing import Dict, Union


################################################################################
#                        < Arbitrary_Byte (in File/DB) >                       #
#                                      ^                                       #
#          base64.urlsafe_b64decode(.) ||                                      #
#             (not always success...)) ||                                      #
#                                      || base64.urlsafe_b64encode(.)          #
#                                       v                                      #
#                     < BASE64_byte (Printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(always success due to BASE64...)     #
#                                       v                                      #
#            < JSON_str (Printable Key / Signature / Salt / Ticket) >          #
################################################################################
################################################################################
#                     < BASE64_byte (Printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(not always success...)               #
#                                       v                                      #
#            < JSON_str (Printable Key / Signature / Salt / Ticket) >          #
################################################################################
def byte_to_str(byte: bytes) -> str:
    base64_byte = base64.urlsafe_b64encode(byte)
    return base64_byte.decode("UTF-8")


def str_to_byte(string: str) -> bytes:
    base64_byte = string.encode("UTF-8")
    return base64.urlsafe_b64decode(base64_byte)


################################################################################
#                        < ECC_Key_obj (Key in Program) >                      #
#                                      ^                                       #
#       load_der_public/private_key(.) ||                                      #
#             (not always success...)) ||                                      #
#                                      || public/private_bytes(.)              #
#                                       v                                      #
#                           < DER_byte (in File/DB) >                          #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(always success due to BASE64...)     #
#                                       v                                      #
#            < JSON_str (Printable Key / Signature / Salt / Ticket) >          #
################################################################################
def key_to_byte(
    key_obj: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey],
    key_type: str = "ecc-public-key",
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
    key_byte: bytes, key_type: str = "ecc-public-key"
) -> Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
    if key_type == "ecc-public-key":
        return load_der_public_key(key_byte, backend=default_backend())
    elif key_type == "ecc-private-key":
        return load_der_private_key(key_byte, password=None, backend=default_backend())
    else:
        failure_msg = "Only support key_type = [ecc-public-key] or [ecc-private-key]"
        logging.info(failure_msg)
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
# Testing: base64.urlsafe_b64encode / base64.urlsafe_b64decode
################################################################################

# orig_byte = '你好嗎'.encode('UTF-8')
# logging.info('orig_byte: ' + str(orig_byte))
# b64_byte = base64.urlsafe_b64encode(orig_byte)
# logging.info('b64_byte: ' + str(b64_byte))
# new_byte = base64.urlsafe_b64decode(b64_byte)
# logging.info('new_byte: ' + str(new_byte))

# logging.info(orig_byte == new_byte)

# logging.info("")


################################################################################
#                  < Custom_Ticket_obj (Ticket in Program) >                   #
#                                      ^                                       #
#                   __dict__.update(.) ||                                      #
#                                      || __dict__                             #
#                                       v                                      #
#                          < JSON_dict (in Program) >                          #
#                                      ^                                       #
#                        json.loads(.) ||                                      #
#                                      || json.dumps(.)                        #
#                                       v                                      #
#            < JSON_str (Printable Key / Signature / Salt / Ticket) >          #
################################################################################
def _dict_to_ticket(dict_obj):
    ticket_obj = ticket.Ticket()
    ticket_obj.__dict__.update(dict_obj)
    return ticket_obj


def _ticket_to_dict(ticket_obj: Ticket) -> Dict[str, str]:
    return ticket_obj.__dict__


def jsonstr_to_ticket(json_str: str) -> Ticket:
    try:
        return json.loads(json_str, object_hook=_dict_to_ticket)
    except json.JSONDecodeError:
        # logging.error("NOT VALID JSON")
        raise RuntimeError("NOT VALID JSON")


# sort_keys = True
def ticket_to_jsonstr(ticket_obj: Ticket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    try:
        return json.dumps(ticket_obj, indent=4, default=_ticket_to_dict, sort_keys=True)
    except TypeError:
        # logging.error("NOT VALID TICKET")
        raise RuntimeError("NOT VALID TICKET")


def jsonstr_to_dict(json_str: str) -> Dict[str, str]:
    return json.loads(json_str)


# sort_keys = True
def dict_to_jsonstr(dict_obj: Dict[str, str]) -> str:
    # separators = (", ", ": ") in default
    return json.dumps(dict_obj, sort_keys=True)


######################################################
# Testing: jsonstr_to_obj / obj_to_jsonstr
######################################################

# ticket_str1 = '{"device_id": "1234", "holder_id": "abcd"}'
# ticket1 = jsonstr_to_ticket(ticket_str1)
# logging.info(ticket1)
# logging.info("")

# new_ticket1 = ticket.Ticket()
# new_ticket1.device_id = "1234"
# new_ticket1.holder_id = "abcd"
# new_ticket_str1 = ticket_to_jsonstr(new_ticket1)
# logging.info(new_ticket_str1)
# logging.info("")

# # Notice that different setting order will generate different json string...
# new_ticket2 = ticket.Ticket()
# new_ticket2.holder_id = "abcd"
# new_ticket2.device_id = "1234"
# new_ticket_str2 = ticket_to_jsonstr(new_ticket2)
# logging.info(new_ticket_str2)
# logging.info("")

# # Notice that wrong field will still be set in the object, but no error will be raised
# ticket_str2 = '{"holder_id": "abcd", "wrong": "blablabla..."}'
# ticket2 = jsonstr_to_ticket(ticket_str2)
# logging.info(ticket2)
# logging.info(ticket2.wrong)
