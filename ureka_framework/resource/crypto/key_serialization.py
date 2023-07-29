# ECC Serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)

import ureka_framework.data_model.ticket as ticket
from ureka_framework.data_model.ticket import Ticket
import logging
import json
import base64
from typing import Dict, Union

################################################################################
#                        < ECC_Key_obj (Key in Program) >                      #
#                                      ^                                       #
#       load_der_public/private_key(.) ||                                      #
#             (not always success...)) ||                                      #
#                                      || public/private_bytes(.)              #
#                                       v                                      #
#                           < DER_byte (in File/DB) >                          #
################################################################################


def key_to_byte(
    key_obj: Union[_EllipticCurvePublicKey, _EllipticCurvePrivateKey],
    key_type: str = "ecc-public-key",
) -> bytes:
    if key_type == "ecc-public-key":
        return key_obj.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    elif key_type == "ecc-private-key":
        return key_obj.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    else:
        logging.debug("Only support key_type = [ecc-public-key] or [ecc-private-key]")
        return b""


def byte_backto_key(
    key_byte: bytes, key_type: str = "ecc-public-key"
) -> Union[_EllipticCurvePublicKey, _EllipticCurvePrivateKey]:
    if key_type == "ecc-public-key":
        return load_der_public_key(key_byte, backend=default_backend())
    elif key_type == "ecc-private-key":
        return load_der_private_key(key_byte, password=None, backend=default_backend())
    else:
        logging.debug("Only support key_type = [ecc-public-key] or [ecc-private-key]")
        return None


def str_backto_key(
    key_str: str, key_type: str = "ecc-public-key"
) -> _EllipticCurvePublicKey:
    key_byte = str_backto_byte(key_str)
    return byte_backto_key(key_byte, key_type=key_type)


################################################################################
#                        < Arbitrary_Byte (in File/DB) >                       #
#                                      ^                                       #
#          base64.urlsafe_b64decode(.) ||                                      #
#             (not always success...)) ||                                      #
#                                      || base64.urlsafe_b64encode(.)          #
#                                       v                                      #
#                     < BASE64_byte (printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(always success due to BASE64...)     #
#                                       v                                      #
#       < JSON_str (printable Key / Signature / Salt... in Ticket Field) >     #
################################################################################


def byte_to_str(byte: bytes) -> str:
    base64_byte = base64.urlsafe_b64encode(byte)
    return base64_byte.decode("UTF-8")


def str_backto_byte(string: str) -> bytes:
    base64_byte = string.encode("UTF-8")
    return base64.urlsafe_b64decode(base64_byte)


################################################################################
#                     < BASE64_byte (printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(not always success...)               #
#                                       v                                      #
#                  < JSON_str (printable data Ticket Field) >                  #
################################################################################


# str_to_byte
def str_to_byte(string: str) -> bytes:
    return string.encode("UTF-8")


# byte_backto_str
def byte_backto_str(byte):
    return byte.decode("UTF-8")


################################################################################
# Testing: base64.urlsafe_b64encode / base64.urlsafe_b64decode
################################################################################

# orig_byte = '你好嗎'.encode('UTF-8')
# logging.debug('orig_byte: ' + str(orig_byte))
# b64_byte = base64.urlsafe_b64encode(orig_byte)
# logging.debug('b64_byte: ' + str(b64_byte))
# new_byte = base64.urlsafe_b64decode(b64_byte)
# logging.debug('new_byte: ' + str(new_byte))

# logging.debug(orig_byte == new_byte)

# logging.debug("")


################################################################################
#                      < Custom Object (Ticket in Program) >                   #
#                                      ^                                       #
#                   __dict__.update(.) ||                                      #
#                                      || __dict__                             #
#                                       v                                      #
#                          < JSON_dict (in Program) >                          #
#                                      ^                                       #
#                        json.loads(.) ||                                      #
#                                      || json.dumps(.)                        #
#                                       v                                      #
#                    < JSON_str (Interchangeable Format) >                     #
################################################################################


def dict_to_ticket(dict_obj):
    ticket_obj = ticket.Ticket()
    ticket_obj.__dict__.update(dict_obj)
    return ticket_obj


def ticket_to_dict(ticket_obj: Ticket) -> Dict[str, str]:
    return ticket_obj.__dict__


def jsonstr_to_ticket(json_str):
    return json.loads(json_str, object_hook=dict_to_ticket)


# sort_keys = True
def ticket_to_jsonstr(ticket_obj: Ticket) -> str:
    # separators = (", ", ": ") in default
    return json.dumps(ticket_obj, default=ticket_to_dict, sort_keys=True)


def jsonstr_to_dict(json_str: str) -> Dict[str, str]:
    return json.loads(json_str)


# sort_keys = True
def dict_to_jsonstr(dict_obj: Dict[str, str]) -> str:
    # separators = (", ", ": ") in default
    return json.dumps(dict_obj, sort_keys=True)


######################################################
# Testing: jsonstr_to_obj / obj_to_jsonstr
######################################################

# ticket_str1 = '{"device_id": "1234", "holder_id": "abcd", "issuer_id": "efgh"}'
# ticket1 = jsonstr_to_ticket(ticket_str1)
# logging.debug(ticket1)
# logging.debug("")

# new_ticket1 = ticket.Ticket()
# new_ticket1.device_id = "1234"
# new_ticket1.holder_id = "abcd"
# new_ticket1.issuer_id = "efgh"
# new_ticket_str1 = ticket_to_jsonstr(new_ticket1)
# logging.debug(new_ticket_str1)
# logging.debug("")

# # Notice that different setting order will generate different json string...
# new_ticket2 = ticket.Ticket()
# new_ticket2.holder_id = "abcd"
# new_ticket2.device_id = "1234"
# new_ticket_str2 = ticket_to_jsonstr(new_ticket2)
# logging.debug(new_ticket_str2)
# logging.debug("")

# # Notice that wrong field will still be set in the object, but no error will be raised
# ticket_str2 = '{"holder_id": "abcd", "wrong": "blablabla..."}'
# ticket2 = jsonstr_to_ticket(ticket_str2)
# logging.debug(ticket2)
# logging.debug(ticket2.wrong)
