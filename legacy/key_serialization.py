# Ureka Module
import ticket

# JSON Serialization
import json
from collections import OrderedDict

# Base64 Serialization
import base64

# ECC Serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding


################################################################################
#                        < ECC_Key_obj (Key in Program) >                      #
#                                      ^                                       #
#       load_der_public/private_key(.) ||                                      #
#             (not always success...)) ||                                      #
#                                      || public/private_bytes(.)              #
#                                       v                                      #
#                           < DER_byte (in File/DB) >                          #
################################################################################


def key_to_byte(key_obj, key_type="ecc-public-key"):
    if key_type == "ecc-public-key":
        return key_obj.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    elif key_type == "ecc-private-key":
        return key_obj.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    else:
        print("Only support key_type = [ecc-public-key] or [ecc-private-key]")
        return b""


def byte_backto_key(key_byte, key_type="ecc-public-key"):
    if key_type == "ecc-public-key":
        return load_der_public_key(key_byte, backend=default_backend())
    elif key_type == "ecc-private-key":
        return load_der_private_key(key_byte, password=None, backend=default_backend())
    else:
        print("Only support key_type = [ecc-public-key] or [ecc-private-key]")
        return None


def str_backto_key(key_str, key_type="ecc-public-key"):
    key_byte = str_backto_byte(key_str)
    return byte_backto_key(key_byte, key_type=key_type)


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
#       < JSON_str (Printable Key / Signature / Salt... in Ticket Field) >     #
################################################################################


def byte_to_str(byte):
    base64_byte = base64.urlsafe_b64encode(byte)
    return base64_byte.decode("UTF-8")


def str_backto_byte(string):
    base64_byte = string.encode("UTF-8")
    return base64.urlsafe_b64decode(base64_byte)


################################################################################
#                     < BASE64_byte (Printable Characters) >                   #
#                                      ^                                       #
#                      encode('UTF-8') ||                                      #
#                                      || decode('UTF-8')                      #
#                                      ||(not always success...)               #
#                                       v                                      #
#                  < JSON_str (Printable data Ticket Field) >                  #
################################################################################


# str_to_byte
def str_to_byte(string):
    return string.encode("UTF-8")


# byte_backto_str
def byte_backto_str(byte):
    return byte.decode("UTF-8")


######################################################
# Testing: base64.urlsafe_b64encode / base64.urlsafe_b64decode
######################################################

# orig_byte = '你好嗎'.encode('UTF-8')
# print('orig_byte: ' + str(orig_byte))
# b64_byte = base64.urlsafe_b64encode(orig_byte)
# print('b64_byte: ' + str(b64_byte))
# new_byte = base64.urlsafe_b64decode(b64_byte)
# print('new_byte: ' + str(new_byte))

# print(orig_byte == new_byte)

# print()


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


def ticket_to_dict(ticket_obj):
    return ticket_obj.__dict__


def jsonstr_to_ticket(json_str):
    return json.loads(json_str, object_hook=dict_to_ticket)


# sort_keys = True
def ticket_to_jsonstr(ticket_obj):
    # separators = (", ", ": ") in default
    return json.dumps(ticket_obj, default=ticket_to_dict, sort_keys=True)


def jsonstr_to_dict(json_str):
    return json.loads(json_str)


# sort_keys = True
def dict_to_jsonstr(dict_obj):
    # separators = (", ", ": ") in default
    return json.dumps(dict_obj, sort_keys=True)


######################################################
# Testing: jsonstr_to_obj / obj_to_jsonstr
######################################################

# ticket_str1 = '{"device_id": "1234", "holder_id": "abcd", "issuer_id": "efgh"}'
# ticket1 = jsonstr_to_ticket(ticket_str1)
# print(ticket1)
# print()

# new_ticket1 = ticket.Ticket()
# new_ticket1.device_id = "1234"
# new_ticket1.holder_id = "abcd"
# new_ticket1.issuer_id = "efgh"
# new_ticket_str1 = ticket_to_jsonstr(new_ticket1)
# print(new_ticket_str1)
# print()

# # Notice that different setting order will generate different json string...
# new_ticket2 = ticket.Ticket()
# new_ticket2.holder_id = "abcd"
# new_ticket2.device_id = "1234"
# new_ticket_str2 = ticket_to_jsonstr(new_ticket2)
# print(new_ticket_str2)
# print()

# # Notice that wrong field will still be set in the object, but no error will be raised
# ticket_str2 = '{"holder_id": "abcd", "wrong": "blablabla..."}'
# ticket2 = jsonstr_to_ticket(ticket_str2)
# print(ticket2)
# print(ticket2.wrong)
