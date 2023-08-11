from dataclasses import dataclass
import json
from typing import Dict

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.crypto.serialization_util import (
    key_to_str,
    str_to_key,
)


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


################################################################################
#                                < Person_obj >                                #
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
def _dict_to_this_person(this_person_dict):
    this_person_obj = ThisPerson()

    # Not JSON Serializable
    if this_person_dict["person_priv_key"] != None:
        this_person_obj.person_priv_key = str_to_key(
            this_person_dict["person_priv_key"], "ecc-private-key"
        )
    if this_person_dict["person_pub_key"] != None:
        this_person_obj.person_pub_key = str_to_key(
            this_person_dict["person_pub_key"], "ecc-public-key"
        )

    return this_person_obj


def _this_person_to_dict(this_person_obj: ThisPerson) -> Dict[str, str]:
    # Prevent side effect on this_person_obj
    # However, cannot deepcopy key object, so we need to handle it separately
    this_person_dict = {}

    # Not JSON Serializable
    if this_person_obj.person_priv_key == None:
        this_person_dict["person_priv_key"] = None
    else:
        this_person_dict["person_priv_key"] = key_to_str(
            this_person_obj.person_priv_key, "ecc-private-key"
        )
    if this_person_obj.person_pub_key == None:
        this_person_dict["person_pub_key"] = None
    else:
        this_person_dict["person_pub_key"] = key_to_str(
            this_person_obj.person_pub_key, "ecc-public-key"
        )

    return this_person_dict


def jsonstr_to_this_person(json_str: str) -> ThisPerson:
    try:
        return json.loads(json_str, object_hook=_dict_to_this_person)
    except json.JSONDecodeError:
        # logging.error("NOT VALID JSON")
        raise RuntimeError("NOT VALID JSON")


def this_person_to_jsonstr(this_person_obj: ThisPerson) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    if type(this_person_obj) == ThisPerson:
        return json.dumps(
            this_person_obj, indent=4, default=_this_person_to_dict, sort_keys=True
        )
    else:
        # logging.error("NOT VALID DEVICE")
        raise RuntimeError("NOT VALID DEVICE")
