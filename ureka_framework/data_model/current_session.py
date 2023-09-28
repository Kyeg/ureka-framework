from ureka_framework.resource.logger.simple_logger import simple_log
from pydantic import BaseModel, ConfigDict, ValidationError

# Notice that cryptography types are not supported by pydantic, so we simply use dataclass instead
from cryptography.hazmat.primitives.asymmetric import ec
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.crypto.serialization_util import (
    byte_to_base64str,
    key_to_str,
    base64str_backto_byte,
    str_to_key,
)


######################################################
# Data Model
######################################################
class CurrentSession(BaseModel):
    # Access Permission UT
    current_u_ticket_id: None | str = None
    current_device_id: None | str = None
    current_holder_id: None | str = None
    current_task_scope: None | str = None

    # CR-KE
    challenge_1: None | str = None
    challenge_2: None | str = None
    key_exchange_salt_1: None | str = None
    key_exchange_salt_2: None | str = None

    # PS
    iv_1: None | str = None
    cipher_text_1: None | str = None
    iv_2: None | str = None
    cipher_text_2: None | str = None
    # current_session_key_byte: None | bytes = None

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                             < CurrentSession_obj >                           #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def current_session_to_jsonstr(current_session_obj: CurrentSession) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    current_session_json = current_session_obj.model_dump_json(
        indent=4, exclude_none=True
    )
    return current_session_json


def jsonstr_to_current_session(json_str: str) -> CurrentSession:
    try:
        return CurrentSession.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
