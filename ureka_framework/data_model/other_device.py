from dataclasses import dataclass, field
import json
import copy
from typing import Union, Dict


######################################################
# Data Model
######################################################
@dataclass
class OtherDevice:
    # Use device public key as Primary key in Table
    device_id: str = ""

    device_name: str = ""
    # role: str = ""

    # consent_state: str = ""
    # execution_state: str = ""

    # URequest, UTicket, UReject, RTicket, etc.
    device_u_ticket: str = ""


################################################################################
#                             < Other_Device_obj >                             #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def _other_device_to_dict(other_device_obj: OtherDevice) -> Dict[str, str]:
    # Prevent side effect on other_device_obj
    other_device_dict = copy.deepcopy(other_device_obj.__dict__)
    return other_device_dict


def _dict_to_other_device(
    other_device_dict: Dict[str, Union[str, OtherDevice]]
) -> Union[Dict[str, OtherDevice], OtherDevice]:
    # Dict -> OtherDevice
    if "device_id" in other_device_dict:
        other_device_obj = OtherDevice()
        other_device_obj.__dict__.update(other_device_dict)
        return other_device_obj
    # DeviceTable -> DeviceTable
    else:
        return other_device_dict


def device_table_to_jsonstr(other_device_obj: Dict[str, OtherDevice]) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    return json.dumps(
        other_device_obj, indent=4, default=_other_device_to_dict, sort_keys=True
    )


def jsonstr_to_device_table(json_str: str) -> Dict[str, OtherDevice]:
    try:
        return json.loads(json_str, object_hook=_dict_to_other_device)
    except json.JSONDecodeError:
        failure_msg = "NOT VALID JSON"
        # logging.error(failure_msg)
        raise RuntimeError(failure_msg)
