# from dataclasses import dataclass
import copy
import json
from typing import Dict
from pydantic import BaseModel


######################################################
# Protocol Version
######################################################
TICKET_PROTOCOL_VERSION: str = "UREKA-1.0"

######################################################
# Ticket Type
######################################################
TYPE_INITIALIZATION_TICKET: str = "INITIALIZATION"
# TYPE_QUERY_TICKET: str = "QUERY"
TYPE_MANAGEMENT_TICKET: str = "MANAGEMENT"
TYPE_ACCESS_PERMISSION_TICKET: str = "ACCESS-PERMISSION"
TYPE_CHALLENGE_TICKET: str = "CHALLENGE"
TYPE_RESPONSE_TICKET: str = "RESPONSE"
TYPE_KEY_EXCHANGE_TICKET: str = "KEY-EXCHANGE"
# TYPE_COMMAND_TICKET: str = "COMMAND"
# TYPE_RETURN_TICKET: str = "RETURN"
LEGAL_TICKET_TYPES: {str} = {
    TYPE_INITIALIZATION_TICKET,
    TYPE_MANAGEMENT_TICKET,
    TYPE_ACCESS_PERMISSION_TICKET,
    TYPE_CHALLENGE_TICKET,
    TYPE_RESPONSE_TICKET,
    TYPE_KEY_EXCHANGE_TICKET,
}

######################################################
# Request Body Type
######################################################
REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: str = "MANAGEMENT-TYPE"
REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: str = "RESOURCE-TREE"

######################################################
# Device Type
######################################################
USER_AGENT_OR_CLOUD_SERVER: str = "USER-AGENT-OR-CLOUD-SERVER"
IOT_DEVICE: str = "IOT_DEVICE"

######################################################
# Management Type
######################################################
MANAGEMENT_OWNER: str = "NEW-OWNER"
# MANAGEMENT_MANAGER: str = "NEW-MANAGER"


######################################################
# Data Model
######################################################
# @dataclass
class Ticket(BaseModel):
    ticket_protocol_verision: str = TICKET_PROTOCOL_VERSION

    # ticket_number: str = ""
    # transaction_number: str = ""

    device_id: str = ""

    ticket_type: str = ""

    task_scope: str = ""
    holder_id: str = ""

    issuer_signature: str = ""


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
