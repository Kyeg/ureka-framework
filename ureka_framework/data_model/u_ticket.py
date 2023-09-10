import logging
from pydantic import BaseModel, ConfigDict, ValidationError


######################################################
# Protocol Version
######################################################
PROTOCOL_VERSION: str = "UREKA-1.0"

######################################################
# UTicket Type
######################################################
TYPE_INITIALIZATION_UTICKET: str = "INITIALIZATION"
TYPE_MANAGEMENT_UTICKET: str = "MANAGEMENT"
TYPE_ACCESS_PERMISSION_UTICKET: str = "ACCESS-PERMISSION"
TYPE_CHALLENGE_UTICKET: str = "CHALLENGE"
TYPE_RESPONSE_UTICKET: str = "RESPONSE"
TYPE_KEY_EXCHANGE_UTICKET: str = "KEY-EXCHANGE"
# TYPE_COMMAND_UTICKET: str = "COMMAND"
# TYPE_RETURN_UTICKET: str = "RETURN"
# TYPE_QUERY_UTICKET: str = "QUERY"
LEGAL_UTICKET_TYPES: {str} = {
    TYPE_INITIALIZATION_UTICKET,
    TYPE_MANAGEMENT_UTICKET,
    TYPE_ACCESS_PERMISSION_UTICKET,
    TYPE_CHALLENGE_UTICKET,
    TYPE_RESPONSE_UTICKET,
    TYPE_KEY_EXCHANGE_UTICKET,
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
class UTicket(BaseModel):
    protocol_verision: str = PROTOCOL_VERSION
    u_ticket_id: str = ""

    u_ticket_type: str = ""

    device_id: str = ""
    holder_id: str = ""
    task_scope: str = ""

    issuer_signature: str = ""

    def __eq__(self, other):
        if isinstance(other, UTicket):
            return self.u_ticket_id == other.u_ticket_id
        return False

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < UTicket_obj >                               #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def u_ticket_to_jsonstr(u_ticket_obj: UTicket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    # return json.dumps(u_ticket_obj, indent=4, default=_u_ticket_to_dict, sort_keys=True)
    u_ticket_json = u_ticket_obj.model_dump_json(indent=4)
    return u_ticket_json


def jsonstr_to_u_ticket(json_str: str) -> UTicket:
    try:
        # return json.loads(json_str, object_hook=_dict_to_u_ticket)
        return UTicket.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        logging.error(f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
