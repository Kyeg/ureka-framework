import logging
from pydantic import BaseModel, ConfigDict, ValidationError


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
class Ticket(BaseModel):
    ticket_protocol_verision: str = TICKET_PROTOCOL_VERSION

    ticket_id: str = ""

    device_id: str = ""

    ticket_type: str = ""

    task_scope: str = ""
    holder_id: str = ""

    issuer_signature: str = ""

    def __eq__(self, other):
        if isinstance(other, Ticket):
            return self.ticket_id == other.ticket_id
        return False

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < Ticket_obj >                                #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def ticket_to_jsonstr(ticket_obj: Ticket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    # return json.dumps(ticket_obj, indent=4, default=_ticket_to_dict, sort_keys=True)
    ticket_json = ticket_obj.model_dump_json(indent=4)
    return ticket_json


def jsonstr_to_ticket(json_str: str) -> Ticket:
    try:
        # return json.loads(json_str, object_hook=_dict_to_ticket)
        return Ticket.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        logging.error(f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
