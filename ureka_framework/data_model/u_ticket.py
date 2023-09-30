from ureka_framework.resource.logger.simple_logger import simple_log
from pydantic import BaseModel, ConfigDict, ValidationError


######################################################
# Protocol Version
######################################################
PROTOCOL_VERSION: str = "UREKA-1.0"

######################################################
# UTicket Type
######################################################
# UTicket
TYPE_INITIALIZATION_UTICKET: str = "INITIALIZATION"
TYPE_OWNERSHIP_UTICKET: str = "OWNERSHIP"
TYPE_ACCESS_UTICKET: str = "ACCESS"
# TYPE_QUERY_UTICKET: str = "QUERY"
# UToken
TYPE_CMD_UTOKEN: str = "UToken"
TYPE_DATA_UTOKEN: str = "RToken"
LEGAL_UTICKET_TYPES: {str} = {
    TYPE_INITIALIZATION_UTICKET,
    TYPE_OWNERSHIP_UTICKET,
    TYPE_ACCESS_UTICKET,
    TYPE_CMD_UTOKEN,
    TYPE_DATA_UTOKEN,
}


######################################################
# Task Scope
######################################################
TASK_SCOPE_RESOURCE_TREE: str = "TASK-SCOPE-RESOURCE-TREE"


######################################################
# Data Model
######################################################
class UTicket(BaseModel):
    # UT
    protocol_verision: None | str = PROTOCOL_VERSION
    u_ticket_id: None | str = None

    u_ticket_type: None | str = None

    device_id: None | str = None
    holder_id: None | str = None
    task_scope: None | str = None

    issuer_signature: None | str = None

    # PS
    associated_plaintext: None | str = None
    iv: None | str = None
    ciphertext: None | str = None
    gcm_authentication_tag: None | str = None

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
    u_ticket_json = u_ticket_obj.model_dump_json(indent=4, exclude_none=True)
    return u_ticket_json


def jsonstr_to_u_ticket(json_str: str) -> UTicket:
    try:
        return UTicket.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
