# Data Model (Message)
from typing import Optional
from pydantic import BaseModel, ConfigDict, ValidationError


######################################################
# Data Model
######################################################
class UTicket(BaseModel):
    # UT
    device_id: Optional[str] = None
    cmd_or_data: Optional[str] = None
    end_tag: Optional[str] = None

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
        failure_msg = "NOT VALID JSON or VALID UTICKET SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)


######################################################
# Generator
######################################################
def generate_arbitrary_u_ticket(arbitrary_dict: dict) -> str:
    try:
        generated_u_ticket = UTicket(**arbitrary_dict)
    except ValidationError as error:  # pragma: no cover -> Weird Ticket-Request
        print(f"{error}")
        raise RuntimeError(f"{error}")

    generated_u_ticket_json = u_ticket_to_jsonstr(generated_u_ticket)
    return generated_u_ticket_json
