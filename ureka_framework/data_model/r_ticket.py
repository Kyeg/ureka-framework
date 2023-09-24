import logging
from pydantic import BaseModel, ConfigDict, ValidationError
import ureka_framework.data_model.u_ticket as u_ticket

######################################################
# RTicket Type
######################################################
TYPE_CRKE1_RTICKET: str = "CR-KE-1"
TYPE_CRKE2_RTICKET: str = "CR-KE-2"
TYPE_CRKE3_RTICKET: str = "CR-KE-3"
LEGAL_RTICKET_TYPES: {str} = {
    TYPE_CRKE1_RTICKET,
    TYPE_CRKE2_RTICKET,
    TYPE_CRKE3_RTICKET,
}


######################################################
# Data Model
######################################################
class RTicket(BaseModel):
    protocol_verision: str = u_ticket.PROTOCOL_VERSION
    r_ticket_id: str = ""

    r_ticket_type: str = ""

    device_id: str = ""
    audit_start: str = ""
    audit_end: str = ""

    result: str = ""

    # CR-KE-PS
    challenge_1: str = ""
    challenge_2: str = ""
    key_exchange_salt_1: str = ""
    key_exchange_salt_2: str = ""
    iv_1: str = ""
    cipher_text_1: str = ""
    iv_2: str = ""
    cipher_text_2: str = ""

    device_signature: str = ""

    def __eq__(self, other):
        if isinstance(other, RTicket):
            return self.r_ticket_id == other.r_ticket_id
        return False

    # By default, Pydantic "ignore" extra input fields not defined in model schema
    # Moreover, we can explicitly "allow" or "forbid (with Error)" extra input fields not defined in model schema
    model_config = ConfigDict(extra="forbid")


################################################################################
#                                < RTicket_obj >                               #
#                                       | self-defined serilaization           #
#                                       | (all str, which is native type)      #
#                                       v                                      #
#         < JSON_dict (Should be JSON serializable, i.e. native type) >        #
#                                       |                                      #
#                                       v                                      #
#                       < JSON_str (Printable Characters) >                    #
################################################################################
def r_ticket_to_jsonstr(r_ticket_obj: RTicket) -> str:
    # "indent" do not affect json validation, but may affect json size!?
    r_ticket_json = r_ticket_obj.model_dump_json(indent=4)
    return r_ticket_json


def jsonstr_to_r_ticket(json_str: str) -> RTicket:
    try:
        return RTicket.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID SCHEMA"
        logging.error(f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
