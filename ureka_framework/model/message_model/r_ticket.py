from ureka_framework.resource.logger.simple_logger import simple_log
from pydantic import BaseModel, ConfigDict, ValidationError
import ureka_framework.model.message_model.u_ticket as u_ticket

######################################################
# Message Type
######################################################
MESSAGE_TYPE: str = "RTICKET"

######################################################
# RTicket Type (same as UTicket Type)
# RTicket Type (CRKE)
# RTicket Type (PS)
######################################################
# UTicket
# TYPE_INITIALIZATION_UTICKET: str = "INITIALIZATION"
# TYPE_OWNERSHIP_UTICKET: str = "OWNERSHIP"
# CRKE
TYPE_CRKE1_RTICKET: str = "CR-KE-1"
TYPE_CRKE2_RTICKET: str = "CR-KE-2"
TYPE_CRKE3_RTICKET: str = "CR-KE-3"
# CRKE
LEGAL_CRKE_TYPES: {str} = {TYPE_CRKE1_RTICKET, TYPE_CRKE2_RTICKET, TYPE_CRKE3_RTICKET}
# RToken
TYPE_DATA_RTOKEN: str = "DATA_RTOKEN"
# RToken (TX_END)
# TYPE_TX_END_UTOKEN: str = "TX_END"
# All
LEGAL_RTICKET_TYPES: {str} = {
    u_ticket.TYPE_INITIALIZATION_UTICKET,
    u_ticket.TYPE_OWNERSHIP_UTICKET,
    TYPE_CRKE1_RTICKET,
    TYPE_CRKE2_RTICKET,
    TYPE_CRKE3_RTICKET,
    TYPE_DATA_RTOKEN,
    u_ticket.TYPE_TX_END_UTOKEN,
}


######################################################
# Data Model
######################################################
class RTicket(BaseModel):
    # RT
    protocol_verision: None | str = u_ticket.PROTOCOL_VERSION

    r_ticket_id: None | str = None
    r_ticket_type: None | str = None

    device_id: None | str = None

    result: None | str = None
    ticket_order: None | int = None

    audit_start: None | str = None
    audit_end: None | str = None

    # CR-KE
    challenge_1: None | str = None
    challenge_2: None | str = None
    key_exchange_salt_1: None | str = None
    key_exchange_salt_2: None | str = None

    # PS-Cmd
    associated_plaintext_cmd: None | str = None
    ciphertext_cmd: None | str = None
    iv_cmd: None | str = None
    gcm_authentication_tag_cmd: None | str = None

    # PS-Data
    associated_plaintext_data: None | str = None
    ciphertext_data: None | str = None
    iv_data: None | str = None
    gcm_authentication_tag_data: None | str = None

    # RT
    device_signature: None | str = None

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
    r_ticket_json = r_ticket_obj.model_dump_json(indent=4, exclude_none=True)
    return r_ticket_json


def jsonstr_to_r_ticket(json_str: str) -> RTicket:
    try:
        return RTicket.model_validate_json(json_str)
    except ValidationError as error:
        failure_msg = "NOT VALID JSON or VALID RTICKET SCHEMA"
        # simple_log("error", f"{failure_msg}: {error}")
        raise RuntimeError(failure_msg)
