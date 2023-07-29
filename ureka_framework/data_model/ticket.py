from dataclasses import dataclass

# Protocol Version
TICKET_PROTOCOL_VERSION: str = "UREKA-1.0"

# Ticket Type
TYPE_INITIALIZATION_TICKET: str = "INITIALIZATION"
TYPE_QUERY_TICKET: str = "QUERY"
TYPE_MANAGEMENT_TICKET: str = "MANAGEMENT"
TYPE_ACCESS_PERMISSION_TICKET: str = "ACCESS-PERMISSION"
TYPE_CHALLENGE_TICKET: str = "CHALLENGE"
TYPE_RESPONSE_TICKET: str = "RESPONSE"
TYPE_KEY_EXCHANGE_TICKET: str = "KEY-EXCHANGE"
TYPE_COMMAND_TICKET: str = "COMMAND"
TYPE_RETURN_TICKET: str = "RETURN"

# Request Body Type
REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: str = "MANAGEMENT-TYPE"
REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: str = "RESOURCE-TREE"

# DEVICE-TYPE
USER_AGENT_OR_CLOUD_SERVER: str = "USER-AGENT-OR-CLOUD-SERVER"
IOT_DEVICE: str = "IOT-DEVICE"

# MANAGEMENT-TYPE
MANAGEMENT_OWNER: str = "NEW-OWNER"
# MANAGEMENT_MANAGER: str = "NEW-MANAGER"


@dataclass
class Ticket:
    ticket_protocol_verision: str = TICKET_PROTOCOL_VERSION

    # Not implemented yet
    ticket_number: str = ""
    transaction_number: str = ""

    device_id: str = ""

    ticket_type: str = ""
    task_scope: str = ""
    holder_id: str = ""

    issuer_signature: str = ""
