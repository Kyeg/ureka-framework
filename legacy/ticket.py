# Protocol Version
TICKET_PROTOCOL_VERSION = "UREKA-1.0"


# Ticket Type
TYPE_INITIALIZATION_TICKET = "INITIALIZATION"

TYPE_QUERY_TICKET = "QUERY"

TYPE_MANAGEMENT_TICKET = "MANAGEMENT"

TYPE_ACCESS_PERMISSION_TICKET = "ACCESS-PERMISSION"
TYPE_CHALLENGE_TICKET = "CHALLENGE"
TYPE_RESONSE_TICKET = "RESONSE"
TYPE_KEY_EXCHANGE_TICKET = "KEY-EXCHANGE"
TYPE_COMMAND_TICKET = "COMMAND"

TYPE_RETURN_TICKET = "RETURN"


# Request Body Type
REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE = "MANAGEMENT-TYPE"
REQUEST_BODY_CCESS_PERMISSION_RESOURCE_TREE = "RESOURCE-TREE"

# DEVICE-TYPE
USER_AGENT_OR_CLOUD_SERVER = "USER-AGENT-OR-CLOUD-SERVER"
IOT_DEVICE = "IOT-DEVICE"

# MANAGEMENT-TYPE
MANAGEMENT_OWNER = "NEW-OWNER"
# MANAGEMENT_MANAGER = "NEW-MANAGER"


class Ticket:
    # Explicit Field
    ticket_protocol_verision = TICKET_PROTOCOL_VERSION

    ticket_type = ""  # I think using string rather than number will be better here?

    # device_name = ''
    device_id = ""

    # issuer_name = ''
    issuer_id = ""

    # holder_name = ''
    holder_id = ""

    request_body = ""
    response_body = ""

    issuer_signature = ""

    def __repr__(self):
        representation = "< (Ticket Object) >"

        if self.ticket_protocol_verision != "":
            representation = (
                representation
                + "\n\t ticket_protocol_verision: "
                + str(self.ticket_protocol_verision)
            )

        if self.ticket_type != "":
            representation = (
                representation + "\n\t ticket_type: " + str(self.ticket_type)
            )

        # if (self.device_name != ''):
        #     representation = representation + "\n\t device_name: " + self.device_name
        if self.device_id != "":
            representation = representation + "\n\t device_id: " + self.device_id[0:64]

        # if (self.issuer_name != ''):
        #     representation = representation + "\n\t issuer_name: " + self.issuer_name
        if self.issuer_id != "":
            representation = representation + "\n\t issuer_id: " + self.issuer_id[0:64]

        # if (self.holder_name != ''):
        #     representation = representation + "\n\t holder_name: " + self.holder_name
        if self.holder_id != "":
            representation = representation + "\n\t holder_id: " + self.holder_id[0:64]

        if self.request_body != "":
            representation = representation + "\n\t request_body: " + self.request_body

        if self.response_body != "":
            representation = (
                representation + "\n\t response_body: " + self.response_body
            )

        if self.issuer_signature != "":
            representation = (
                representation + "\n\t issuer_signature: " + self.issuer_signature
            )

        return representation
