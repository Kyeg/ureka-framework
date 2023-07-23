# Ureka Module
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket
import legacy.key_serialization as key_serialization

# Testing
import logging

######################################################
# Setup
######################################################

# 2 ticket modules, seperately in Private Autenticator & IoT Device
print("")
private_authenticator_1 = ticket_module.TicketModule(
    module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
    module_name="private_authenticator_1",
    db_path="/secure_db/private_authenticator_1",
)
private_authenticator_2 = ticket_module.TicketModule(
    module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
    module_name="private_authenticator_2",
    db_path="/secure_db/private_authenticator_2",
)
iot_device_1 = ticket_module.TicketModule(
    module_type=ticket.IOT_DEVICE,
    module_name="iot_device_1",
    db_path="/secure_db/iot_device_1",
)
# iot_device_2 = ticket_module.TicketModule(module_type = ticket.IOT_DEVICE, module_name = "iot_device_2", db_path = '/secure_db/iot_device_2')
print("")

if not (
    private_authenticator_1.is_initialized
    and private_authenticator_2.is_initialized
    and iot_device_1.is_initialized
):
    print("All devices should be initiziled 1st...")


######################################################
# After Initialization...
######################################################
pub_private_authenticator_1 = private_authenticator_1.device_pub_key_str
priv_private_authenticator_1 = private_authenticator_1.device_priv_key

pub_private_authenticator_2 = private_authenticator_2.device_pub_key_str
priv_private_authenticator_2 = private_authenticator_2.device_priv_key

pub_iot_device_1 = iot_device_1.device_pub_key_str
priv_iot_device_1 = iot_device_1.device_priv_key


######################################################
# Access IoT Device
#     - Private Autenticator (1, nn5)
#         (->) Access Permission Ticket
#             (<-) Challenge Ticket
#         (->) Repsonse Ticket
#             (<-) Key-exchange Ticket
#         (->) Command Ticket(s)
#                 - Private Autenticator (2, MBNs)
######################################################

# -----------------------------------------------------
#     - (->) Access Permission Ticket
# -----------------------------------------------------
private_authenticator_1.display_module_name()

print("Access...")

# App-level Permission:    Owner: open all resource permissions;   Authorized User: open partial resource permissions
resource_tree_dict = {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
resource_tree_str = key_serialization.dict_to_jsonstr(
    resource_tree_dict
)  # sort_keys = True
print("resource_tree_str = " + resource_tree_str)

request_body_dict = {
    ticket.REQUEST_BODY_CCESS_PERMISSION_RESOURCE_TREE: resource_tree_str
}
request_body_str = key_serialization.dict_to_jsonstr(
    request_body_dict
)  # sort_keys = True
print("request_body_str = " + request_body_str)


# holder_id: can be owner or authorized user
test_ticket = private_authenticator_1.generate_access_permission_ticket(
    device_id=pub_iot_device_1,
    holder_id=pub_private_authenticator_1,
    request_body=request_body_str,
)

# -----------------------------------------------------
#     -      Access Permission Ticket (->)
# -----------------------------------------------------

iot_device_1.display_module_name()

print("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)


# -----------------------------------------------------
#     -      Challenge Ticket (<-)
# -----------------------------------------------------
test_ticket = iot_device_1.generate_challenge_ticket(
    device_id=pub_iot_device_1, holder_id=pub_private_authenticator_1
)

# -----------------------------------------------------
#     - (<-) Challenge Ticket
# -----------------------------------------------------
private_authenticator_1.display_module_name()

print("Receive: " + str(test_ticket))
private_authenticator_1.verify_xxx_ticket(test_ticket)


# -----------------------------------------------------
#     - (->) Repsonse Ticket
# -----------------------------------------------------
test_ticket = private_authenticator_1.generate_response_ticket(
    device_id=pub_iot_device_1, holder_id=pub_private_authenticator_1
)

# -----------------------------------------------------
#     -      Repsonse Ticket (->)
# -----------------------------------------------------
iot_device_1.display_module_name()

print("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)


# -----------------------------------------------------
#     -      Key-exchange Ticket (<-)
# -----------------------------------------------------
test_ticket = iot_device_1.generate_key_exchange_ticket(
    device_id=pub_iot_device_1, holder_id=pub_private_authenticator_1
)

# -----------------------------------------------------
#     - (<-) Key-exchange Ticket
# -----------------------------------------------------
private_authenticator_1.display_module_name()

print("Receive: " + str(test_ticket))
private_authenticator_1.verify_xxx_ticket(test_ticket)


# -----------------------------------------------------
#     - (->) Command Ticket(s)
# -----------------------------------------------------
# test_ticket = private_authenticator_1.generate_command_ticket()
