import sys
import ticket_module
import ticket
import key_serialization

######################################################
# Setup
######################################################

# 2 ticket modules, seperately in Private Autenticator & IoT Device
print()
private_authenticator_1 = ticket_module.TicketModule(
    module_type=ticket.PRIVATE_ANTHENTICATOR,
    module_name="private_authenticator_1",
    db_path="/secure_db/private_authenticator_1",
)
private_authenticator_2 = ticket_module.TicketModule(
    module_type=ticket.PRIVATE_ANTHENTICATOR,
    module_name="private_authenticator_2",
    db_path="/secure_db/private_authenticator_2",
)
iot_device_1 = ticket_module.TicketModule(
    module_type=ticket.IOT_DEVICE,
    module_name="iot_device_1",
    db_path="/secure_db/iot_device_1",
)
# iot_device_2 = ticket_module.TicketModule(module_type = ticket.IOT_DEVICE, module_name = "iot_device_2", db_path = '/secure_db/iot_device_2')
print()

# Different features in initialization_mode & ticket_mode
if not (
    private_authenticator_1.ticket_mode
    and private_authenticator_2.ticket_mode
    and iot_device_1.ticket_mode
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
# Manage IoT Device
#     - Private Autenticator (1, nn5)
#         (->) Management Ticket
#             - Private Autenticator (2, MBNs)
######################################################
# -----------------------------------------------------
#     - (->) Management Ticket
# -----------------------------------------------------
private_authenticator_1.display_module_name()

print("Change owner...")

request_body_dict = {
    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
}
request_body_str = key_serialization.dict_to_jsonstr(
    request_body_dict
)  # sort_keys = True
print("request_body_str = " + request_body_str)

test_ticket = private_authenticator_1.generate_management_ticket(
    device_id=pub_iot_device_1,
    holder_id=pub_private_authenticator_2,
    request_body=request_body_str,
)

# -----------------------------------------------------
#     -      Management Ticket (->)
# -----------------------------------------------------
iot_device_1.display_module_name()

print("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)


######################################################
# Manage IoT Device
#     - Private Autenticator (2, MBNs)
#         (->) Management Ticket
#             - Private Autenticator (1, nn5)
######################################################
# -----------------------------------------------------
#     - (->) Management Ticket
# -----------------------------------------------------
private_authenticator_2.display_module_name()

print("Change owner...")

request_body_dict = {
    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
}
request_body_str = key_serialization.dict_to_jsonstr(
    request_body_dict
)  # sort_keys = True
print("request_body_str = " + request_body_str)

test_ticket = private_authenticator_2.generate_management_ticket(
    device_id=pub_iot_device_1,
    holder_id=pub_private_authenticator_1,
    request_body=request_body_str,
)

# -----------------------------------------------------
#     -      Management Ticket (->)
# -----------------------------------------------------
iot_device_1.display_module_name()

print("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)
