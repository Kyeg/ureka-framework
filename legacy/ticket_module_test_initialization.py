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
if (
    private_authenticator_1.ticket_mode
    or private_authenticator_2.ticket_mode
    or iot_device_1.ticket_mode
):
    print("All devices have already initiziled...")


######################################################
# Initialize Private Autenticator
#     - Private Autenticator (1, nn5)
######################################################
# -----------------------------------------------------
#     Initialization...
# -----------------------------------------------------
private_authenticator_1.display_module_name()

private_authenticator_1.initialize_private_authenticator()

# -----------------------------------------------------
# After Initialization...
# -----------------------------------------------------
pub_private_authenticator_1 = private_authenticator_1.device_pub_key_str
priv_private_authenticator_1 = private_authenticator_1.device_priv_key


######################################################
# Initialize Private Autenticator
#     -  Private Autenticator (2, MBNs)
######################################################
# -----------------------------------------------------
#     Initialization...
# -----------------------------------------------------
private_authenticator_2.display_module_name()

private_authenticator_2.initialize_private_authenticator()

# -----------------------------------------------------
# After Initialization...
# -----------------------------------------------------
pub_private_authenticator_2 = private_authenticator_2.device_pub_key_str
priv_private_authenticator_2 = private_authenticator_2.device_priv_key


######################################################
# Initialize IoT Device
#     - Private Autenticator (1, nn5)
#         (->) Initialization Ticket
#             - IoT Device (1, A1Z)
######################################################
# -----------------------------------------------------
#     - (->) Initialization Ticket
# -----------------------------------------------------
private_authenticator_1.display_module_name()

test_ticket = private_authenticator_1.generate_boostrapping_ticket(
    holder_id=pub_private_authenticator_1
)

# -----------------------------------------------------
#     -      Initialization Ticket (->)
# -----------------------------------------------------
iot_device_1.display_module_name()

print("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)

# -----------------------------------------------------
# After Initialization...
# -----------------------------------------------------
pub_iot_device_1 = iot_device_1.device_pub_key_str
priv_iot_device_1 = iot_device_1.device_priv_key
