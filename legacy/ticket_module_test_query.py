# Ureka Module
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket

# Testing
import logging

######################################################
# Setup
######################################################

# 2 ticket modules, seperately in Private Autenticator & IoT Device
logging.debug("")
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
logging.debug("")

# Different features in initialization_mode & ticket_mode
if not (
    private_authenticator_1.ticket_mode
    and private_authenticator_2.ticket_mode
    and iot_device_1.ticket_mode
):
    logging.debug("All devices should be initiziled 1st...")


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
# Query IoT Device
#     - Private Autenticator (2, MBNs)
#         (->) Query Ticket
#             - IoT Device (1, A1Z)
######################################################
# -----------------------------------------------------
#     - (->) Query Ticket
# -----------------------------------------------------
private_authenticator_2.display_module_name()

logging.debug("Query...")

test_ticket = private_authenticator_2.generate_query_ticket()


# -----------------------------------------------------
#     -      Query Ticket (->)
# -----------------------------------------------------
iot_device_1.display_module_name()

logging.debug("Receive: " + str(test_ticket))
iot_device_1.verify_xxx_ticket(test_ticket)
