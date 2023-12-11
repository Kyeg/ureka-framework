# Environment
from ureka_framework.environment import Environment

# Resource (Storage)
from ureka_framework.resource.storage.simple_storage import SimpleStorage

# Resource (Logger)
from ureka_framework.resource.logger.simple_logger import simple_log

# View (CLI Menu)
from ureka_framework.view.menu_iot_device import MenuIoTDevice

if __name__ == "__main__":
    try:
        ######################################################
        # Unintialized Device
        ######################################################
        MenuIoTDevice.set_environment("cli")

        # RE-GIVEN:
        SimpleStorage.delete_storage_in_test()

        ######################################################
        # Intialize Device
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + Initialize Device")
        print(f"[   M-REC] : {f'*' * 50}")

        # GIVEN: Uninitialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")

        # WHEN: Holder: DM's CS apply the initialization_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.ticket_order == 1
        assert iot_device.shared_data.this_device.device_priv_key_str != None

        ######################################################
        # Transfer Device Ownership (DM to UA)
        ######################################################
        print(f"[   M-REC] : ")
        print(f"[   M-REC] : {f'*' * 50}")
        print(f"[   M-REC] : + Transfer Device Ownership (DM to UA)")
        print(f"[   M-REC] : {f'*' * 50}")

        # GIVEN: Initialized IoTD
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.owner_pub_key_str != None

    except RuntimeError as error:
        simple_log("error", f"{error}")
