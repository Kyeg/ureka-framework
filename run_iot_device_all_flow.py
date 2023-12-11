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
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Initialize Device")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Uninitialized IoTD
        menu_iot_device = MenuIoTDevice(device_name="iot_device")

        # WHEN: Holder: DM's CS apply the initialization_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.ticket_order == 1
        assert iot_device.shared_data.this_device.device_priv_key_str != None

        ######################################################
        # Transfer Device Ownership
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Transfer Device Ownership")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Initialized IoTD
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: DO's UA apply the ownership_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert iot_device.shared_data.this_device.owner_pub_key_str != None

        ######################################################
        # Receive Insecure Command & Send Insecure Data
        ######################################################
        for option in ["shortest", "with_device_id", "u_ticket_size"]:
            print(f"[   PRINT] : ")
            print(f"[   PRINT] : {f'*' * 50}")
            print(f"[   PRINT] : + Insecurely Recv Command & Send Data ({option})")
            print(f"[   PRINT] : {f'*' * 50}")

            # GIVEN: Initialized IoTD
            iot_device = menu_iot_device.get_iot_device()

            # WHEN: DM's CS apply the insecure_cmd to IoTD
            iot_device = menu_iot_device.receive_insecure_cmd_through_bluetooth(
                option=option
            )

            # THEN: ...

        ######################################################
        # Grant Device Access Right (to owner herself)
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Grant Device Access Right (to owner herself)")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Initialized IoTD
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: EP's CS apply the self_access_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the access_end_u_token to IoTD
        original_device_order = iot_device.shared_data.this_device.ticket_order
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert (
            iot_device.shared_data.this_device.ticket_order == original_device_order + 1
        )

        ######################################################
        # Grant Device Access Right (to other)
        ######################################################
        print(f"[   PRINT] : ")
        print(f"[   PRINT] : {f'*' * 50}")
        print(f"[   PRINT] : + Grant Device Access Right (to other)")
        print(f"[   PRINT] : {f'*' * 50}")

        # GIVEN: Initialized IoTD
        iot_device = menu_iot_device.get_iot_device()

        # WHEN: Holder: EP's CS apply the access_u_ticket to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the u_token to IoTD
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + iot_device.shared_data.current_session.plaintext_cmd
        )

        ###########################

        # GIVEN: IoTD cannot be rebooted, because the state & session is non-volatile

        # WHEN: Holder: EP's CS apply the access_end_u_token to IoTD
        original_device_order = iot_device.shared_data.this_device.ticket_order
        iot_device = menu_iot_device.receive_u_ticket_through_bluetooth()

        # THEN: Succeed to share a private session with DO's IoTD
        assert "SUCCESS" in iot_device.shared_data.result_message
        assert (
            iot_device.shared_data.this_device.ticket_order == original_device_order + 1
        )

        ###########################

    except RuntimeError as error:
        simple_log("error", f"{error}")
