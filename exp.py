class DeviceController:
    def __init__(self) -> None:
        # Data Model (Persistent)
        self.this_device: str = "456"

        # Worker
        self.executor = Executor(
            controller=self,
        )


class Executor:
    def __init__(
        self,
        controller: DeviceController,
    ) -> None:
        # Store a reference to the DeviceController instance
        self.controller = controller

    def change_this_device(self):
        # Modify the this_device attribute of the DeviceController instance
        self.controller.this_device = "123"


cloud_server_dm = DeviceController()

print(cloud_server_dm.shared_data.this_device)  # Output: "123"


cloud_server_dm.executor.change_this_device()  # Change the this_device attribute in Executor
print(cloud_server_dm.shared_data.this_device)  # Output: "123"
