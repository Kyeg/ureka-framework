# File I/O
from pathlib import Path
import shutil

from typing import Tuple
from ureka_framework.data_model.this_device import ThisDevice
from ureka_framework.data_model.this_person import ThisPerson
import logging
from ureka_framework.data_model.this_device import (
    jsonstr_to_this_device,
    this_device_to_jsonstr,
)
from ureka_framework.data_model.this_person import (
    jsonstr_to_this_person,
    this_person_to_jsonstr,
)


class SimpleStorage:
    # Class Variables
    path_storage: Path = Path(__file__).parent / "SimpleStorage"

    # Instance Variables
    def __init__(self, device_name: str) -> None:
        # Directory Path
        self.path_device_controller: Path = self.path_storage / device_name
        self._create_root_directory_for_each_device_controller()

        # File Path for Data Model
        self.path_this_device: Path = self.path_device_controller / "this_device.json"
        self.path_this_person: Path = self.path_device_controller / "this_person.json"

    def _create_root_directory_for_each_device_controller(self) -> None:
        # Create a new directory if it doesn't exist
        if not Path(self.path_device_controller).exists():
            self.path_device_controller.mkdir(parents=True)
            logging.debug(f"Create: {self.path_device_controller}")
        else:
            logging.debug(f"Exist: {self.path_device_controller}")

    def store_storage(self, this_device: ThisDevice, this_person: ThisPerson) -> None:
        with self.path_this_device.open("w") as file:
            file.write(this_device_to_jsonstr(this_device))

        with self.path_this_person.open("w") as file:
            file.write(this_person_to_jsonstr(this_person))

    def load_storage(self) -> Tuple[ThisDevice, ThisPerson]:
        this_device: ThisDevice = ThisDevice()
        this_person: ThisPerson = ThisPerson()

        if Path(self.path_this_device).exists():
            with self.path_this_device.open("r") as file:
                this_device: ThisDevice = jsonstr_to_this_device(file.read())

        if Path(self.path_this_person).exists():
            with self.path_this_person.open("r") as file:
                this_person: ThisPerson = jsonstr_to_this_person(file.read())

        return (this_device, this_person)

    # Teardown - Development Only Function
    @classmethod
    def delete_storage_in_test(cls) -> None:
        # removing directory (If use Path.rmdir(), the directory must be empty...)
        try:
            shutil.rmtree(cls.path_storage)
            logging.debug(f"Delete: {cls.path_storage}")
        except OSError as e:
            # logging.error(f"FAILURE: {e.filename} - {e.strerror}.")
            pass
