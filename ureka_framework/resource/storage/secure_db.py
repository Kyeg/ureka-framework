# File I/O
import os
import shutil
import errno

import ureka_framework.resource.crypto.serialization_util as serialization_util
from cryptography.hazmat.primitives.asymmetric import ec
import logging


class SecureDB:
    # Class Variables
    secure_db_path: str = os.path.abspath(os.path.dirname(__file__)) + "/SecureDB"

    # Instance Variables
    def __init__(self, device_name: str = "") -> None:
        # Device
        self.path_device_controller: str = self.secure_db_path + "/" + device_name
        self.path_has_device_type: str = "/HasDeviceType/HasDeviceType.txt"
        self.path_is_initialized: str = "/IsInitialized/IsInitialized.txt"
        self.path_device_type: str = "/DeviceType/DeviceType.txt"
        self.path_device_name: str = "/DeviceName/DeviceName.txt"
        self.path_device_priv: str = "/DevicePrivateKey/DevicePrivateKey.key"
        self.path_device_pub: str = "/DevicePublicKey/DevicePublicKey.key"
        self.path_owner_pub: str = "/OwnerPublicKey/OwnerPublicKey.key"

        # Person
        self.path_person_priv: str = "/PersonPrviateKey/PersonPrviateKey.key"
        self.path_person_pub: str = "/PersonPublicKey/PersonPublicKey.key"

    ######################################################
    # Device Storage
    ######################################################
    def load_secure_db(self) -> None:
        has_device_type: bool = False
        is_initialized: bool = False
        device_type: str = ""
        device_name: str = ""
        device_priv_key: ec.EllipticCurvePrivateKey = None
        device_pub_key: ec.EllipticCurvePublicKey = None
        owner_pub_key: ec.EllipticCurvePublicKey = None
        person_priv_key: ec.EllipticCurvePrivateKey = None
        person_pub_key: ec.EllipticCurvePublicKey = None

        if self._check_file_exist(self.path_has_device_type):
            has_device_type = True

        if self._check_file_exist(self.path_is_initialized):
            is_initialized = True

        if self._check_file_exist(self.path_device_type):
            if self._check_file_exist(self.path_device_name):
                device_type = self._load_str_file(self.path_device_type)
                device_name = self._load_str_file(self.path_device_name)

        if self._check_file_exist(self.path_device_priv):
            if self._check_file_exist(self.path_device_pub):
                device_priv_key = serialization_util.byte_to_key(
                    self._load_bytes_file(self.path_device_priv),
                    key_type="ecc-private-key",
                )
                device_pub_key = serialization_util.byte_to_key(
                    self._load_bytes_file(self.path_device_pub),
                    key_type="ecc-public-key",
                )

        if self._check_file_exist(self.path_owner_pub):
            owner_pub_key = serialization_util.byte_to_key(
                self._load_bytes_file(self.path_owner_pub), key_type="ecc-public-key"
            )

        if self._check_file_exist(self.path_person_priv):
            if self._check_file_exist(self.path_person_pub):
                person_priv_key = serialization_util.byte_to_key(
                    self._load_bytes_file(self.path_person_priv),
                    key_type="ecc-private-key",
                )
                person_pub_key = serialization_util.byte_to_key(
                    self._load_bytes_file(self.path_person_pub),
                    key_type="ecc-public-key",
                )

        return (
            has_device_type,
            is_initialized,
            device_type,
            device_name,
            device_priv_key,
            device_pub_key,
            owner_pub_key,
            person_priv_key,
            person_pub_key,
        )

    # Teardown - Development Only Function
    @classmethod
    def delete_secure_db_in_test(cls) -> None:
        # removing directory
        try:
            shutil.rmtree(cls.secure_db_path)
            logging.debug(f"Delete: {cls.secure_db_path}")
        except OSError as e:
            # logging.error(f"FAILURE: {e.filename} - {e.strerror}.")
            pass

    # Set Device Type
    def store_device_type_and_name(
        self,
        device_type: str,
        device_name: str,
    ) -> None:
        self._store_str_file(self.path_has_device_type, "HasDeviceType")
        self._store_str_file(self.path_device_type, device_type)
        self._store_str_file(self.path_device_name, device_name)

    # Initialization
    def store_is_initialized(
        self,
    ) -> None:
        self._store_str_file(self.path_is_initialized, "IsInitialized")

    # Initialization
    def store_device_id(
        self,
        device_priv_key_byte: bytes,
        device_pub_key_byte: bytes,
    ) -> None:
        self._store_bytes_file(self.path_device_priv, device_priv_key_byte)
        self._store_bytes_file(self.path_device_pub, device_pub_key_byte)

    # Initialization / Ownership-transfer
    def store_owner_id(self, owner_pub_key_byte: bytes) -> None:
        self._store_bytes_file(self.path_owner_pub, owner_pub_key_byte)

    # Initialization
    def store_person_id(
        self,
        person_priv_key_byte: bytes,
        person_pub_key_byte: bytes,
    ) -> None:
        self._store_bytes_file(self.path_person_priv, person_priv_key_byte)
        self._store_bytes_file(self.path_person_pub, person_pub_key_byte)

    ######################################################
    # File I/O (byte)
    ######################################################

    def _load_bytes_file(self, relative_path: str) -> bytes:
        # Get abs file path
        abs_path = self.path_device_controller + relative_path

        if self._check_file_exist(relative_path):
            # Open and read file
            with open(abs_path, "rb") as f:
                data = f.read()
            return data
        else:
            return b""

    def _load_str_file(self, relative_path: str) -> str:
        # Get abs file path
        abs_path = self.path_device_controller + relative_path

        if self._check_file_exist(relative_path):
            # Open and read file
            with open(abs_path, "r") as f:
                data = f.read()
            return data
        else:
            return ""

    def _store_bytes_file(self, relative_path: str, data: bytes) -> None:
        # Get abs file path
        abs_path = self.path_device_controller + relative_path

        # mkdir if not exist
        if not os.path.exists(os.path.dirname(abs_path)):
            try:
                os.makedirs(os.path.dirname(abs_path))
                # logging.debug(f"Create: {abs_path}")
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        # Open and write file
        with open(abs_path, "wb") as f:
            f.write(data)

    def _store_str_file(self, relative_path: str, data: str) -> None:
        # Get abs file path
        abs_path = self.path_device_controller + relative_path

        # mkdir if not exist
        if not os.path.exists(os.path.dirname(abs_path)):
            try:
                os.makedirs(os.path.dirname(abs_path))
                # logging.debug(f"Create: {abs_path}")
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        # Open and write file
        with open(abs_path, "w") as f:
            f.write(data)

    def _check_file_exist(self, relative_path: str) -> bool:
        # Get abs file path
        abs_path = self.path_device_controller + relative_path

        if os.path.exists(os.path.dirname(abs_path)):
            return True
        else:
            # logging.error(f"FAILURE: {relative_path} does not exist.")
            return False


######################################################
# Testing
######################################################

# mSecureDB = SecureDB(db_path = '')
# logging.info('Load SecureDB')


# path = '/hello_file.txt'
# data = b'abcd'
# mSecureDB._store_file(path, data)
# logging.info("")

# path = '/hello_file.txt'
# mSecureDB._load_file(path)
# logging.info("")


# mSecureDB.load_secure_db()
