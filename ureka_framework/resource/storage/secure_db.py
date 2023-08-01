# File I/O
import os
import shutil
import errno

import ureka_framework.resource.crypto.serialization_util as serialization_util
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple
import logging


class SecureDB:
    def __init__(self, db_path: str = "") -> None:
        # File I/O
        # self.secure_db_path = os.path.abspath(os.path.dirname(__file__)) + "/secure_db"
        self.current_path: str = os.path.abspath(os.path.dirname(__file__)) + db_path

        self.path_device_priv: str = "/DeviceKey/PrivateKey.key"
        self.path_device_pub: str = "/DeviceKey/PublicKey.key"
        self.path_owner_pub: str = "/OwnerKey/PublicKey.key"

        self.device_priv_key: ec.EllipticCurvePrivateKey = None
        self.device_pub_key: ec.EllipticCurvePublicKey = None
        self.owner_pub_key: ec.EllipticCurvePublicKey = None

    ######################################################
    # Device Storage
    ######################################################
    def load_secure_db(
        self,
    ) -> Tuple[
        bool,
        ec.EllipticCurvePrivateKey | None,
        ec.EllipticCurvePublicKey | None,
        ec.EllipticCurvePublicKey | None,
    ]:
        # False: Uninitialized / True: Initialized
        is_initialized = False

        if self._check_file_exist(self.path_device_priv):
            if self._check_file_exist(self.path_device_pub):
                self.device_priv_key = serialization_util.byte_to_key(
                    self._load_file(self.path_device_priv), key_type="ecc-private-key"
                )
                self.device_pub_key = serialization_util.byte_to_key(
                    self._load_file(self.path_device_pub), key_type="ecc-public-key"
                )
                is_initialized = True

        if self._check_file_exist(self.path_owner_pub):
            self.owner_pub_key = serialization_util.byte_to_key(
                self._load_file(self.path_owner_pub), key_type="ecc-public-key"
            )
            is_initialized = True

        return (
            is_initialized,
            self.device_priv_key,
            self.device_pub_key,
            self.owner_pub_key,
        )

    # Teardown - Development Only Function
    def delete_secure_db(self) -> None:
        # removing directory
        try:
            # shutil.rmtree(self.secure_db_path)
            shutil.rmtree(self.current_path)
            logging.debug(f"{self.current_path} deleted.")
        except OSError as e:
            logging.error(f"ERROR: {e.filename} - {e.strerror}.")

    # Initialization
    def store_device_id(
        self,
        device_priv_key_byte: bytes,
        device_pub_key_byte: bytes,
    ) -> None:
        self._store_file(self.path_device_priv, device_priv_key_byte)
        self._store_file(self.path_device_pub, device_pub_key_byte)

    # Initialization / Ownership-transfer
    def store_owner_id(self, owner_pub_key_byte: bytes) -> None:
        self._store_file(self.path_owner_pub, owner_pub_key_byte)

    ######################################################
    # File I/O (byte)
    ######################################################

    def _load_file(self, relative_path: str) -> bytes:
        # Get abs file path
        abs_path = self.current_path + relative_path

        if self._check_file_exist(relative_path):
            # Open and read file
            with open(abs_path, "rb") as f:
                data = f.read()
            return data
        else:
            logging.error(f"ERROR: {relative_path} does not exist.")
            return b""

    def _store_file(self, relative_path: str, data: bytes) -> None:
        # Get abs file path
        abs_path = self.current_path + relative_path

        # Create directory if not exist
        if not os.path.exists(os.path.dirname(abs_path)):
            try:
                os.makedirs(os.path.dirname(abs_path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        # Open and write file
        with open(abs_path, "wb") as f:
            f.write(data)

    def _check_file_exist(self, relative_path: str) -> bool:
        # Get abs file path
        abs_path = self.current_path + relative_path

        if not os.path.exists(os.path.dirname(abs_path)):
            return False
        else:
            return True


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
