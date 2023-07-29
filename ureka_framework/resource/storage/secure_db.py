import os
import shutil
import errno
from cryptography.hazmat.primitives.asymmetric import ec

import ureka_framework.resource.crypto.key_serialization as key_serialization
import logging
from typing import Tuple, Union


class SecureDB:
    def __init__(self, db_path: str = "") -> None:
        # File I/O
        # self.secure_db_path = os.path.abspath(os.path.dirname(__file__)) + "/secure_db"
        self.current_path: str = os.path.abspath(os.path.dirname(__file__)) + db_path

        self.path_device_priv: str = "/DeviceKey/PrivateKey.key"
        self.path_device_pub: str = "/DeviceKey/PublicKey.key"

        self.path_owner_pub: str = "/OwnerKey/PublicKey.key"

        # Device Id
        self.device_priv_key: ec.EllipticCurvePrivateKey = None
        self.device_priv_key_byte: bytes = b""
        self.device_priv_key_str: str = ""

        self.device_pub_key: ec.EllipticCurvePublicKey = None
        self.device_pub_key_byte: bytes = b""
        self.device_pub_key_str: str = ""

        # Permission Table (Owner, manager...)
        self.owner_pub_key: ec.EllipticCurvePublicKey = None
        self.owner_pub_key_byte: bytes = b""
        self.owner_pub_key_str: str = ""

    def loadSecureDB(
        self,
    ) -> Union[
        Tuple[bool, None, str, None, str, None, str],
        Tuple[
            bool,
            ec.EllipticCurvePrivateKey,
            str,
            ec.EllipticCurvePublicKey,
            str,
            None,
            str,
        ],
        Tuple[
            bool,
            ec.EllipticCurvePrivateKey,
            str,
            ec.EllipticCurvePublicKey,
            str,
            ec.EllipticCurvePublicKey,
            str,
        ],
    ]:
        # False: Uninitialized / True: Initialized
        is_initialized = False

        if self.checkFileExist(self.path_device_priv):
            if self.checkFileExist(self.path_device_pub):
                self.device_priv_key_byte = self.loadFile(self.path_device_priv)
                self.device_priv_key = key_serialization.byte_backto_key(
                    self.device_priv_key_byte, key_type="ecc-private-key"
                )
                self.device_priv_key_str = key_serialization.byte_to_str(
                    self.device_priv_key_byte
                )

                self.device_pub_key_byte = self.loadFile(self.path_device_pub)
                self.device_pub_key = key_serialization.byte_backto_key(
                    self.device_pub_key_byte, key_type="ecc-public-key"
                )
                self.device_pub_key_str = key_serialization.byte_to_str(
                    self.device_pub_key_byte
                )

                is_initialized = True

        if self.checkFileExist(self.path_owner_pub):
            self.owner_pub_key_byte = self.loadFile(self.path_owner_pub)
            self.owner_pub_key = key_serialization.byte_backto_key(
                self.owner_pub_key_byte, key_type="ecc-public-key"
            )
            self.owner_pub_key_str = key_serialization.byte_to_str(
                self.owner_pub_key_byte
            )

            is_initialized = True

        return (
            is_initialized,
            self.device_priv_key,
            self.device_priv_key_str,
            self.device_pub_key,
            self.device_pub_key_str,
            self.owner_pub_key,
            self.owner_pub_key_str,
        )

    # Teardown - Development Only Function
    def deleteSecureDB(self) -> None:
        # removing directory
        try:
            # shutil.rmtree(self.secure_db_path)
            shutil.rmtree(self.current_path)
            logging.debug(f"{self.current_path} deleted.")
        except OSError as e:
            logging.debug(f"ERROR: {e.filename} - {e.strerror}.")

    # Initialization
    def initDeviceId(
        self,
        device_priv_key_byte: bytes,
        device_pub_key_byte: bytes,
    ) -> None:
        self.storeFile(self.path_device_priv, device_priv_key_byte)
        self.storeFile(self.path_device_pub, device_pub_key_byte)

    # Initialization / Ownership-transfer
    def storeOwnerKey(self, owner_pub_key_byte: bytes) -> None:
        self.storeFile(self.path_owner_pub, owner_pub_key_byte)

    ######################################################
    # File I/O (byte)
    ######################################################
    def storeFile(self, relative_path: str, data: bytes) -> None:
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

    def loadFile(self, relative_path: str) -> bytes:
        # Get abs file path
        abs_path = self.current_path + relative_path

        if self.checkFileExist(relative_path):
            # Open and read file
            with open(abs_path, "rb") as f:
                data = f.read()
            return data
        else:
            logging.debug(f"ERROR: {relative_path} does not exist.")
            return b""

    def checkFileExist(self, relative_path: str) -> bool:
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
# logging.debug('+++ Load SecureDB +++ \n')


# path = '/hello_file.txt'
# data = b'abcd\n'
# mSecureDB.storeFile(path, data)
# logging.debug("")

# path = '/hello_file.txt'
# mSecureDB.loadFile(path)
# logging.debug("")


# mSecureDB.loadSecureDB()
