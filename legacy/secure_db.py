# Ureka Module
import legacy.key_serialization as key_serialization

# Testing
import logging

# File Path
import os
import shutil
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)
from typing import Tuple, Union


class SecureDB:
    def __init__(self, db_path: str = "") -> None:
        # File I/O
        # self.secure_db_path = os.path.abspath(os.path.dirname(__file__)) + "/secure_db"
        self.current_path = os.path.abspath(os.path.dirname(__file__)) + db_path

        self.path_device_priv = "/DeviceKey/PrivateKey.key"
        self.path_device_pub = "/DeviceKey/PublicKey.key"

        self.path_owner_pub = "/OwnerKey/PublicKey.key"

        # Device Id
        self.device_priv_key = None
        self.device_priv_key_byte = b""
        self.device_priv_key_str = ""

        self.device_pub_key = None
        self.device_pub_key_byte = b""
        self.device_pub_key_str = ""

        # Permission Table (Owner, manager...)
        self.owner_pub_key = None
        self.owner_pub_key_byte = b""
        self.owner_pub_key_str = ""

    def loadSecureDB(
        self, debug_mode: bool = False
    ) -> Union[
        Tuple[bool, None, str, None, str, None, str],
        Tuple[
            bool, _EllipticCurvePrivateKey, str, _EllipticCurvePublicKey, str, None, str
        ],
        Tuple[
            bool,
            _EllipticCurvePrivateKey,
            str,
            _EllipticCurvePublicKey,
            str,
            _EllipticCurvePublicKey,
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

                if debug_mode:
                    logging.debug("device_priv_key_str: %s" % self.device_priv_key_str)
                    logging.debug("device_pub_key_str: %s" % self.device_pub_key_str)
                    logging.debug("")

                is_initialized = True

        if self.checkFileExist(self.path_owner_pub):
            self.owner_pub_key_byte = self.loadFile(self.path_owner_pub)
            self.owner_pub_key = key_serialization.byte_backto_key(
                self.owner_pub_key_byte, key_type="ecc-public-key"
            )
            self.owner_pub_key_str = key_serialization.byte_to_str(
                self.owner_pub_key_byte
            )

            if debug_mode:
                logging.debug("owner_pub_key_str: %s" % self.owner_pub_key_str)
                logging.debug("")

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
    def deleteSecureDB(self, debug_mode: bool = False) -> None:
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
        debug_mode: bool = False,
    ) -> None:
        self.storeFile(self.path_device_priv, device_priv_key_byte)
        self.storeFile(self.path_device_pub, device_pub_key_byte)

    # Initialization / Ownership-transfer
    def storeOwnerKey(
        self, owner_pub_key_byte: bytes, debug_mode: bool = False
    ) -> None:
        self.storeFile(self.path_owner_pub, owner_pub_key_byte)

    ######################################################
    # File I/O (byte)
    ######################################################
    def storeFile(
        self, relative_path: str, data: bytes, debug_mode: bool = False
    ) -> None:
        # Get abs file path
        abs_path = self.current_path + relative_path

        if debug_mode:
            logging.debug("Data : %s" % data)

        # Create directory if not exist
        if not os.path.exists(os.path.dirname(abs_path)):
            try:
                os.makedirs(os.path.dirname(abs_path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    if debug_mode:
                        logging.debug("Directory not exist.")
                    raise

        # Open and write file
        with open(abs_path, "wb") as f:
            f.write(data)

        if debug_mode:
            logging.debug("Store Data in : %s" % abs_path)

    def loadFile(self, relative_path: str, debug_mode: bool = False) -> bytes:
        # Get abs file path
        abs_path = self.current_path + relative_path

        if debug_mode:
            logging.debug("Load Data from : %s" % abs_path)

        if self.checkFileExist(relative_path):
            # Open and read file
            with open(abs_path, "rb") as f:
                data = f.read()

            if debug_mode:
                logging.debug("Data : %s" % data)

            return data

        if debug_mode:
            logging.debug("File not exist.")

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
# mSecureDB.storeFile(path, data, debug_mode = True)
# logging.debug("")

# path = '/hello_file.txt'
# mSecureDB.loadFile(path, debug_mode = True)
# logging.debug("")


# mSecureDB.loadSecureDB(debug_mode = True)
