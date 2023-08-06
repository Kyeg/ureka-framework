import inspect
import logging
import pytest


######################################################
# Helper Functions
######################################################
def get_current_class_name() -> str:
    # Get Current Class Name
    for frame_info in inspect.stack():
        frame_locals = frame_info.frame.f_locals
        if "self" in frame_locals:
            return frame_locals["self"].__class__.__name__


def get_current_function_name() -> str:
    # Get Current Function Name called by the test
    for frame_info in inspect.stack():
        frame_locals = frame_info.frame.f_locals
        if "self" in frame_locals:
            return frame_info.function


def setup_log() -> None:
    # Log
    if get_current_class_name() != None:
        logging.info("")
        logging.info("*" * 50)
        logging.info(f"Setup: {get_current_class_name()}")
        logging.info("*" * 50)


def test_log() -> None:
    # Log
    if (
        get_current_function_name() != "_hookexec"
        and get_current_function_name() != None
    ):
        logging.info("*" * 50)
        logging.info(f"Test: {get_current_function_name()}")
        logging.info("*" * 50)


def teardown_log() -> None:
    # Log
    if get_current_class_name() != None:
        logging.info("*" * 50)
        logging.info(f"Teardown: {get_current_class_name()}")
        logging.info("*" * 50)


######################################################
# Fixtures (Reusable Test Data)
######################################################
