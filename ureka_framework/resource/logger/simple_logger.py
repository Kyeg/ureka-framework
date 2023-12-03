import logging
from ureka_framework.environment import Environment


def simple_log(log_level: str, log_info: str) -> None:  # pragma: no cover -> PRODUCTION
    if Environment.DEPLOYMENT_ENV == "TEST":
        if Environment.DEBUG_LOG == "OPEN":
            if log_level == "debug":
                logging.debug(log_info)
            elif log_level == "info":
                logging.info(log_info)

        if Environment.DEBUG_LOG == "OPEN" or Environment.DEBUG_LOG == "CLOSED":
            if log_level == "warning":
                logging.warning(log_info)
            elif log_level == "error":
                logging.error(log_info)
            elif log_level == "critical":
                logging.critical(log_info)

        if Environment.CLI_LOG == "OPEN":
            if log_level == "cli":
                logging.debug(log_info)

        if Environment.MEASURE_LOG == "OPEN":
            if log_level == "measure":
                logging.debug(log_info)

    elif Environment.DEPLOYMENT_ENV == "PRODUCTION":
        if Environment.DEBUG_LOG == "OPEN":
            if log_level == "debug":
                print(f"[   DEBUG] : {log_info}")
            elif log_level == "info":
                print(f"[    INFO] : {log_info}")

        if Environment.DEBUG_LOG == "OPEN" or Environment.DEBUG_LOG == "CLOSED":
            if log_level == "warning":
                print(f"[ WARNING] : {log_info}")
            elif log_level == "error":
                print(f"[   ERROR] : {log_info}")
            elif log_level == "critical":
                print(f"[CRITICAL] : {log_info}")

        if Environment.CLI_LOG == "OPEN":
            if log_level == "cli":
                print(f"[     CLI] : {log_info}")

        if Environment.MEASURE_LOG == "OPEN":
            if log_level == "measure":
                print(f"[ MEASURE] : {log_info}")

    else:
        raise RuntimeError(
            f"Deployment Environment: {Environment.DEPLOYMENT_ENV} is not supported."
        )
