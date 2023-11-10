import logging
from ureka_framework.environment import Environment


def simple_log(log_level: str, log_info: str) -> None:  # pragma: no cover -> PRODUCTION
    if Environment.DEPLOYMENT_ENV == "TEST":
        if log_level == "demo":
            logging.debug(log_info)
        elif log_level == "debug":
            logging.debug(log_info)
            pass
        elif log_level == "info":
            logging.info(log_info)
            pass
        elif log_level == "warning":
            logging.warning(log_info)
        elif log_level == "error":
            logging.error(log_info)
        elif log_level == "critical":
            logging.critical(log_info)
        else:
            raise RuntimeError(f"Log Level: {log_level} is not supported.")
    elif Environment.DEPLOYMENT_ENV == "PRODUCTION":
        # Can omit debug logs, or even omit all logs
        if log_level == "demo":
            print(f"[    DEMO] : {log_info}")
        elif log_level == "debug":
            print(f"[   DEBUG] : {log_info}")
        elif log_level == "info":
            print(f"[    INFO] : {log_info}")
        elif log_level == "warning":
            print(f"[ WARNING] : {log_info}")
        elif log_level == "error":
            print(f"[   ERROR] : {log_info}")
        elif log_level == "critical":
            print(f"[CRITICAL] : {log_info}")
        else:
            raise RuntimeError(f"Log Level: {log_level} is not supported.")
    elif Environment.DEPLOYMENT_ENV == "DEMO":
        # Keep only demo logs, omit all other logs
        if log_level == "demo":
            print(f"[    DEMO] : {log_info}")
    else:
        raise RuntimeError(
            f"Deployment Environment: {Environment.DEPLOYMENT_ENV} is not supported."
        )
