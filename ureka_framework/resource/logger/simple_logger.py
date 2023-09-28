import logging

# "TEST": Test Mode (e.g., logging, etc.)
# "PRODUCTION": Production Mode (e.g., print, etc.)
DEPLOYMENT_ENV = "TEST"


def simple_log(log_level: str, log_info: str):  # pragma: no cover
    global DEPLOYMENT_ENV

    if DEPLOYMENT_ENV == "TEST":
        if log_level == "debug":
            logging.debug(log_info)
        elif log_level == "info":
            logging.info(log_info)
        elif log_level == "warning":
            logging.warning(log_info)
        elif log_level == "error":
            logging.error(log_info)
        elif log_level == "critical":
            logging.critical(log_info)
        else:
            raise RuntimeError(f"Log Level: {log_level} is not supported.")
    elif DEPLOYMENT_ENV == "PRODUCTION":
        # Can omit debug logs, or even omit all logs
        if log_level == "debug":
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
    else:
        raise RuntimeError(
            f"Deployment Environment: {DEPLOYMENT_ENV} is not supported."
        )
