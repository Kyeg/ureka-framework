def simple_log(log_level: str, log_info: str) -> None:  # pragma: no cover -> PRODUCTION
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
