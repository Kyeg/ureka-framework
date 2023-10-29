class Environment:
    # "TEST": Test Mode (e.g., logging, etc.)
    # "PRODUCTION": Production Mode (e.g., print, etc.)
    DEPLOYMENT_ENV = "TEST"

    # "TEST"
    INTERRUPT_CYCLE_TIME = 0.01
    # "PRODUCTION"
    NETWORK_DELAY = 0.1
