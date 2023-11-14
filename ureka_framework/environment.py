class Environment:
    ######################################################
    # Deployment Environment
    ######################################################
    # "TEST": Test Mode (e.g., logging, etc.)
    # "PRODUCTION": Production Mode (e.g., print, etc.)
    DEPLOYMENT_ENV = "TEST"

    ######################################################
    # Communication Channel
    ######################################################
    # "SIMULATED": Exchange message through shared memory
    # "BLUETOOTH": Exchange message through bluetooth communication
    COMMUNICATION_CHANNEL = "SIMULATED"

    # "TEST": No Delay (complete tests faster)
    # "PRODUCTION": With Delay (make local simulation interactive)
    SIMULULATED_COMM_DELAY = 1
    SIMULULATED_COMM_INTERRUPT_CYCLE_TIME = 0.01

    ######################################################
    # Log
    ######################################################
    # "OPEN": Print Log
    # "CLOSED": Not Print Log
    DEBUG_LOG = "OPEN"
    CLI_LOG = "OPEN"
    MEASURE_LOG = "OPEN"
