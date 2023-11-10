# ureka-framework

> The Ureka framework is a user-centric security framework that prioritizes the protection of user devices and data through comprehensive authentication, authorization, and auditing functions.

## Environment

+ Hardware: Mac (Apple M2, arm64), Raspberry Pi 3B (ARM Cortex-A53, armv7l), Tinker Board (ARMv7 Processor, armv7l)
+ Platform: MacOS (Darwin), Linux (+ zsh/oh-my-zsh)
+ Python: 3.9.2 (default Python version on Raspberry Pi OS, until 2023.10)
+ Package Management: venv/pyenv + pip
+ Formatter: Black
+ Testing: pytest + pytest-cover


## Get Started

Install the environment through **pyenv** (for multiple versions)
```
pyenv install 3.9.2
pyenv virtualenv 3.9.2 project-name-version
pyenv activate project-name-version
pip3 install --upgrade pip
pip3 install -r requirements/requirements_platform_python_version.txt

...
<command> 
or pyenv exec <command>    # if version has conflict
...

pyenv deactivate
```

Install the environment through **venv** (for single version)
```
python3 -m venv .venv
source .venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements/requirements_platform_python_version.txt

...
<command> 
...

deactivate
```

Always update the dependency files (Edit: top + Freeze: locked) if you install new packages:
```
vim requirements/requirements-top.txt
pip3 freeze > requirements/requirements_platform_python_version.txt
```


## Program Arguments

Optionally add program arguments in `.vscode/launch.json`.
+ For example, add bluetooth MAC address for connecting.


## PIP: PyBluez (Bluetooth Classic)

### Homepage
+ Bluetooth for Python: [pybluez/pybluez](https://github.com/pybluez/pybluez)

### Dependency
+ Linux
    + `$ sudo apt-get install bluetooth libbluetooth-dev bluez python-bluez`

### Trouble-shooting
+ 'Installation - error in PyBluez setup command: use_2to3 is invalid'
    + Install PyBluez==0.30 from source (latest Bluetooth Python extension module  as [pybluez/setup.py](https://github.com/pybluez/pybluez/blob/master/setup.py))
    + [< Ref > Installation Error: use_2to3 ](https://github.com/pybluez/pybluez/issues/431#issuecomment-1107884273)
+ 'Discoverable Mode'
    + `$ sudo hciconfig hci0 piscan (can be added in shell booting procedure)`
    + or `$ bluetoothctl discoverable` + `$ bluetoothctl discoverable-timeout=0` (but may not feasible in every legacy device)
    + [< Ref > BT Error: Discoverable](https://github.com/sraodev/bluetooth-service-rfcomm-python)
+ 'No such file or directory'
    + Put `$ ExecStart=/usr/lib/bluetooth/bluetoothd -C` in /lib/systemd/system/bluetooth.service, and etc.
    + [< Ref > BT Error: No such file or directory](https://stackoverflow.com/questions/36675931/bluetooth-btcommon-bluetootherror-2-no-such-file-or-directory/63455894#63455894)
+ 'Permission denied'
    + `$ sudo chgrp bluetooth /var/run/sdp`, and etc.
    + [< Ref > BT Error: Permission Denied](https://stackoverflow.com/questions/34599703/rfcomm-bluetooth-permission-denied-error-raspberry-pi/42306883#42306883)
+ 'Connection refused'
    + `$ DisablePlugins = pnat`, and etc.
    + [< Ref > BT Error: DisablePlugins](https://stackoverflow.com/questions/31331741/what-does-disableplugins-pnat-do)


## PIP: Cryptography

### Homepage
+ Cryptography for Python: [pyca/cryptography](https://github.com/pyca/cryptography)

### Dependency
+ Linux
    + `$ sudo apt-get install build-essential libssl-dev libffi-dev \ python3-dev cargo pkg-config`
+ MacOS
    + `$ xcode-select --install`
    + `$ brew install openssl@3 rust`

### Trouble-shooting
+ 'Rust Installation Issue'
    + Latest versions (after 3.4) may need Rust, use ==3.3.2 in legacy systems
    + [< Ref > PYCA/Cryptography: Change Log](https://cryptography.io/en/latest/changelog/#v3-4)


## Test (Simulation in Single Node) & Experiment (Demo for Multiple Nodes in Real Network)

Experiment specific source code
```
python3 demo.py
```


Test the source code through **pytest** (& the log in the pytest.log)
```
pytest 
or pytest -v
```

Or with more testing parameters (& the log in the pytest.log) & Generate the coverage report
```
python3 run_tests.py
```

Open the coverage report through **pytest-cover** locally or remotely (& the report in the htmlcov/ folder, e.g., the html/index.html)

Locally:
```
open htmlcov/index.html
```

Remotely (in Browser or in VSCode Preview):
```
python3 -m http.server 8000
http://localhost:8000/htmlcov/ or http://host-ip:8000/htmlcov/
```


## Optional Tools

### 1. Apply Tree to show the directory structure
```
tree -aI '__pycache__|.git|.venv|.pytest_cache|.mypy_cache|htmlcov|__init__.py' .
```

### 2. Apply MonkeyType to add Python Type Hints to the source code

Manually:
```
monkeytype run run_tests.py
monkeytype list-modules
monkeytype apply ureka_framework.module_name...
monkeytype apply tests.testxxx...
```

Automatically:
```
monkeytype run run_tests.py
monkeytype list-modules >> list-monkeytype.txt
python3 auto-monkeytype.py
```

### 3. Apply Pyreverse (in pylint) to show UML diagram
Manually:
```
pyreverse -ASmy -o <png> <src-path> (-c <ClassName>)
```