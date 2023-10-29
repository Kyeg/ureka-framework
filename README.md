# ureka-framework

> The Ureka framework is a user-centric security framework that prioritizes the protection of user devices and data through comprehensive authentication, authorization, and auditing functions.

## Environment
+ Platform: MacOS (Darwin) or Linux (+ zsh/oh-my-zsh)
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
pip3 install -r requirements_platform_python_version.txt

pyenv deactivate
```

Install the environment through **venv** (for single version)
```
python3 -m venv .venv
source .venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements_platform_python_version.txt

deactivate
```

Always update the dependency files (Edit: top + Freeze: locked) if you install new packages:
```
vim requirements-top.txt
pip3 freeze > requirements_platform_python_version.txt
```

## PIP Note
Latest versions (after 3.4) may need Rust, use ==3.3.2 in legacy systems
<Ref> https://cryptography.io/en/latest/changelog/#v3-4


## Test & Experiment

Test the source code through **pytest** (& the log in the pytest.log)
```
pytest 
or pytest -v
```

or with more testing parameters (& the log in the pytest.log)
```
python3 run_tests.py
```

Experiment other source code
```
python3 demo.py
```


## Optional Tools

Apply MonkeyType to add type hints to the source code
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

