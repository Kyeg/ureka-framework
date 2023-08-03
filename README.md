# ureka-framework

> The Ureka framework is a user-centric security framework that prioritizes the protection of user devices and data through comprehensive authentication, authorization, and auditing functions.

## Environment
+ Python: 3.11.4
+ Package Management: venv + pip
+ Formatter: Black
+ Testing: Pytest


## Get Started

Install the environment through **venv**

```
python3 -m venv .venv
source .venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements-top.txt
```

Test the source code through **pytest** (& the log in the pytest.log)

```
pytest
```

or with more testing parameters (& the log in the pytest.log)

```
python3 run_tests.py
```

Experiment other source code

```
python3 run_exp.py
```

Always update the dependency files if you install new packages:

```
vim requirements-top.txt
pip3 freeze > requirements.txt
```

## Optional Tools

Apply MonkeyType to add type hints to the source code

```
monkeytype run run_tests.py
monkeytype list-modules
monkeytype apply ureka_framework.module_name...
monkeytype apply tests.testxxx...
```

