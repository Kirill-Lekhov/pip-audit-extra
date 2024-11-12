# pip-audit-extra
Extended version of [pip-audit](https://pypi.org/project/pip-audit/).

## Features
* Viewing vulnerabilities of project dependencies along with severities.

## Installation
```sh
pip install pip-audit-extra
```

## Usage
```sh
cat requirements.txt | pip-audit-extra
```

Poetry
```sh
poetry export -f requirements.txt | pip-audit-extra
```

### Severity filter
If necessary, you can filter vulnerabilities by severity.
```sh
cat requirements.txt | pip-audit-extra --severity CRITICAL
```
