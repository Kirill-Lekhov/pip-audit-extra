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

UV
```sh
uv export --format requirements-txt | pip-audit-extra
```

### Severity filter
If necessary, you can filter vulnerabilities by severity.
By default, the filter selects vulnerabilities with the specified severity AND SEVERITIES WITH A HIGHER PRIORITY.
It only affects the vulnerability table.
```sh
cat requirements.txt | pip-audit-extra --severity CRITICAL
```

To select only the specified level, add the prefix `~`, for example:
```sh
cat requirements.txt | pip-audit-extra --severity ~CRITICAL
```

### Fail level
You can set severity of vulnerability from which the audit will be considered to have failed.
```sh
cat requirements.txt | pip-audit-extra --fail-level HIGH
```
In this example, the audit will be considered failed if vulnerabilities of CRITICAL or HIGH severity are found.
