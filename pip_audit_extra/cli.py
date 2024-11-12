from pip_audit_extra.severity import Severity

from argparse import ArgumentParser
from typing import Optional, Any


def severity_handler(value: Any) -> Optional[Severity]:
	"""
	Converts raw values to optional Severity type.

	Args:
		value: Value to convert.

	Returns:
		Severity enum value or None.
	"""
	if value is None:
		return value

	return Severity(value)


def get_parser() -> ArgumentParser:
	parser = ArgumentParser(
		"pip-audit-extra",
		description="An add-on to the pip-audit utility, which allows to work with vulnerabilities of a certain severity",
	)
	parser.add_argument("--severity", type=severity_handler, choices=Severity, default=None)

	return parser
