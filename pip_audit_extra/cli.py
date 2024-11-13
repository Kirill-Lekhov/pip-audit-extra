from pip_audit_extra.vulnerability.filter.severity import SeverityFilterOption
from pip_audit_extra.severity import Severity

from argparse import ArgumentParser, ArgumentTypeError
from typing import Optional, Any, Final


FILTER_PREFIX_EXAC: Final[str] = "~"


class SeverityFilterHandler:
	"""
	Converts value to optional SeverityFilterOption object.
	"""
	def __init__(self) -> None:
		self.severity_names = set(Severity.get_names())

	def __call__(self, value: Any) -> Optional[SeverityFilterOption]:
		if value is None:
			return value

		if not isinstance(value, str):
			raise ArgumentTypeError("Value must be str or None")

		if value.startswith(FILTER_PREFIX_EXAC):
			return SeverityFilterOption(True, self.get_severity(value.lstrip(FILTER_PREFIX_EXAC)))

		return SeverityFilterOption(False, self.get_severity(value))

	def get_severity(self, severity_name: str) -> Severity:
		severity_name = severity_name.upper()

		if severity_name not in self.severity_names:
			raise ArgumentTypeError("Unknown severity was met")

		return Severity[severity_name]


def get_parser() -> ArgumentParser:
	parser = ArgumentParser(
		"pip-audit-extra",
		description="An add-on to the pip-audit utility, which allows to work with vulnerabilities of a certain severity",
	)
	parser.add_argument(
		"--severity",
		type=SeverityFilterHandler(),
		default=None,
		help=f"""\
vulnerability filter by severity.
Possible values: {', '.join(Severity.get_names())}.
By default, the filter selects vulnerabilities with the specified severity AND SEVERITIES WITH A HIGHER PRIORITY.
To select only the specified level, add the prefix `~`, for example `--severity ~HIGH`\
""",
	)

	return parser
