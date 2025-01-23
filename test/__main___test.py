from pip_audit_extra import __main__ as main
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.vulnerability.filter.severity import SeverityFilterOption
from pip_audit_extra.severity import Severity
from test.factory import make_vulnerability

from typing import List, Optional
from unittest.mock import patch


class FakeConsoleStatus:
	def __enter__(self):
		pass

	def __exit__(self, *args, **kwargs):
		pass


class FakeConsole:
	def __init__(self) -> None:
		self._last_status_text = None
		self._last_status_spinner = None
		self._last_print_text = None

	def status(self, text: str, spinner: str) -> FakeConsoleStatus:
		self._last_status_text = text
		self._last_status_spinner = spinner

		return FakeConsoleStatus()

	def print(self, text: str):
		self._last_print_text = text


class FakeNamespace:
	def __init__(self, severity: SeverityFilterOption, cache_lifetime: str, fail_level: Optional[Severity]) -> None:
		self.severity = severity
		self.cache_lifetime = cache_lifetime
		self.fail_level = fail_level


class FakeParser:
	def __init__(self, namespace: FakeNamespace) -> None:
		self.namespace = namespace
		self._last_parse_args_argv = None

	def parse_args(self, argv: List[str]) -> FakeNamespace:
		self._last_parse_args_argv = argv

		return self.namespace


class FakeStream:
	def __init__(self, content: str) -> None:
		self.content = content

	def read(self) -> str:
		return self.content


class FakeAuditor:
	def __init__(self, cache_lifetime: str, *, vulnerabilities: List[Vulnerability]) -> None:
		self.cache_lifetime = cache_lifetime
		self._last_audit_requirements = None
		self._vulnerabilities = vulnerabilities

	def audit(self, requirements: str) -> List[Vulnerability]:
		self._last_audit_requirements = requirements
		return self._vulnerabilities


class TestMain:
	def test_exceptions(self):
		def make_auditor(cache_lifetime: str) -> FakeAuditor:
			return FakeAuditor(
				cache_lifetime,
				vulnerabilities=[
					make_vulnerability(severity=Severity.CRITICAL),
				],
			)


		namespace = FakeNamespace(SeverityFilterOption(exac=False, value=Severity.CRITICAL), "1d", None)

		with patch.object(main, "get_parser") as get_parser_func:
			get_parser_func.return_value = FakeParser(namespace)

			with patch.object(main, "stdin", new=FakeStream("")):
				with patch.object(main, "Auditor", new=make_auditor):
					with patch.object(main, "Console", new=FakeConsole):
						with patch.object(main, "print_vulnerabilities") as print_vulnerabilities_func:
							print_vulnerabilities_func.return_value = None

							assert main.main() == 1

							namespace.fail_level = Severity.HIGH
							assert main.main() == 1

	def test_normal(self):
		namespace = FakeNamespace(SeverityFilterOption(exac=False, value=Severity.HIGH), "1d", Severity.CRITICAL)
		auditor = FakeAuditor("", vulnerabilities=[])
		console = FakeConsole()


		def make_auditor(cache_lifetime: str) -> FakeAuditor:
			auditor.cache_lifetime = cache_lifetime

			return auditor


		with patch.object(main, "get_parser") as get_parser_func:
			get_parser_func.return_value = FakeParser(namespace)

			with patch.object(main, "stdin", new=FakeStream("TEST_REQ")):
				with patch.object(main, "Auditor", new=make_auditor):
					with patch.object(main, "Console") as console_cls:
						console_cls.return_value = console

						with patch.object(main, "print_vulnerabilities") as print_vulnerabilities_func:
							print_vulnerabilities_func.return_value = None

							assert main.main() == 0
							print_vulnerabilities_func.assert_not_called()
							assert console._last_status_text == "Vulnerabilities are being searched..."
							assert console._last_status_spinner == "boxBounce2"
							assert console._last_print_text == "[green]✨ No vulnerabilities found ✨[/green]"

							get_parser_func.assert_called_once()

							auditor._vulnerabilities.append(make_vulnerability(severity=Severity.HIGH))
							assert main.main() == 0
							print_vulnerabilities_func.assert_called_once()
							assert print_vulnerabilities_func.call_args[0][0] is console
							assert console._last_print_text == "[green]✨ No vulnerabilities leading to failure found ✨[/green]"
