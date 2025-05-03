from pip_audit_extra.__main__ import main
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.vulnerability.filter.severity import SeverityFilterOption
from pip_audit_extra.severity import Severity

from unittest.mock import patch, Mock
from datetime import timedelta

from rich.console import Console


class TestMain:
	def test_without_vulnerabilities(self):
		with patch("pip_audit_extra.__main__.get_parser") as get_parser_mock:
			with patch("pip_audit_extra.__main__.argv", ["test_script.py", "arg1", "arg2"]):
				get_parser_mock.return_value = Mock()
				get_parser_mock.return_value.parse_args = Mock()
				get_parser_mock.return_value.parse_args.return_value = Mock()
				get_parser_mock.return_value.parse_args.return_value.severity = None
				get_parser_mock.return_value.parse_args.return_value.local = False
				get_parser_mock.return_value.parse_args.return_value.cache_lifetime = timedelta(hours=10)
				get_parser_mock.return_value.parse_args.return_value.disable_pip = False
				get_parser_mock.return_value.parse_args.return_value.fail_level = None

				with patch("pip_audit_extra.__main__.stdin") as stdin_mock:
					stdin_mock.read = Mock()
					stdin_mock.read.return_value = "REQUIREMENTS"

					with patch("pip_audit_extra.__main__.Auditor") as AuditorMock:
						AuditorMock.return_value = Mock()
						AuditorMock.return_value.audit = Mock()
						AuditorMock.return_value.audit.return_value = []

						with patch("pip_audit_extra.__main__.Printer") as PrinterMock:
							PrinterMock.return_value = Mock()
							PrinterMock.return_value.__enter__ = Mock()
							PrinterMock.return_value.__enter__.return_value = PrinterMock.return_value
							PrinterMock.return_value.__exit__ = Mock()
							PrinterMock.return_value.handle_collecting_start = "handle_collecting_start"
							PrinterMock.return_value.handle_collecting_end = "handle_collecting_end"
							PrinterMock.return_value.handle_checking_start = "handle_checking_start"
							PrinterMock.return_value.handle_checking_step = "handle_checking_step"
							PrinterMock.return_value.handle_checking_end = "handle_checking_end"
							PrinterMock.return_value.handle_vulns_inspecting_start = "handle_vulns_inspecting_start"
							PrinterMock.return_value.handle_vulns_inspecting_step = "handle_vulns_inspecting_step"
							PrinterMock.return_value.handle_vulns_inspecting_end = "handle_vulns_inspecting_end"

							with patch("pip_audit_extra.__main__.partial") as partial_mock:
								assert main() == 0
								get_parser_mock.assert_called_once()
								get_parser_mock.return_value.parse_args.assert_called_once_with(["arg1", "arg2"])
								stdin_mock.read.assert_called_once()
								AuditorMock.assert_called_once_with(
									cache_lifetime=timedelta(hours=10),
									local=False,
									disable_pip=False,
								)
								AuditorMock.return_value.audit.assert_called_once_with("REQUIREMENTS")
								assert AuditorMock.return_value.on_collecting_start == PrinterMock.return_value.handle_collecting_start
								assert AuditorMock.return_value.on_collecting_end == PrinterMock.return_value.handle_collecting_end
								assert AuditorMock.return_value.on_checking_start == PrinterMock.return_value.handle_checking_start
								assert AuditorMock.return_value.on_checking_step == PrinterMock.return_value.handle_checking_step
								assert AuditorMock.return_value.on_checking_end == PrinterMock.return_value.handle_checking_end
								assert AuditorMock.return_value.on_inspecting_start == PrinterMock.return_value.handle_vulns_inspecting_start
								assert AuditorMock.return_value.on_inspecting_step == PrinterMock.return_value.handle_vulns_inspecting_step
								assert AuditorMock.return_value.on_inspecting_end == PrinterMock.return_value.handle_vulns_inspecting_end
								PrinterMock.assert_called_once()
								PrinterMock.return_value.__enter__.assert_called_once()
								PrinterMock.return_value.__exit__.assert_called_once()
								assert isinstance(PrinterMock.call_args[0][0], Console)
								partial_mock.assert_called_once_with(
									PrinterMock.call_args[0][0].print,
									"[green]✨ No vulnerabilities found ✨[/green]",
								)

	def test_without_fail(self):
		with patch("pip_audit_extra.__main__.get_parser") as get_parser_mock:
			with patch("pip_audit_extra.__main__.argv", ["test_script.py", "arg1", "arg2"]):
				get_parser_mock.return_value = Mock()
				get_parser_mock.return_value.parse_args = Mock()
				get_parser_mock.return_value.parse_args.return_value = Mock()
				get_parser_mock.return_value.parse_args.return_value.severity = SeverityFilterOption(
					False,
					Severity.HIGH,
				)
				get_parser_mock.return_value.parse_args.return_value.local = False
				get_parser_mock.return_value.parse_args.return_value.cache_lifetime = timedelta(hours=10)
				get_parser_mock.return_value.parse_args.return_value.disable_pip = False
				get_parser_mock.return_value.parse_args.return_value.fail_level = Severity.CRITICAL

				with patch("pip_audit_extra.__main__.stdin") as stdin_mock:
					stdin_mock.read = Mock()
					stdin_mock.read.return_value = "REQUIREMENTS"

					with patch("pip_audit_extra.__main__.Auditor") as AuditorMock:
						AuditorMock.return_value = Mock()
						AuditorMock.return_value.audit = Mock()
						AuditorMock.return_value.audit.return_value = [
							Vulnerability("VULN_ID", "VULN_PACKAGE_NAME", "VULN_PACKAGE_VERSION", [], Severity.LOW),
						]

						with patch("pip_audit_extra.__main__.Printer") as PrinterMock:
							PrinterMock.return_value = Mock()
							PrinterMock.return_value.__enter__ = Mock()
							PrinterMock.return_value.__enter__.return_value = PrinterMock.return_value
							PrinterMock.return_value.__exit__ = Mock()

							with patch("pip_audit_extra.__main__.partial") as partial_mock:
								with patch("pip_audit_extra.__main__.SeverityChecker") as SeverityCheckerMock:
									SeverityCheckerMock.return_value = Mock()
									SeverityCheckerMock.return_value.check = Mock()
									SeverityCheckerMock.return_value.check.return_value = False

									assert main() == 0
									get_parser_mock.assert_called_once()
									get_parser_mock.return_value.parse_args.assert_called_once_with(["arg1", "arg2"])
									stdin_mock.read.assert_called_once()
									AuditorMock.assert_called_once_with(
										cache_lifetime=timedelta(hours=10),
										local=False,
										disable_pip=False,
									)
									AuditorMock.return_value.audit.assert_called_once_with("REQUIREMENTS")
									SeverityCheckerMock.assert_called_once_with(Severity.CRITICAL)
									SeverityCheckerMock.return_value.check.assert_called_once()
									PrinterMock.assert_called_once()
									PrinterMock.return_value.__enter__.assert_called_once()
									PrinterMock.return_value.__exit__.assert_called_once()
									assert isinstance(PrinterMock.call_args[0][0], Console)
									partial_mock.assert_called_once_with(
										PrinterMock.call_args[0][0].print,
										"[green]✨ No vulnerabilities leading to failure found ✨[/green]",
									)

	def test_with_fail__without_table(self):
		with patch("pip_audit_extra.__main__.get_parser") as get_parser_mock:
			with patch("pip_audit_extra.__main__.argv", ["test_script.py", "arg1", "arg2"]):
				get_parser_mock.return_value = Mock()
				get_parser_mock.return_value.parse_args = Mock()
				get_parser_mock.return_value.parse_args.return_value = Mock()
				get_parser_mock.return_value.parse_args.return_value.severity = SeverityFilterOption(
					False,
					Severity.HIGH,
				)
				get_parser_mock.return_value.parse_args.return_value.local = True
				get_parser_mock.return_value.parse_args.return_value.cache_lifetime = timedelta(hours=10)
				get_parser_mock.return_value.parse_args.return_value.disable_pip = False
				get_parser_mock.return_value.parse_args.return_value.fail_level = None

				with patch("pip_audit_extra.__main__.Auditor") as AuditorMock:
					AuditorMock.return_value = Mock()
					AuditorMock.return_value.audit = Mock()
					AuditorMock.return_value.audit.return_value = [
						Vulnerability("VULN_ID", "VULN_PACKAGE_NAME", "VULN_PACKAGE_VERSION", [], Severity.LOW),
					]

					with patch("pip_audit_extra.__main__.Printer") as PrinterMock:
						PrinterMock.return_value = Mock()
						PrinterMock.return_value.__enter__ = Mock()
						PrinterMock.return_value.__enter__.return_value = PrinterMock.return_value
						PrinterMock.return_value.__exit__ = Mock()

						with patch("pip_audit_extra.__main__.partial") as partial_mock:
							with patch("pip_audit_extra.__main__.SeverityChecker") as SeverityCheckerMock:
								SeverityCheckerMock.return_value = Mock()
								SeverityCheckerMock.return_value.check = Mock()
								SeverityCheckerMock.return_value.check.return_value = False

								assert main() == 1
								get_parser_mock.assert_called_once()
								get_parser_mock.return_value.parse_args.assert_called_once_with(["arg1", "arg2"])
								AuditorMock.assert_called_once_with(
									cache_lifetime=timedelta(hours=10),
									local=True,
									disable_pip=False,
								)
								AuditorMock.return_value.audit.assert_called_once_with("")
								SeverityCheckerMock.assert_not_called()
								PrinterMock.assert_called_once()
								PrinterMock.return_value.__enter__.assert_called_once()
								PrinterMock.return_value.__exit__.assert_called_once()
								assert isinstance(PrinterMock.call_args[0][0], Console)
								partial_mock.assert_not_called()

	def test_with_fail__with_table(self):
		with patch("pip_audit_extra.__main__.get_parser") as get_parser_mock:
			with patch("pip_audit_extra.__main__.argv", ["test_script.py", "arg1", "arg2"]):
				get_parser_mock.return_value = Mock()
				get_parser_mock.return_value.parse_args = Mock()
				get_parser_mock.return_value.parse_args.return_value = Mock()
				get_parser_mock.return_value.parse_args.return_value.severity = SeverityFilterOption(
					False,
					Severity.LOW,
				)
				get_parser_mock.return_value.parse_args.return_value.local = True
				get_parser_mock.return_value.parse_args.return_value.cache_lifetime = timedelta(hours=10)
				get_parser_mock.return_value.parse_args.return_value.disable_pip = False
				get_parser_mock.return_value.parse_args.return_value.fail_level = Severity.LOW

				with patch("pip_audit_extra.__main__.Auditor") as AuditorMock:
					AuditorMock.return_value = Mock()
					AuditorMock.return_value.audit = Mock()
					AuditorMock.return_value.audit.return_value = [
						Vulnerability("VULN_ID", "VULN_PACKAGE_NAME", "VULN_PACKAGE_VERSION", [], Severity.LOW),
					]

					with patch("pip_audit_extra.__main__.Printer") as PrinterMock:
						PrinterMock.return_value = Mock()
						PrinterMock.return_value.__enter__ = Mock()
						PrinterMock.return_value.__enter__.return_value = PrinterMock.return_value
						PrinterMock.return_value.__exit__ = Mock()

						with patch("pip_audit_extra.__main__.partial") as partial_mock:
							with patch("pip_audit_extra.__main__.SeverityChecker") as SeverityCheckerMock:
								SeverityCheckerMock.return_value = Mock()
								SeverityCheckerMock.return_value.check = Mock()
								SeverityCheckerMock.return_value.check.return_value = True

								assert main() == 1
								get_parser_mock.assert_called_once()
								get_parser_mock.return_value.parse_args.assert_called_once_with(["arg1", "arg2"])
								AuditorMock.assert_called_once_with(
									cache_lifetime=timedelta(hours=10),
									local=True,
									disable_pip=False,
								)
								AuditorMock.return_value.audit.assert_called_once_with("")
								SeverityCheckerMock.assert_called_once_with(Severity.LOW)
								SeverityCheckerMock.return_value.check.assert_called_once()
								PrinterMock.assert_called_once()
								PrinterMock.return_value.__enter__.assert_called_once()
								PrinterMock.return_value.__exit__.assert_called_once()
								assert isinstance(PrinterMock.call_args[0][0], Console)
								partial_mock.assert_called_once()
