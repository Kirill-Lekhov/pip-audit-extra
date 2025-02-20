from pip_audit_extra.cli import get_parser
from pip_audit_extra.auditor import Auditor
from pip_audit_extra.vulnerability.print import print_vulnerabilities
from pip_audit_extra.vulnerability.filter.filter import VulnerabilityFilter
from pip_audit_extra.vulnerability.filter.severity import SeverityChecker

from sys import exit, argv, stdin

from rich.console import Console


def main() -> int:
	parser = get_parser()
	namespace = parser.parse_args(argv[1:])
	vulnerability_filter = VulnerabilityFilter(severity=namespace.severity)

	if namespace.local:
		requirements = ""
	else:
		requirements = stdin.read()

	console = Console()
	auditor = Auditor(cache_lifetime=namespace.cache_lifetime, local=namespace.local)

	with console.status("Vulnerabilities are being searched...", spinner="boxBounce2"):
		vulns = [*auditor.audit(requirements)]

		if filtered_vulns := [*vulnerability_filter.filter(vulns)]:
			print_vulnerabilities(console, filtered_vulns)

		if vulns and namespace.fail_level is None:
			return 1

		severity_checker = SeverityChecker(namespace.fail_level)

		if any(map(severity_checker.check, vulns)):
			return 1

	if vulns:
		console.print("[green]✨ No vulnerabilities leading to failure found ✨[/green]")
	else:
		console.print("[green]✨ No vulnerabilities found ✨[/green]")

	return 0


if __name__ == "__main__":
	exit(main())
