from pip_audit_extra.cli import get_parser
from pip_audit_extra.core import audit
from pip_audit_extra.vulnerability.print import print_vulnerabilities
from pip_audit_extra.vulnerability.filter.filter import VulnerabilityFilter

from sys import exit, argv, stdin

from rich.console import Console


def main() -> int:
	parser = get_parser()
	namespace = parser.parse_args(argv[1:])
	vulnerability_filter = VulnerabilityFilter(severity=namespace.severity)
	requirements = stdin.read()
	console = Console()

	with console.status("Vulnerabilities are being searched...", spinner="boxBounce2"):
		vulns = audit(requirements, vulnerability_filter)

		if vulns:
			print_vulnerabilities(console, vulns)
			return 1

	console.print("[green]✨ No vulnerabilities found ✨[/green]")

	return 0


if __name__ == "__main__":
	exit(main())
