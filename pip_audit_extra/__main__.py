from pip_audit_extra.cli import get_parser
from pip_audit_extra.core import audit
from pip_audit_extra.vulnerability import print_vulnerabilities

from sys import exit, argv, stdin

from rich.console import Console


def main() -> int:
	parser = get_parser()
	namespace = parser.parse_args(argv[1:])
	requirements = stdin.read()
	console = Console()

	with console.status("Vulnerabilities are being searched...", spinner="boxBounce2"):
		vulns = audit(requirements, namespace.severity)

		if vulns:
			print_vulnerabilities(console, vulns)
			return 1

	if namespace.severity is None:
		console.print("[green]No vulnerabilities found✨[/green]")
	else:
		console.print(f"[green]No {namespace.severity.value} vulnerabilities found✨[/green]")

	return 0


if __name__ == "__main__":
	exit(main())
