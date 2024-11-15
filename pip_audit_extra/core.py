from pip_audit_extra.severity import Severity
from pip_audit_extra.iface.audit import get_audit_report
from pip_audit_extra.iface.osv import OSVService
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.requirement import clean_requirements

from typing import Generator, Final
from warnings import warn


VULN_ID_PREFIX_PYSEC: Final[str] = "PYSEC"
VULN_ID_PREFIX_GHSA: Final[str] = "GHSA"


def audit(requirements: str) -> Generator[Vulnerability, None, None]:
	"""
	Performs project dependencies audit.

	Args:
		requirements: Project dependencies in the `requirements.txt` format.

	Yields:
		Vulnerability objects.
	"""
	requirements = clean_requirements(requirements)
	raw_report = get_audit_report(requirements)
	osv_service = OSVService()

	for dependency in raw_report.get("dependencies", []):
		for vuln in dependency.get("vulns", []):
			if vuln_id := vuln.get("id"):
				try:
					vuln_details = osv_service.get_vulnerability(vuln_id)

					if vuln_id.startswith(VULN_ID_PREFIX_PYSEC):
						for alias in vuln_details.get("aliases", []):
							if alias.startswith(VULN_ID_PREFIX_GHSA):
								vuln_details = osv_service.get_vulnerability(alias)		# GHSAs have severity
								break

					raw_severity = vuln_details.get("database_specific", {}).get("severity")

					yield Vulnerability(
						id=vuln_id,
						package_name=dependency.get("name"),
						package_version=dependency.get("version"),
						fix_versions=vuln.get("fix_versions"),
						severity=None if raw_severity is None else Severity(raw_severity),
					)

				except Exception as err:
					warn(f"Could not get information about {vuln_id} vulnerability. Error: {err}")
