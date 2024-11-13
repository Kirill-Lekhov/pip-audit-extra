from pip_audit_extra.severity import Severity
from pip_audit_extra.iface.audit import get_audit_report
from pip_audit_extra.iface.osv import OSVService
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.vulnerability.filter.filter import VulnerabilityFilter
from pip_audit_extra.requirement import clean_requirements

from typing import List
from warnings import warn


def audit(requirements: str, vulnerability_filter: VulnerabilityFilter) -> List[Vulnerability]:
	"""
	Performs project dependencies audit.

	Args:
		requirements: Project dependencies in the `requirements.txt` format.
		vulnerability_filter: Vulnerability filter.

	Returns:
		Vulnerability object list.
	"""
	requirements = clean_requirements(requirements)
	raw_report = get_audit_report(requirements)
	osv_service = OSVService()
	vulns = []

	for dependency in raw_report.get("dependencies", []):
		for vuln in dependency.get("vulns", []):
			if vuln_id := vuln.get("id"):
				try:
					vuln_details = osv_service.get_vulnerability(vuln_id)
					raw_severity = vuln_details.get("database_specific", {}).get("severity")
					vulns.append(
						Vulnerability(
							id=vuln_id,
							package_name=dependency.get("name"),
							package_version=dependency.get("version"),
							fix_versions=vuln.get("fix_versions"),
							severity=None if raw_severity is None else Severity(raw_severity),
						)
					)
				except Exception as err:
					warn(f"Could not get information about {vuln_id} vulnerability. Error: {err}")

	return [*vulnerability_filter.filter(vulns)]
