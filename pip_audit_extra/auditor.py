from pip_audit_extra.severity import Severity
from pip_audit_extra.iface.audit import get_audit_report, get_audit_local_report
from pip_audit_extra.iface.osv import OSVService
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.vulnerability.cache import Cache, VulnerabilityData
from pip_audit_extra.requirement import clean_requirements

from typing import Generator, Final, Optional
from warnings import warn
from datetime import timedelta


VULN_ID_PREFIX_PYSEC: Final[str] = "PYSEC"
VULN_ID_PREFIX_GHSA: Final[str] = "GHSA"


class Auditor:
	def __init__(self, cache_lifetime: Optional[timedelta], local: bool = False) -> None:
		self.osv_service = OSVService()
		self.cache = Cache(lifetime=cache_lifetime)
		self.local = local

	def audit(self, requirements: str) -> Generator[Vulnerability, None, None]:
		"""
		Performs project dependencies audit.

		Args:
			requirements: Project dependencies in the `requirements.txt` format.

		Yields:
			Vulnerability objects.
		"""
		if self.local:
			raw_report = get_audit_local_report()
		else:
			requirements = clean_requirements(requirements)
			raw_report = get_audit_report(requirements)

		for dependency in raw_report.get("dependencies", []):
			for vuln in dependency.get("vulns", []):
				if vuln_id := vuln.get("id"):
					try:
						severity = self.get_severity(vuln)
					except Exception as err:
						warn(f"Could not get information about {vuln_id} vulnerability. Error: {err}")
						continue

					yield Vulnerability(
						id=vuln_id,
						package_name=dependency.get("name"),
						package_version=dependency.get("version"),
						fix_versions=vuln.get("fix_versions"),
						severity=severity,
					)

		self.cache.save()

	def get_severity(self, vuln: dict) -> Optional[Severity]:
		vuln_id = vuln["id"]

		if vuln_data := self.cache.get(vuln_id):
			raw_severity = vuln_data.severity
		else:
			vuln_details = self.osv_service.get_vulnerability(vuln_id)

			if vuln_id.startswith(VULN_ID_PREFIX_PYSEC):
				for alias in vuln_details.get("aliases", []):
					if alias.startswith(VULN_ID_PREFIX_GHSA):
						vuln_details = self.osv_service.get_vulnerability(alias)		# GHSAs have severity
						break

			raw_severity = vuln_details.get("database_specific", {}).get("severity")
			self.cache.add(VulnerabilityData(vuln_id, vuln.get("fix_versions", []), raw_severity))

		if raw_severity:
			return Severity(raw_severity)

		return None
