from pip_audit_extra.severity import Severity
from pip_audit_extra.iface.pip_audit import (
	AuditPreferences, PIPAuditRequirements, AuditPreferencesRequirements, PIPAuditLocal, DependencyVuln,
)
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
	def __init__(self, cache_lifetime: Optional[timedelta], local: bool = False, disable_pip: bool = False) -> None:
		self.osv_service = OSVService()
		self.cache = Cache(lifetime=cache_lifetime)
		self.local = local
		self.disable_pip = disable_pip

	def audit(self, requirements: str) -> Generator[Vulnerability, None, None]:
		"""
		Performs project dependencies audit.

		Args:
			requirements: Project dependencies in the `requirements.txt` format.

		Yields:
			Vulnerability objects.
		"""
		if self.local:
			preferences = AuditPreferences()
			audit_strategy_cls = PIPAuditLocal
		else:
			if not self.disable_pip:
				requirements = clean_requirements(requirements)

			preferences = AuditPreferencesRequirements(requirements, disable_pip=self.disable_pip)
			audit_strategy_cls = PIPAuditRequirements

		pip_audit = audit_strategy_cls()
		audit_report = pip_audit.run(preferences)

		for dependency in audit_report.dependencies:
			for vuln in dependency.vulns:
				try:
					severity = self.get_severity(vuln)
				except Exception as err:
					warn(f"Could not get information about {vuln.id} vulnerability. Error: {err}")
					continue

				yield Vulnerability(
					id=vuln.id,
					package_name=dependency.name,
					package_version=dependency.version,
					fix_versions=vuln.fix_versions,
					severity=severity,
				)

		self.cache.save()

	def get_severity(self, vuln: DependencyVuln) -> Optional[Severity]:
		if vuln_data := self.cache.get(vuln.id):
			raw_severity = vuln_data.severity
		else:
			vuln_details = self.osv_service.get_vulnerability(vuln.id)

			if vuln.id.startswith(VULN_ID_PREFIX_PYSEC):
				for alias in vuln_details.get("aliases", []):
					if alias.startswith(VULN_ID_PREFIX_GHSA):
						vuln_details = self.osv_service.get_vulnerability(alias)		# GHSAs have severity
						break

			raw_severity = vuln_details.get("database_specific", {}).get("severity")
			self.cache.add(VulnerabilityData(vuln.id, vuln.fix_versions, raw_severity))

		if raw_severity:
			return Severity(raw_severity)

		return None
