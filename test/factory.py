from pip_audit_extra.vulnerability.cache import VulnerabilityData
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.severity import Severity

from typing import List, Optional


def make_raw_dependency(name: str, version: str, vulns: Optional[List[dict]] = None) -> dict:
	return {
		"name": name,
		"version": version,
		"vulns": vulns or [],
	}


def make_raw_vulnerability(vuln_id: str, fix_versions: Optional[List[str]] = None) -> dict:
	return {
		"id": vuln_id,
		"fix_versions": fix_versions or [],
	}


def make_vulnerability_data(
	vuln_id: str = "ID",
	fix_versions: Optional[List[str]] = None,
	severity: Optional[str] = None,
) -> VulnerabilityData:
	return VulnerabilityData(vuln_id, fix_versions or [], severity)


def make_vulnerability(
	vuln_id: str = "ID",
	package_name: str = "PACKAGE_NAME",
	package_version: str = "PACKAGE_VERSION",
	fix_versions: Optional[List[str]] = None,
	severity: Optional[Severity] = None,
) -> Vulnerability:
	return Vulnerability(
		vuln_id,
		package_name,
		package_version,
		fix_versions or [],
		severity,
	)
