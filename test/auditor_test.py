from pip_audit_extra.auditor import Auditor, VULN_ID_PREFIX_PYSEC, VULN_ID_PREFIX_GHSA
from pip_audit_extra.iface.osv import OSVService
from pip_audit_extra.vulnerability.cache import Cache
from pip_audit_extra.severity import Severity
from test.factory import make_raw_dependency, make_raw_vulnerability, make_vulnerability_data

from datetime import timedelta
from unittest.mock import patch
from typing import Dict

import pytest


class FakeGetSeverity:
	def __init__(self, severity_map: Dict[str, Severity]) -> None:
		self.severity_map = severity_map

	def __call__(self, raw_vulnerability: dict) -> Severity:
		if severity := self.severity_map.get(raw_vulnerability["id"]):
			return severity

		raise RuntimeError("Vulnerability not found")


class TestAuditor:
	def test___init__(self):
		auditor = Auditor(None)
		assert isinstance(auditor.osv_service, OSVService)
		assert isinstance(auditor.cache, Cache)
		assert auditor.cache.lifetime == timedelta.min

		auditor = Auditor(timedelta(minutes=30))
		assert auditor.cache.lifetime == timedelta(minutes=30)

	def test_audit(self):
		with patch("pip_audit_extra.auditor.clean_requirements", side_effect=lambda x: x) as clean_requirements_func:
			with patch("pip_audit_extra.auditor.get_audit_report") as get_audit_report_func:
				auditor = Auditor(None)

				with patch.object(auditor.cache, "save", side_effect=lambda: None) as cache_save_method:
					get_audit_report_func.return_value = {}
					vulnerabilities = list(auditor.audit("TEST"))

					assert not vulnerabilities
					clean_requirements_func.assert_called_once_with("TEST")
					get_audit_report_func.assert_called_once_with("TEST")
					cache_save_method.assert_called_once()

					get_audit_report_func.return_value = {
						"dependencies": [
							make_raw_dependency("DEP.1", "0.0.0", []),
							make_raw_dependency("DEP.2", "1.0.1", [
								make_raw_vulnerability("", []),
								make_raw_vulnerability("TEST.1"),
								make_raw_vulnerability("TEST.2", ["FIX_VER.1", "FIX_VER.2"]),
								make_raw_vulnerability("TEST.3", ["FIX_VER.3"]),
							]),
						],
					}
					fake_get_severity = FakeGetSeverity({"TEST.1": Severity.LOW, "TEST.2": Severity.CRITICAL})

					with patch.object(auditor, "get_severity", new=fake_get_severity):
						with pytest.warns(
							UserWarning,
							match=(
								r"Could not get information about TEST\.3 vulnerability\. "
								r"Error: Vulnerability not found"
							),
						):
							vulnerabilities = list(auditor.audit(""))

					assert len(vulnerabilities) == 2
					assert vulnerabilities[0].id == "TEST.1"
					assert vulnerabilities[0].package_name == "DEP.2"
					assert vulnerabilities[0].package_version == "1.0.1"
					assert vulnerabilities[0].fix_versions == []
					assert vulnerabilities[0].severity is Severity.LOW
					assert vulnerabilities[1].id == "TEST.2"
					assert vulnerabilities[1].package_name == "DEP.2"
					assert vulnerabilities[1].package_version == "1.0.1"
					assert vulnerabilities[1].fix_versions == ["FIX_VER.1", "FIX_VER.2"]
					assert vulnerabilities[1].severity is Severity.CRITICAL

	def test_get_severity(self):
		vuln = make_raw_vulnerability("ID", ["FIX_VER.1", "FIX_VER.2"])
		auditor = Auditor(None)

		with patch.object(auditor.cache, "get") as cache_get_method:
			cache_get_method.return_value = make_vulnerability_data(severity=None)

			assert auditor.get_severity(vuln) is None
			cache_get_method.assert_called_once_with(vuln["id"])

			cache_get_method.return_value = make_vulnerability_data(severity=Severity.MODERATE.value)
			assert auditor.get_severity(vuln) is Severity.MODERATE

			cache_get_method.return_value = None

			with patch.object(auditor.osv_service, "get_vulnerability") as osv_service_get_vulnerability_method:
				osv_service_get_vulnerability_method.return_value = {}

				with patch.object(auditor.cache, "add") as cache_add_method:
					cache_add_method.return_value = None
					assert auditor.get_severity(vuln) is None
					assert osv_service_get_vulnerability_method.call_count == 1
					cache_add_method.assert_called_once()
					assert cache_add_method.call_args[0][0].id == "ID"
					assert cache_add_method.call_args[0][0].fix_versions == ["FIX_VER.1", "FIX_VER.2"]
					assert cache_add_method.call_args[0][0].severity is None

					osv_service_get_vulnerability_method.reset_mock()
					osv_service_get_vulnerability_method.return_value = {
						"aliases": [VULN_ID_PREFIX_GHSA + "_TEST"],
						"database_specific": {"severity": "CRITICAL"},
					}
					vuln["id"] = VULN_ID_PREFIX_PYSEC + "_TEST"
					assert auditor.get_severity(vuln) is Severity.CRITICAL
					assert cache_add_method.call_count == 2
					assert cache_add_method.call_args[0][0].id == VULN_ID_PREFIX_PYSEC + "_TEST"
					assert cache_add_method.call_args[0][0].fix_versions == ["FIX_VER.1", "FIX_VER.2"]
					assert cache_add_method.call_args[0][0].severity == "CRITICAL"
					assert osv_service_get_vulnerability_method.call_args_list[0][0][0] == VULN_ID_PREFIX_PYSEC + "_TEST"
					assert osv_service_get_vulnerability_method.call_args_list[1][0][0] == VULN_ID_PREFIX_GHSA + "_TEST"
