from pip_audit_extra.auditor import Auditor, VULN_ID_PREFIX_PYSEC, VULN_ID_PREFIX_GHSA
from pip_audit_extra.severity import Severity
from pip_audit_extra.vulnerability.dataclass import Vulnerability
from pip_audit_extra.vulnerability.cache.cache import Cache
from pip_audit_extra.vulnerability.cache.type import VulnerabilityData
from pip_audit_extra.iface.osv.service import OSVService
from pip_audit_extra.iface.pip_audit.dataclass import Dependency, DependencyVuln

from unittest.mock import patch, Mock
from datetime import timedelta

import pytest


class TestAuditor:
	def test___init__(self):
		auditor = Auditor(None)
		assert isinstance(auditor.osv_service, OSVService)
		assert isinstance(auditor.cache, Cache)
		assert auditor.cache.lifetime == timedelta.min
		assert not auditor.local
		assert not auditor.disable_pip
		assert auditor.on_collecting_start is auditor.noop
		assert auditor.on_collecting_end is auditor.noop
		assert auditor.on_checking_start is auditor.noop
		assert auditor.on_checking_step is auditor.noop
		assert auditor.on_checking_end is auditor.noop
		assert auditor.on_inspecting_start is auditor.noop
		assert auditor.on_inspecting_step is auditor.noop
		assert auditor.on_inspecting_end is auditor.noop


		def fake_handler(*args, **kwargs) -> None:
			pass


		auditor = Auditor(
			timedelta(hours=10),
			local=True,
			disable_pip=True,
			on_collecting_start=fake_handler,
			on_collecting_end=fake_handler,
			on_checking_start=fake_handler,
			on_checking_step=fake_handler,
			on_checking_end=fake_handler,
			on_inspecting_start=fake_handler,
			on_inspecting_step=fake_handler,
			on_inspecting_end=fake_handler,
		)
		assert auditor.cache.lifetime == timedelta(hours=10)
		assert auditor.local
		assert auditor.disable_pip
		assert auditor.on_collecting_start is fake_handler
		assert auditor.on_collecting_end is fake_handler
		assert auditor.on_checking_start is fake_handler
		assert auditor.on_checking_step is fake_handler
		assert auditor.on_checking_end is fake_handler
		assert auditor.on_inspecting_start is fake_handler
		assert auditor.on_inspecting_step is fake_handler
		assert auditor.on_inspecting_end is fake_handler

	def test_noop(self):
		assert Auditor.noop() is None

	def test_audit(self):
		with patch("pip_audit_extra.auditor.Cache") as CacheMock:
			CacheMock.return_value = Mock()
			CacheMock.return_value.save = Mock()
			auditor = Auditor(None, local=True, disable_pip=False)

		with patch("pip_audit_extra.auditor.PIPAuditLocal") as PIPAuditLocalMock:
			PIPAuditLocalMock.return_value = Mock()
			PIPAuditLocalMock.return_value.run = Mock()
			PIPAuditLocalMock.return_value.run.return_value = Mock()
			PIPAuditLocalMock.return_value.run.return_value.dependencies = []

			with patch.object(auditor, "on_collecting_start") as on_collecting_start_mock:
				with patch.object(auditor, "on_collecting_end") as on_collecting_end_mock:
					with patch.object(auditor, "on_checking_start") as on_checking_start_mock:
						with patch.object(auditor, "on_checking_end") as on_checking_end_mock:
							with patch.object(auditor.cache, "save") as cache_save_mock:
								assert list(auditor.audit("REQUIREMENTS")) == []

								PIPAuditLocalMock.assert_called_once()
								on_collecting_start_mock.assert_called_once()
								PIPAuditLocalMock.return_value.run.assert_called_once()
								on_collecting_end_mock.assert_called_once()
								on_checking_start_mock.assert_called_once_with(0)
								on_checking_end_mock.assert_called_once()
								cache_save_mock.assert_called_once()

		auditor.local = False

		with patch("pip_audit_extra.auditor.PIPAuditRequirements") as PIPAuditRequirementsMock:
			PIPAuditRequirementsMock.return_value = Mock()
			PIPAuditRequirementsMock.return_value.run = Mock()
			PIPAuditRequirementsMock.return_value.run.return_value = Mock()
			PIPAuditRequirementsMock.return_value.run.return_value.dependencies = [
				Dependency(
					name="DEP_1_NAME",
					version="DEP_1_VERSION",
					vulns=[
						DependencyVuln(
							id="DEP_1_VULN_1_ID",
							aliases=["DEP_1_VULN_1_ALIAS_1", "DEP_1_VULN_1_ALIAS_2"],
							description="DEP_1_VULN_1_DESCRIPTION",
							fix_versions=["DEP_1_VULN_1_FIX_VERSION_1", "DEP_1_VULN_1_FIX_VERSION_2"],
						),
						DependencyVuln(
							id="DEP_1_VULN_2_ID",
							aliases=["DEP_1_VULN_2_ALIAS_1", "DEP_1_VULN_2_ALIAS_2"],
							description="DEP_1_VULN_2_DESCRIPTION",
							fix_versions=["DEP_1_VULN_2_FIX_VERSION_1", "DEP_1_VULN_2_FIX_VERSION_2"],
						),
					],
				),
				Dependency(
					name="DEP_2_NAME",
					version="DEP_2_VERSION",
					vulns=[
						DependencyVuln(
							id="DEP_2_VULN_1_ID",
							aliases=["DEP_2_VULN_1_ALIAS_2", "DEP_2_VULN_1_ALIAS_2"],
							description="DEP_2_VULN_1_DESCRIPTION",
							fix_versions=["DEP_2_VULN_1_FIX_VERSION_2", "DEP_2_VULN_1_FIX_VERSION_2"],
						),
					],
				),
			]


			def get_severity_side_effect(vuln: DependencyVuln) -> Severity:
				if vuln.id == "DEP_2_VULN_1_ID":
					raise RuntimeError("TEST")

				return Severity.HIGH


			with patch("pip_audit_extra.auditor.clean_requirements") as clean_requirements_mock:
				clean_requirements_mock.return_value = "CLEANED_REQUIREMENTS"

				with patch.object(auditor, "on_checking_start") as on_checking_start_mock:
					with patch.object(auditor, "on_checking_step") as on_checking_step_mock:
						with patch.object(auditor, "on_inspecting_start") as on_inspecting_start_mock:
							with patch.object(auditor, "on_inspecting_step") as on_inspecting_step_mock:
								with patch.object(auditor, "on_inspecting_end") as on_inspecting_end_mock:
									with patch.object(auditor, "get_severity") as get_severity_mock:
										get_severity_mock.side_effect = get_severity_side_effect

										with pytest.warns(
											UserWarning,
											match="Could not get information about DEP_2_VULN_1_ID vulnerability. Error: TEST",
										):
											vulnerabilities = list(auditor.audit("REQUIREMENTS"))

										assert len(vulnerabilities) == 2
										assert isinstance(vulnerabilities[0], Vulnerability)
										assert vulnerabilities[0].id == "DEP_1_VULN_1_ID"
										assert vulnerabilities[0].package_name == "DEP_1_NAME"
										assert vulnerabilities[0].package_version == "DEP_1_VERSION"
										assert vulnerabilities[0].fix_versions == [
											"DEP_1_VULN_1_FIX_VERSION_1",
											"DEP_1_VULN_1_FIX_VERSION_2",
										]
										assert vulnerabilities[0].severity == Severity.HIGH
										assert vulnerabilities[1].id == "DEP_1_VULN_2_ID"
										assert vulnerabilities[1].package_name == "DEP_1_NAME"
										assert vulnerabilities[1].package_version == "DEP_1_VERSION"
										assert vulnerabilities[1].fix_versions == [
											"DEP_1_VULN_2_FIX_VERSION_1",
											"DEP_1_VULN_2_FIX_VERSION_2",
										]
										assert vulnerabilities[1].severity == Severity.HIGH
										clean_requirements_mock.assert_called_once_with("REQUIREMENTS")
										PIPAuditRequirementsMock.assert_called_once()
										PIPAuditRequirementsMock.return_value.run.assert_called_once()
										assert PIPAuditRequirementsMock.return_value.run.call_args[0][0].requirements == "CLEANED_REQUIREMENTS"
										assert not PIPAuditRequirementsMock.return_value.run.call_args[0][0].disable_pip
										on_checking_start_mock.assert_called_once_with(2)
										on_checking_step_mock.assert_called()
										assert on_checking_step_mock.call_count == 2
										on_inspecting_start_mock.assert_called()
										assert on_inspecting_start_mock.call_count == 2
										assert on_inspecting_start_mock.call_args_list[0][0][0] == 2
										assert on_inspecting_start_mock.call_args_list[1][0][0] == 1
										on_inspecting_step_mock.assert_called()
										assert on_inspecting_step_mock.call_count == 3
										on_inspecting_end_mock.assert_called()
										assert on_inspecting_start_mock.call_count == 2

	def test_get_severity(self):
		auditor = Auditor(None)
		dep_vuln = DependencyVuln(id="VULN_ID", aliases=[], description="", fix_versions=["FIX_VERSION_1"])

		with patch.object(auditor.cache, "get") as cache_get_mock:
			cache_get_mock.return_value = VulnerabilityData("VULN_ID", ["FIX_VERSION_1"], Severity.LOW.value)

			assert auditor.get_severity(dep_vuln) is Severity.LOW
			cache_get_mock.assert_called_once_with("VULN_ID")

			cache_get_mock.return_value = VulnerabilityData("VULN_ID", ["FIX_VERSION_1"], None)
			assert auditor.get_severity(dep_vuln) is None

			cache_get_mock.return_value = None

			with patch.object(auditor.cache, "add") as cache_add_mock:
				with patch.object(auditor.osv_service, "get_vulnerability") as osv_service_get_vulnerability_mock:
					osv_service_get_vulnerability_mock.return_value = {
						"database_specific": {"severity": Severity.LOW.value},
					}

					assert auditor.get_severity(dep_vuln) is Severity.LOW
					osv_service_get_vulnerability_mock.assert_called_once_with("VULN_ID")
					cache_add_mock.assert_called_once()
					assert isinstance(cache_add_mock.call_args[0][0], VulnerabilityData)
					assert cache_add_mock.call_args[0][0].id == "VULN_ID"
					assert cache_add_mock.call_args[0][0].fix_versions == ["FIX_VERSION_1"]
					assert cache_add_mock.call_args[0][0].severity == Severity.LOW.value

					osv_service_get_vulnerability_mock.return_value = {}
					osv_service_get_vulnerability_mock.side_effect = [{}]
					dep_vuln.id = VULN_ID_PREFIX_PYSEC + "_VULN_ID"
					assert auditor.get_severity(dep_vuln) is None

					cache_add_mock.reset_mock()
					osv_service_get_vulnerability_mock.reset_mock()
					osv_service_get_vulnerability_mock.return_value = {}
					osv_service_get_vulnerability_mock.side_effect = [
						{"aliases": ["VULN_ID", VULN_ID_PREFIX_GHSA + "_VULN_ID"]},
						{"database_specific": {"severity": Severity.HIGH.value}},
					]
					dep_vuln.id = VULN_ID_PREFIX_PYSEC + "_VULN_ID"
					assert auditor.get_severity(dep_vuln) is Severity.HIGH
					osv_service_get_vulnerability_mock.assert_called()
					assert osv_service_get_vulnerability_mock.call_count == 2
