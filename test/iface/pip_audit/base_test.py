from pip_audit_extra.iface.pip_audit.base import AuditPreferences, PIPAudit

from subprocess import CompletedProcess
from unittest.mock import patch

import pytest


class TestAudit(PIPAudit):
	__test__ = False

	def audit(self, preferences: AuditPreferences) -> CompletedProcess:
		return CompletedProcess([], 0)


class TestAuditPreferences:
	def test___init__(self):
		preferences = AuditPreferences()
		assert preferences.timeout == 600

		preferences = AuditPreferences(timeout=300)
		assert preferences.timeout == 300


class TestPIPAudit:
	def test_run(self) -> None:
		audit = TestAudit()

		with patch.object(audit, "audit") as audit_mock:
			with patch.object(audit, "audit_postprocess") as audit_postprocess_mock:
				audit_mock.return_value = "COMPLETED_PROCESS"
				audit_postprocess_mock.return_value = "AUDIT_REPORT"
				preferences = AuditPreferences()
				assert audit.run(preferences) == "AUDIT_REPORT"
				audit_mock.assert_called_once_with(preferences)
				audit_postprocess_mock.assert_called_once_with("COMPLETED_PROCESS")

	def test_audit_postprocess(self) -> None:
		audit = TestAudit()
		completed_process = CompletedProcess([], returncode=100)

		with pytest.raises(RuntimeError, match="pip-audit returned an unexpected code: 100"):
			audit.audit_postprocess(completed_process)

		completed_process = CompletedProcess([], returncode=0, stdout="STDOUT")

		with patch("pip_audit_extra.iface.pip_audit.base.loads") as loads_mock:
			loads_mock.return_value = []

			with pytest.raises(ValueError, match="Deserialized report must be of dict type"):
				audit.audit_postprocess(completed_process)

			loads_mock.assert_called_once_with(completed_process.stdout)

		with patch("pip_audit_extra.iface.pip_audit.base.loads") as loads_mock:
			loads_mock.return_value = {"key1": "value1"}

			with patch("pip_audit_extra.iface.pip_audit.base.AuditReport.from_dict") as audit_report_from_dict_mock:
				audit_report_from_dict_mock.return_value = "AUDIT_REPORT"
				assert audit.audit_postprocess(completed_process) == "AUDIT_REPORT"

				loads_mock.assert_called_once_with(completed_process.stdout)
				audit_report_from_dict_mock.assert_called_once_with({"key1": "value1"})
