from pip_audit_extra.iface.pip_audit.local import PIPAuditLocal
from pip_audit_extra.iface.pip_audit.base import AuditPreferences

from unittest.mock import patch


class TestPIPAuditLocal:
	def test_audit(self):
		audit = PIPAuditLocal()
		preferences = AuditPreferences(timeout=300)

		with patch("pip_audit_extra.iface.pip_audit.local.run") as run_mock:
			run_mock.return_value = "COMPLETED_PROCESS"
			assert audit.audit(preferences) == "COMPLETED_PROCESS"
			run_mock.assert_called_once_with(
				["pip-audit", "-f", "json", "--progress-spinner", "off", "-l"],
				capture_output=True,
				encoding="utf-8",
				timeout=300,
			)
