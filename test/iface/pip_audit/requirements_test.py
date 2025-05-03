from pip_audit_extra.iface.pip_audit.requirements import AuditPreferencesRequirements, PIPAuditRequirements

from unittest.mock import patch, Mock

import pytest


class TestAuditPreferencesRequirements:
	def test___init__(self):
		preferences = AuditPreferencesRequirements(requirements="REQUIREMENTS")
		assert preferences.requirements == "REQUIREMENTS"
		assert not preferences.disable_pip
		assert preferences.timeout == 600

		preferences = AuditPreferencesRequirements(requirements="REQUIREMENTS", disable_pip=True, timeout=300)
		assert preferences.requirements == "REQUIREMENTS"
		assert preferences.disable_pip
		assert preferences.timeout == 300


class TestPIPAuditRequirements:
	def test_audit(self):
		audit = PIPAuditRequirements()
		preferences = AuditPreferencesRequirements(requirements="REQUIREMENTS", disable_pip=False, timeout=300)

		with patch("pip_audit_extra.iface.pip_audit.requirements.NamedTemporaryFile") as NamedTemporaryFileMock:
			NamedTemporaryFileMock.return_value = Mock()
			NamedTemporaryFileMock.return_value.name = "TMPFILE_NAME"
			NamedTemporaryFileMock.return_value.write = Mock()
			NamedTemporaryFileMock.return_value.close = Mock()

			with patch("pip_audit_extra.iface.pip_audit.requirements.run") as run_mock:
				run_mock.side_effect = RuntimeError("TEST")

				with patch("pip_audit_extra.iface.pip_audit.requirements.remove") as remove_mock:
					with pytest.raises(RuntimeError, match="TEST"):
						audit.audit(preferences)

					NamedTemporaryFileMock.assert_called_once_with("w", delete=False)
					NamedTemporaryFileMock.return_value.write.assert_called_once_with("REQUIREMENTS")
					NamedTemporaryFileMock.return_value.close.assert_called_once()
					remove_mock.assert_called_once_with("TMPFILE_NAME")

				run_mock.reset_mock()
				run_mock.side_effect = None
				run_mock.return_value = "COMPLETED_PROCESS"

				with patch("pip_audit_extra.iface.pip_audit.requirements.remove") as remove_mock:
					assert audit.audit(preferences) == "COMPLETED_PROCESS"
					run_mock.assert_called_once_with(
						["pip-audit", "-f", "json", "--progress-spinner", "off", "-r", "TMPFILE_NAME"],
						capture_output=True,
						encoding="utf-8",
						timeout=300,
					)
					remove_mock.assert_called_once_with("TMPFILE_NAME")

				run_mock.reset_mock()
				preferences.disable_pip = True

				with patch("pip_audit_extra.iface.pip_audit.requirements.remove") as remove_mock:
					assert audit.audit(preferences) == "COMPLETED_PROCESS"
					run_mock.assert_called_once_with(
						["pip-audit", "-f", "json", "--progress-spinner", "off", "-r", "TMPFILE_NAME", "--disable-pip"],
						capture_output=True,
						encoding="utf-8",
						timeout=300,
					)
