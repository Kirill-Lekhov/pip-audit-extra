from pip_audit_extra.iface.audit import get_audit_report

from unittest.mock import patch
from json import loads

import pytest


class FakeNamedTemporaryFile:
	def __init__(self, mode: str = "r", delete: bool = True, *, name: str = "testfile") -> None:
		self.mode = mode
		self.delete = delete
		self.name = name

		self._write_was_called = False
		self._write_content = None
		self._close_was_called = False

	def write(self, content: str) -> None:
		self._write_content = content
		self._write_was_called = True

	def close(self) -> None:
		self._close_was_called = True


class FakeCompletedProcess:
	def __init__(self, returncode: int = 0, stdout: str = "") -> None:
		self.returncode = returncode
		self.stdout = stdout


class TestGetAuditReport:
	def test__tmpfile_remove_on_error(self):
		with patch("pip_audit_extra.iface.audit.NamedTemporaryFile", new=FakeNamedTemporaryFile):
			with patch("pip_audit_extra.iface.audit.run") as run_func:
				run_func.side_effect = Exception("TEST")

				with patch("pip_audit_extra.iface.audit.remove") as remove_func:
					remove_func.return_value = None

					with pytest.raises(Exception, match="TEST"):
						get_audit_report("")

					remove_func.assert_called_with("testfile")

	def test__exceptions(self):
		with patch("pip_audit_extra.iface.audit.NamedTemporaryFile", new=FakeNamedTemporaryFile):
			with patch("pip_audit_extra.iface.audit.run") as run_func:
				run_func.return_value = FakeCompletedProcess(2)

				with patch("pip_audit_extra.iface.audit.remove", return_value=None):
					with pytest.raises(RuntimeError, match="pip-audit returned an unexpected code: 2"):
						get_audit_report("")

				run_func.return_value = FakeCompletedProcess(0, "[]")

				with patch("pip_audit_extra.iface.audit.remove", return_value=None):
					with pytest.raises(ValueError, match="Deserialized report must be of dict type"):
						get_audit_report("")

	def test__normal(self):
		tmpfile = FakeNamedTemporaryFile()

		def build_tmpfile(mode: str = "r", delete: bool = True):
			tmpfile.mode = mode
			tmpfile.delete = delete

			return tmpfile

		with patch("pip_audit_extra.iface.audit.NamedTemporaryFile", new=build_tmpfile):
			with patch("pip_audit_extra.iface.audit.run") as run_func:
				run_func.return_value = FakeCompletedProcess(0, "{ \"text\": \"Hello World\" }")

				with patch("pip_audit_extra.iface.audit.remove", return_value=None):
					with patch("pip_audit_extra.iface.audit.loads", autospec=True) as loads_func:
						loads_func.side_effect = loads
						assert get_audit_report("TEST", 11231) == {"text": "Hello World"}
						assert tmpfile._write_was_called
						assert tmpfile._write_content == "TEST"
						assert tmpfile._close_was_called
						run_func.assert_called_once_with(
							["pip-audit", "-f", "json", "--progress-spinner", "off", "-r", "testfile"],
							capture_output=True,
							encoding="utf-8",
							timeout=11231,
						)
						loads_func.assert_called_once_with("{ \"text\": \"Hello World\" }")
