from pip_audit_extra.iface.pip_audit.base import PIPAudit, AuditPreferences

from subprocess import run, CompletedProcess
from tempfile import NamedTemporaryFile
from os import remove


class AuditPreferencesRequirements(AuditPreferences):
	"""
	Audit preferences dataclass.

	Attrs:
		requirements: Project dependencies in the `requirements.txt` format.
		timeout: (in seconds) Max audit execution time.
	"""
	__slots__ = "timeout", "requirements"

	requirements: str

	def __init__(self, requirements: str, *, timeout: float = 600):
		super().__init__(timeout=timeout)
		self.requirements = requirements


class PIPAuditRequirements(PIPAudit):
	def audit(self, preferences: AuditPreferencesRequirements) -> CompletedProcess:
		tmpfile = NamedTemporaryFile("w", delete=False)

		try:
			tmpfile.write(preferences.requirements)
			tmpfile.close()
			completed_process = run(
				["pip-audit", "-f", "json", "--progress-spinner", "off", "-r", tmpfile.name],
				capture_output=True,
				encoding="utf-8",
				timeout=preferences.timeout,
			)
		finally:
			remove(tmpfile.name)

		return completed_process
