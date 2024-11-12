from subprocess import run
from json import loads
from tempfile import NamedTemporaryFile
from os import remove


def get_audit_report(requirements: str, timeout: float = 600) -> dict:
	"""
	Returns raw project audit report.

	Args:
		requirements: Project dependencies in the `requirements.txt` format.
		timeout: (in seconds) Max audit execution time.

	Notes:
		* All packages and modules of the pip-audit are private, so we use subprocess to interact with it.
	"""
	tmpfile = NamedTemporaryFile("w", delete=False)

	try:
		tmpfile.write(requirements)
		tmpfile.close()
		completed_process = run(
			["pip-audit", "-f", "json", "--progress-spinner", "off", "-r", tmpfile.name],
			capture_output=True,
			encoding="utf-8",
			timeout=timeout,
		)
	finally:
		remove(tmpfile.name)

	if completed_process.returncode not in {0, 1}:
		raise RuntimeError(f"pip-audit returned an unexpected code: {completed_process.returncode}")

	report = loads(completed_process.stdout)

	assert isinstance(report, dict), "Deserialized report must be of dict type"

	return report
