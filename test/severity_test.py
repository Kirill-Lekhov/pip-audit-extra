from pip_audit_extra.severity import Severity


class TestSeverity:
	def test_get_names(self):
		assert Severity.get_names() == ["CRITICAL", "HIGH", "MODERATE", "LOW"]
