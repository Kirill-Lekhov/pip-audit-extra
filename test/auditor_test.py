from pip_audit_extra.auditor import Auditor
from pip_audit_extra.iface.osv import OSVService
from pip_audit_extra.vulnerability.cache import Cache
from pip_audit_extra.severity import Severity

from datetime import timedelta
from typing import Dict


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
