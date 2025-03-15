from pip_audit_extra.iface.osv.router import OSVRouter


class TestOSVRouter:
	def test___init__(self):
		router = OSVRouter()
		assert router.base_url == "https://api.osv.dev/v1/"

		router = OSVRouter("BASE_URL")
		assert router.base_url == "BASE_URL"

	def test_vulnerability_detail(self):
		router = OSVRouter("BASE_URL")
		assert router.vulnerability_detail("VULN_ID") == "BASE_URL/vulns/VULN_ID"
