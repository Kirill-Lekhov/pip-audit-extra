from urllib3 import PoolManager
from json import loads
from posixpath import join
from http import HTTPStatus
from mimetypes import types_map


class OSVRouter:
	def __init__(self, base_url: str = "https://api.osv.dev/v1/") -> None:
		self.base_url = base_url

	def vulnerability_detail(self, vuln_id: str) -> str:
		return join(self.base_url, "vulns", vuln_id)


class OSVService:
	def __init__(self) -> None:
		self.http = PoolManager()
		self.router = OSVRouter()

	def get_vulnerability(self, vuln_id: str) -> dict:
		"""
		Returns vulnerability data by id.

		Args:
			vuln_id: ID of the vulnerability to get the data for.

		Returns:
			Raw vulnerability data.
		"""
		response = self.http.request("GET", self.router.vulnerability_detail(vuln_id))

		if response.status != HTTPStatus.OK:
			raise ValueError(f"Unexpected response status: {response.status}")

		response_content_type = response.headers.get("Content-Type")

		if response_content_type != types_map[".json"]:
			raise ValueError(f"Unexpected response content type: {response_content_type}")

		data = loads(response.data)
		assert isinstance(data, dict), "Invalid response data. A dict was expected"

		return data
