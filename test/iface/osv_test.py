from pip_audit_extra.iface.osv import OSVRouter, OSVService

from urllib3 import PoolManager
from unittest.mock import patch
from http import HTTPStatus
from typing import Optional, Dict
from mimetypes import types_map

import pytest


class FakeResponse:
	def __init__(
		self,
		status: HTTPStatus = HTTPStatus.OK,
		headers: Optional[Dict[str, str]] = None,
		data: bytes = b"",
	) -> None:
		self.status = status
		self.headers = headers
		self.data = data


class TestOSVRouter:
	def test___init__(self):
		router = OSVRouter()
		assert router.base_url == "https://api.osv.dev/v1/"

		router = OSVRouter("BASE_URL")
		assert router.base_url == "BASE_URL"

	def test_vulnerability_detail(self):
		router = OSVRouter("BASE_URL")
		assert router.vulnerability_detail("VULN_ID") == "BASE_URL/vulns/VULN_ID"


class TestOSVService:
	def test___init__(self):
		service = OSVService()

		assert isinstance(service.http, PoolManager)
		assert isinstance(service.router, OSVRouter)

	def test_get_vulnerability__status_error(self):
		service = OSVService()

		with patch.object(service.http, "request") as request_func:
			request_func.return_value = FakeResponse(HTTPStatus.BAD_REQUEST)

			with pytest.raises(ValueError, match="Unexpected response status: .+"):
				service.get_vulnerability("TEST")

	def test_get_vulnerability__content_type_error(self):
		service = OSVService()

		with patch.object(service.http, "request") as request_func:
			request_func.return_value = FakeResponse(HTTPStatus.OK, {"Content-Type": "text/csv"})

			with pytest.raises(ValueError, match="Unexpected response content type: text/csv"):
				service.get_vulnerability("TEST")

	def test_get_vulnerability__body_type_error(self):
		service = OSVService()

		with patch.object(service.http, "request") as request_func:
			request_func.return_value = FakeResponse(HTTPStatus.OK, {"Content-Type": types_map[".json"]}, b"[]")

			with pytest.raises(ValueError, match="Invalid response data. A dict was expected"):
				service.get_vulnerability("TEST")

	def test_get_vulnerability__normal(self):
		service = OSVService()

		with patch.object(service.http, "request") as request_func:
			request_func.return_value = FakeResponse(
				HTTPStatus.OK,
				{"Content-Type": types_map[".json"]},
				b"{ \"text\": \"Hello World\" }",
			)

			assert service.get_vulnerability("TEST") == {"text": "Hello World"}
			request_func.assert_called_once_with("GET", service.router.vulnerability_detail("TEST"))
