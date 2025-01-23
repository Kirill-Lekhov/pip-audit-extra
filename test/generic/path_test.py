from pip_audit_extra.generic.path import get_cache_path

from unittest.mock import patch


class TestGetCachePath:
	def test_windows(self):
		with patch("pip_audit_extra.generic.path.system") as system_func:
			system_func.return_value = "Windows"

			with patch("pip_audit_extra.generic.path.getenv") as getenv_func:
				getenv_func.return_value = "PATH"

				assert get_cache_path() == "PATH"
				system_func.assert_called_once()
				getenv_func.assert_called_once_with("LOCALAPPDATA")

				system_func.reset_mock()
				getenv_func.reset_mock()
				getenv_func.return_value = None

				with patch("pip_audit_extra.generic.path.expanduser") as expanduser_func:
					expanduser_func.return_value = r"C:"

					with patch("pip_audit_extra.generic.path.join", new=lambda *args: r"\\".join(args)):
						assert get_cache_path() == r"C:\\AppData\\Local"
						expanduser_func.assert_called_once_with("~")

	def test_linux(self):
		with patch("pip_audit_extra.generic.path.system") as system_func:
			system_func.return_value = "Linux"

			with patch("pip_audit_extra.generic.path.expanduser") as expanduser_func:
				expanduser_func.return_value = "/home/test"

				with patch("pip_audit_extra.generic.path.join", new=lambda *args: "/".join(args)):
					assert get_cache_path() == "/home/test/.cache"
					expanduser_func.assert_called_once_with("~")
