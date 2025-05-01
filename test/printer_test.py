from pip_audit_extra.printer import Printer
from pip_audit_extra.generic.rich.time_elapsed_column import CustomTimeElapsedColumn

from unittest.mock import patch, Mock

from rich.console import Console, Group
from rich.progress import Progress, TextColumn, BarColumn
from rich.control import Control
from rich.segment import ControlType
from rich.text import Text


class TestPrinter:
	def test___init__(self):
		console = Console()
		printer = Printer(console)

		assert printer.console is console
		assert isinstance(printer.progress, Progress)
		assert isinstance(printer.progress.columns[0], TextColumn)
		assert printer.progress.columns[0].text_format == "[progress.description]{task.description}"
		assert isinstance(printer.progress.columns[1], BarColumn)
		assert isinstance(printer.progress.columns[2], CustomTimeElapsedColumn)
		assert printer.progress.live.transient
		assert printer.task_id_main is None
		assert printer.task_id_deps_collecting is None
		assert printer.task_id_deps_checking is None
		assert printer.task_id_vulns_inspecting is None
		assert printer.print_result is printer.noop

		def print_result():
			pass

		printer = Printer(console, print_result=print_result)
		assert printer.print_result is print_result

	def test___enter__(self):
		console = Console()
		printer = Printer(console)

		with patch.object(printer.progress, "add_task") as add_task_mock:
			with patch.object(printer.progress, "__enter__") as progress_enter_mock:
				add_task_mock.return_value = 4686
				assert printer.__enter__() is printer
				assert printer.task_id_main == 4686
				add_task_mock.assert_called_once_with("Searching vulnerabilities...", total=None)
				progress_enter_mock.assert_called_once()

	def test___exit__(self):
		console = Console()
		printer = Printer(console)

		with patch.object(printer.progress, "remove_task") as remove_task_mock:
			with patch.object(printer.progress, "__exit__") as progress_exit_mock:
				progress_exit_mock.return_value = "TEST"
				assert printer.__exit__(None, None, None) == "TEST"
				remove_task_mock.assert_not_called()
				progress_exit_mock.assert_called_once_with(None, None, None)

		printer.task_id_main = 0		# type: ignore - for testing purposes

		with patch.object(printer.progress, "remove_task") as remove_task_mock:
			with patch.object(printer.progress, "__exit__") as progress_exit_mock:
				progress_exit_mock.return_value = "TEST"
				assert printer.__exit__(Exception, Exception("TEST"), None) == "TEST"
				remove_task_mock.assert_not_called()
				progress_exit_mock.assert_called_once()
				assert progress_exit_mock.call_args[0][0] is Exception
				assert isinstance(progress_exit_mock.call_args[0][1], Exception)
				assert progress_exit_mock.call_args[0][1].args[0] == "TEST"
				assert progress_exit_mock.call_args[0][2] is None

		with patch("pip_audit_extra.printer.Progress.tasks", new_callable=lambda *_: ["TEST TASK"]):
			with patch("rich.progress.Live"):
				printer = Printer(console)
				printer.task_id_main = 0		# type: ignore - for testing purposes

				with patch("pip_audit_extra.printer.CustomTimeElapsedColumn") as CustomTimeElapsedColumnMock:
					CustomTimeElapsedColumnMock.return_value = Mock()
					CustomTimeElapsedColumnMock.return_value.render = Mock()
					CustomTimeElapsedColumnMock.return_value.render.return_value = Text("0.6s")

					with patch.object(printer.progress, "remove_task") as remove_task_mock:
						with patch.object(printer.progress, "__exit__") as progress_exit_mock:
							with patch.object(printer.console, "control") as console_control_mock:
								with patch.object(printer.console, "print") as console_print_mock:
									with patch.object(printer, "print_result") as print_result_mock:
										progress_exit_mock.return_value = "TEST"
										assert printer.__exit__(None, None, None) == "TEST"
										console_control_mock.assert_called_once()
										assert isinstance(console_control_mock.call_args[0][0], Control)
										assert console_control_mock.call_args[0][0].segment.control == [
											(ControlType.CURSOR_UP, 1),
										]
										console_print_mock.assert_called_once()
										CustomTimeElapsedColumnMock.assert_called_once_with(style="white")
										CustomTimeElapsedColumnMock.return_value.render.assert_called_once_with(
											"TEST TASK"
										)
										assert isinstance(console_print_mock.call_args[0][0], Text)
										assert console_print_mock.call_args[0][0]._text == ["The audit was completed in"]
										assert isinstance(console_print_mock.call_args[0][1], Text)
										assert console_print_mock.call_args[0][1]._text == ["0.6s"]
										assert console_print_mock.call_args_list[0].kwargs == {"style": "white"}
										print_result_mock.assert_called_once()
										remove_task_mock.assert_called_once_with(0)
										progress_exit_mock.assert_called_once_with(None, None, None)

	def test_noop(self):
		pass

	def test_handle_collecting_start(self):
		pass

	def test_handle_collecting_end(self):
		pass

	def test_handle_checking_start(self):
		pass

	def test_handle_checking_step(self):
		pass

	def test_handle_checking_end(self):
		pass

	def test_handle_vulns_inspecting_start(self):
		pass

	def test_handle_vulns_inspecting_step(self):
		pass

	def test_handle_vulns_inspecting_end(self):
		pass
