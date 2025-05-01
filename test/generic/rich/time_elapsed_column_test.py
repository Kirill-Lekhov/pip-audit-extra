from pip_audit_extra.generic.rich.time_elapsed_column import CustomTimeElapsedColumn

from unittest.mock import Mock
from datetime import timedelta

from rich.table import Column
from rich.text import Text


class TestCustomTimeElapsedColumn:
	def test___init__(self):
		column = CustomTimeElapsedColumn()
		assert column._table_column is None
		assert column.style == "progress.elapsed"

		table_column = Column()
		column = CustomTimeElapsedColumn(table_column, style="custom-style")
		assert column._table_column is table_column
		assert column.style == "custom-style"

	def test_render(self):
		task_mock = Mock()
		task_mock.finished = True
		task_mock.finished_time = None
		column = CustomTimeElapsedColumn(style="custom-style")
		result = column.render(task_mock)

		assert isinstance(result, Text)
		assert result._text == ["--"]
		assert result.style == "custom-style"

		task_mock.finished = False
		task_mock.elapsed = 0.5678
		result = column.render(task_mock)

		assert isinstance(result, Text)
		assert result._text == ["0.6s"]
		assert result.style == "custom-style"

	def test_render_delta(self):
		td = timedelta(seconds=0.5678)
		column = CustomTimeElapsedColumn()
		assert column.render_delta(td) == "0.6s"
