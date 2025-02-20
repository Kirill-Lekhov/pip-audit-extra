from pip_audit_extra.cli import SeverityFilterHandler, FailLevelHandler, CacheLifetimeHandler, get_parser
from pip_audit_extra.severity import Severity
from pip_audit_extra.vulnerability.filter.severity import SeverityFilterOption

from argparse import ArgumentTypeError
from datetime import timedelta

import pytest


class TestSeverityFilterHandler:
	def test___init__(self):
		handler = SeverityFilterHandler()
		assert handler.severity_names == set(Severity.get_names())

	def test___call__(self):
		handler = SeverityFilterHandler()

		assert handler(None) is None

		with pytest.raises(ArgumentTypeError, match="Value must be str or None"):
			handler(15)

		filter_option = handler("~low")
		assert isinstance(filter_option, SeverityFilterOption)
		assert filter_option.exac == True
		assert filter_option.value is Severity.LOW

		filter_option = handler("MODERATE")
		assert isinstance(filter_option, SeverityFilterOption)
		assert filter_option.exac == False
		assert filter_option.value is Severity.MODERATE

	def test_get_severity(self):
		handler = SeverityFilterHandler()

		with pytest.raises(ArgumentTypeError, match="Unknown severity was met"):
			handler.get_severity("unknown")

		for i in Severity:
			assert handler.get_severity(i.name) is i


class TestFailLevelHandler:
	def test___call__(self):
		handler = FailLevelHandler()

		assert handler(None) is None

		with pytest.raises(ArgumentTypeError, match="Value must be str or None"):
			handler(15)

		with pytest.raises(ArgumentTypeError, match="Unknown severity was met"):
			handler("UNKNOWN")

		assert handler("high") is Severity.HIGH


class TestCacheLifetimeHandler:
	def test___call__(self):
		handler = CacheLifetimeHandler()

		assert handler(None) is None

		with pytest.raises(ArgumentTypeError, match="Value must be str or None"):
			handler(10)

		assert handler("123456") == timedelta(seconds=123456)
		assert handler("10d") == timedelta(days=10)
		assert handler("10h") == timedelta(hours=10)
		assert handler("10m") == timedelta(minutes=10)
		assert handler("10s") == timedelta(seconds=10)

		with pytest.raises(ArgumentTypeError, match=r"Value must be string in format: '<int>\[d,h,m,s\]'"):
			handler("10 centimeters per second")


def test_get_parser():
	parser = get_parser()

	assert parser.prog == "pip-audit-extra"
	assert parser.description == "An add-on to the pip-audit utility, which allows to work with vulnerabilities of a certain severity"
	assert len(parser._actions) == 5

	assert parser._actions[1].option_strings == ["--severity"]
	assert isinstance(parser._actions[1].type, SeverityFilterHandler)
	assert parser._actions[1].default is None

	assert parser._actions[2].option_strings == ["--fail-level"]
	assert isinstance(parser._actions[2].type, FailLevelHandler)
	assert parser._actions[2].default is None

	assert parser._actions[3].option_strings == ["--cache-lifetime"]
	assert isinstance(parser._actions[3].type, CacheLifetimeHandler)
	assert parser._actions[3].default == "1d"

	assert parser._actions[4].option_strings == ["--local"]
	assert parser._actions[4].default == False
