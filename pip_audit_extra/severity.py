from enum import Enum
from typing import Final, Dict, List


class Severity(Enum):
	CRITICAL = "CRITICAL"
	HIGH = "HIGH"
	MODERATE = "MODERATE"
	LOW = "LOW"

	def __str__(self) -> str:
		return self.value


SEVERITY_PRIORITY: Final[Dict[Severity, int]] = {
	Severity.CRITICAL: 0,
	Severity.HIGH: 1,
	Severity.MODERATE: 2,
	Severity.LOW: 3,
}
SEVERITY_COLOR: Final[Dict[Severity, str]] = {
	Severity.CRITICAL: "red",
	Severity.HIGH: "yellow",
	Severity.MODERATE: "cyan",
	Severity.LOW: "white",
}
