from typing import Final


HASH_PREFIX: Final[str] = "--hash"


def clean_requirements(requirements: str) -> str:
	"""
	Cleans project requirements.txt file content, removes hashes and python versions.
	"""
	lines = requirements.split("\n")
	dependencies = []

	for line in lines:
		if line.lstrip().startswith(HASH_PREFIX):
			continue

		line_parts = line.split(" ; ")
		dependencies.append(line_parts[0].strip())

	return "\n".join(dependencies)
