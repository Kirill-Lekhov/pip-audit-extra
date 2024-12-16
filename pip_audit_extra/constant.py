from pip_audit_extra.generic.path import get_cache_path

from typing import Final
from os.path import join


# Cache folder for generic purposes
CACHE_FOLDER: Final[str] = join(get_cache_path(), "pip-audit-extra")
