import sys
from pathlib import Path
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'llm'), str(ROOT / 'context_builder')]


def pytest_configure(config):
    # A fresh exported checkout has no runtime directories yet. Keep temporary
    # files in the project and create the parent expected by pytest's basetemp.
    if not config.option.basetemp:
        config.option.basetemp = str(ROOT / '.review-work' / f'tests-{time.time_ns()}')
    Path(config.option.basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)
