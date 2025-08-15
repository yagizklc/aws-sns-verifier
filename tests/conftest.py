from pathlib import Path
import pytest


@pytest.fixture
def valid_sns_message() -> bytes:
    p = Path(__file__).parent / "data.json"
    return p.read_bytes()
