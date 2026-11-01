import os
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="cv-sec-")
os.environ["SECRET_KEY"] = "test-secret-key-for-collectors-verse-0123456789"
os.environ.pop("OWNER_PASSWORD", None)
os.environ.pop("LOGIN_USERS", None)
os.environ.pop("VERCEL", None)
os.environ["GEMINI_API_KEY"] = ""

import pytest

from app import app, get_local_db, init_local_db


@pytest.fixture
def client():
    init_local_db()
    with get_local_db() as conn:
        conn.execute("DELETE FROM login_attempts")
        conn.commit()
    with app.test_client() as test_client:
        yield test_client
