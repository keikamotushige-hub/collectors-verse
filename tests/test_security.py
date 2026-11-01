import hashlib
import io
import os
import uuid
from urllib.parse import urlparse

import pytest
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash

import app as app_module
from app import PASSWORD_COOKIE, PASSWORD_COOKIE_SALT, app
from shared_owner_auth import SHARED_OWNER_EMAIL


def _csrf(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.status_code
    html = response.get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = html.find(marker)
    assert start != -1, html
    start += len(marker)
    end = html.find('"', start)
    token = html[start:end]
    assert token
    return token


def _signup(client, email=None, password="correct-horse"):
    email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
    token = _csrf(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": email,
            "password": password,
            "password2": password,
            "agree_terms": "on",
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)
    return email, password


def _logout(client):
    token = _csrf(client, "/")
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 302
    return response


def _login(client, email, password, next_url=None, query=None):
    token = _csrf(client, "/login")
    data = {"csrf_token": token, "email": email, "password": password}
    if next_url is not None:
        data["next"] = next_url
    return client.post("/login", query_string=query, data=data)


def _path(response):
    location = response.headers.get("Location") or ""
    return urlparse(location).path


def test_fixed_owner_password_is_rejected(client):
    import shared_owner_auth

    assert not hasattr(shared_owner_auth, "FIRST_LOGIN_PASSWORD")
    response = _login(client, SHARED_OWNER_EMAIL, "password")
    assert response.status_code == 200
    assert "正しくありません" in response.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_owner_env_password_then_change_disables_it(client, monkeypatch):
    monkeypatch.setenv("OWNER_PASSWORD", "env-owner-secret")
    response = _login(client, SHARED_OWNER_EMAIL, "env-owner-secret")
    assert response.status_code == 302
    assert _path(response) == "/"

    token = _csrf(client, "/settings/password")
    changed = client.post(
        "/settings/password",
        data={
            "csrf_token": token,
            "current_password": "env-owner-secret",
            "new_password": "rotated-owner-secret",
            "new_password2": "rotated-owner-secret",
        },
    )
    assert changed.status_code == 302
    _logout(client)

    old = _login(client, SHARED_OWNER_EMAIL, "env-owner-secret")
    assert old.status_code == 200
    new = _login(client, SHARED_OWNER_EMAIL, "rotated-owner-secret")
    assert new.status_code == 302


def test_owner_email_cannot_be_claimed_by_signup(client):
    token = _csrf(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": SHARED_OWNER_EMAIL,
            "password": "attacker-password",
            "password2": "attacker-password",
            "agree_terms": "on",
        },
    )
    assert response.status_code == 200
    assert "新規登録できません" in response.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_unsigned_password_cookie_cannot_authenticate(client):
    email = "victim@example.com"
    forged = generate_password_hash("forged-password")
    client.set_cookie(PASSWORD_COOKIE, f"{email}:{forged}")
    client.set_cookie("cv_owner_ph", f"{SHARED_OWNER_EMAIL}:{forged}")

    victim = _login(client, email, "forged-password")
    assert victim.status_code == 200
    owner = _login(client, SHARED_OWNER_EMAIL, "forged-password")
    assert owner.status_code == 200
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_signed_cookie_keeps_password_when_database_row_is_gone(client):
    email, password = _signup(client, password="persist-secret")
    with app_module.get_local_db() as conn:
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.execute("DELETE FROM owner_credentials WHERE email = ?", (email,))
        conn.commit()
    _logout(client)

    response = _login(client, email, password)
    assert response.status_code == 302
    cookie = response.headers.get("Set-Cookie", "")
    assert "scrypt:" not in cookie
    assert "pbkdf2:" not in cookie
    assert f"{email}:" not in cookie


def test_tampered_signed_cookie_is_ignored(client):
    email, password = _signup(client, password="persist-secret")
    client.set_cookie(PASSWORD_COOKIE, "not-a-valid-signature")
    with app_module.get_local_db() as conn:
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.execute("DELETE FROM owner_credentials WHERE email = ?", (email,))
        conn.commit()
    _logout(client)
    response = _login(client, email, password)
    assert response.status_code == 200


def test_database_hash_wins_over_signed_cookie(client):
    email, password = _signup(client, password="database-secret")
    other = generate_password_hash("cookie-secret")
    token = URLSafeTimedSerializer(app.secret_key, salt=PASSWORD_COOKIE_SALT).dumps(
        {"email": email, "ph": other}
    )
    client.set_cookie(PASSWORD_COOKIE, token)
    _logout(client)

    stale = _login(client, email, "cookie-secret")
    assert stale.status_code == 200
    current = _login(client, email, password)
    assert current.status_code == 302


def test_open_redirect_is_blocked(client):
    email, password = _signup(client)
    _logout(client)
    for target in (
        "https://evil.example/phish",
        "//evil.example",
        "///evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        "/terms\r\nLocation: https://evil.example",
    ):
        response = _login(client, email, password, next_url=target)
        assert response.status_code == 302
        location = response.headers["Location"]
        assert "evil.example" not in location
        assert "javascript" not in location.lower()
        assert _path(response) == "/"
        _logout(client)

    allowed = _login(client, email, password, query={"next": "/terms"})
    assert allowed.status_code == 302
    assert _path(allowed) == "/terms"


def test_login_form_drops_unsafe_next(client):
    page = client.get("/login?next=https://evil.example/phish")
    html = page.get_data(as_text=True)
    assert "evil.example" not in html
    safe = client.get("/login?next=/terms")
    assert 'name="next" value="/terms"' in safe.get_data(as_text=True)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/terms", "/terms"),
        ("/items/abc?x=1", "/items/abc?x=1"),
        ("https://evil.example", None),
        ("//evil.example", None),
        ("///evil.example", None),
        ("/\\evil.example", None),
        ("javascript:alert(1)", None),
        ("/ok\r\nSet-Cookie: a=b", None),
        ("", None),
    ],
)
def test_safe_next_url(target, expected):
    assert app_module.safe_next_url(target) == expected


def test_post_without_csrf_is_rejected(client):
    email, password = _signup(client)
    _logout(client)
    denied = client.post("/login", data={"email": email, "password": password})
    assert denied.status_code == 400
    with client.session_transaction() as sess:
        assert "user" not in sess

    _login(client, email, password)
    story = client.post("/", data={"agree_terms": "on"})
    assert story.status_code == 400
    password_change = client.post(
        "/settings/password",
        data={"current_password": password, "new_password": "another-secret", "new_password2": "another-secret"},
    )
    assert password_change.status_code == 400
    logout = client.post("/logout")
    assert logout.status_code == 400
    with client.session_transaction() as sess:
        assert sess["user"]["email"] == email


def test_get_logout_does_not_end_session(client):
    email, _password = _signup(client)
    response = client.get("/logout")
    assert response.status_code == 405
    with client.session_transaction() as sess:
        assert sess["user"]["email"] == email
    page = client.get("/")
    assert 'method="post"' in page.get_data(as_text=True)
    assert 'action="/logout"' in page.get_data(as_text=True)


def test_login_rate_limit(client, monkeypatch):
    monkeypatch.setattr(app_module, "LOGIN_MAX_FAILURES", 3)
    email, password = _signup(client)
    _logout(client)
    for _ in range(3):
        failed = _login(client, email, "wrong-password")
        assert failed.status_code == 200
        assert "多すぎ" not in failed.get_data(as_text=True)
    blocked = _login(client, email, password)
    assert blocked.status_code == 200
    assert "多すぎ" in blocked.get_data(as_text=True)
    with client.session_transaction() as sess:
        assert "user" not in sess

    with app_module.get_local_db() as conn:
        conn.execute("DELETE FROM login_attempts")
        conn.commit()
    allowed = _login(client, email, password)
    assert allowed.status_code == 302


def test_rate_limit_is_shared_across_emails_and_ignores_old_attempts(client, monkeypatch):
    monkeypatch.setattr(app_module, "LOGIN_MAX_FAILURES", 2)
    with app_module.get_local_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (attempt_key, failed_at) VALUES (?, datetime('now', '-2 hours'))",
            ("ip:127.0.0.1",),
        )
        conn.commit()
    first = _login(client, "one@example.com", "nope-nope")
    second = _login(client, "two@example.com", "nope-nope")
    assert first.status_code == 200 and "多すぎ" not in first.get_data(as_text=True)
    assert second.status_code == 200 and "多すぎ" not in second.get_data(as_text=True)
    third = _login(client, "three@example.com", "nope-nope")
    assert third.status_code == 200
    assert "多すぎ" in third.get_data(as_text=True)


def test_health_does_not_leak_secrets_or_session(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "super-secret-key-value")
    _signup(client)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"ok": True}
    body = response.get_data(as_text=True).lower()
    assert "super-secret" not in body
    assert "gemini" not in body
    assert "logged_in" not in body
    assert "is_owner" not in body
    assert "key" not in body


def test_secret_key_is_not_derived_from_the_old_password(monkeypatch, tmp_path):
    known = hashlib.sha256(b"collectors-verse:password").hexdigest()
    assert app.secret_key != known

    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setattr(app_module, "ON_VERCEL", True)
    monkeypatch.setenv("GEMINI_API_KEY", "")
    with pytest.raises(RuntimeError):
        app_module.load_secret_key()

    monkeypatch.setenv("GEMINI_API_KEY", "live-api-key-value")
    derived = app_module.load_secret_key()
    assert derived == hashlib.sha256(b"collectors-verse-session:live-api-key-value").hexdigest()
    assert derived != known

    monkeypatch.setattr(app_module, "ON_VERCEL", False)
    monkeypatch.setattr(app_module, "DATA_DIR", tmp_path)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    first = app_module.load_secret_key()
    second = app_module.load_secret_key()
    assert first == second
    assert first != known
    assert len(first) >= 32


def test_responses_send_browser_security_headers(client):
    response = client.get("/login")
    policy = response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in policy
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert response.headers["Cache-Control"] == "no-store"


def _post_photo(client, note="memo"):
    token = _csrf(client, "/")
    return client.post(
        "/",
        data={
            "csrf_token": token,
            "agree_terms": "on",
            "journal_note": note,
            "photo": (io.BytesIO(b"\xff\xd8\xff\xd9"), "item.jpg", "image/jpeg"),
        },
    )


def test_story_failure_does_not_reveal_internals(client, monkeypatch):
    _signup(client)
    messages = iter(
        [
            RuntimeError("upstream boom token=super-secret-leak host=internal.example"),
            RuntimeError("GEMINI_API_KEY=super-secret-leak rejected with 401"),
        ]
    )

    def explode(_raw, _mime, _note):
        raise next(messages)

    monkeypatch.setattr(app_module, "generate_story", explode)
    generic = _post_photo(client)
    generic_body = generic.get_data(as_text=True)
    assert generic.status_code == 200
    assert "super-secret-leak" not in generic_body
    assert "RuntimeError" not in generic_body
    assert "internal.example" not in generic_body
    assert "物語の生成に失敗しました" in generic_body

    key_error = _post_photo(client)
    key_body = key_error.get_data(as_text=True)
    assert "super-secret-leak" not in key_body
    assert "GEMINI_API_KEY を確認してください" in key_body


def test_non_image_upload_is_rejected(client, monkeypatch):
    _signup(client)
    called = {"yes": False}

    def explode(*_args, **_kwargs):
        called["yes"] = True
        raise AssertionError("generate_story should not run")

    monkeypatch.setattr(app_module, "generate_story", explode)
    token = _csrf(client, "/")
    response = client.post(
        "/",
        data={
            "csrf_token": token,
            "agree_terms": "on",
            "photo": (io.BytesIO(b"not-an-image"), "evil.jpg", "image/jpeg"),
        },
    )
    assert response.status_code == 200
    assert "画像ファイルを選んでください" in response.get_data(as_text=True)
    assert called["yes"] is False


def test_saved_story_text_is_escaped(client, monkeypatch):
    monkeypatch.setattr(
        app_module,
        "generate_story",
        lambda *_args, **_kwargs: "# タイトル\n<script>alert(1)</script>\n",
    )
    _signup(client)
    token = _csrf(client, "/")
    response = client.post(
        "/",
        data={
            "csrf_token": token,
            "agree_terms": "on",
            "journal_note": "<script>alert(1)</script>",
            "photo": (io.BytesIO(b"\xff\xd8\xff\xd9"), "item.jpg", "image/jpeg"),
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_signup_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(app_module, "LOGIN_MAX_FAILURES", 2)
    _signup(client)
    _logout(client)
    _signup(client)
    _logout(client)
    token = _csrf(client, "/signup")
    blocked = client.post(
        "/signup",
        data={
            "csrf_token": token,
            "email": "third@example.com",
            "password": "correct-horse",
            "password2": "correct-horse",
            "agree_terms": "on",
        },
    )
    assert blocked.status_code == 200
    assert "多すぎ" in blocked.get_data(as_text=True)


def test_item_lookup_uses_parameters(client):
    _signup(client)
    response = client.get("/items/' OR 1=1 --")
    assert response.status_code == 302
    assert _path(response) == "/"


def test_gemini_key_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key-from-env-123456")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key-should-not-win")
    assert app_module.get_api_key() == "gemini-key-from-env-123456"
    monkeypatch.setenv("GEMINI_API_KEY", "")
    assert app_module.get_api_key() == "google-key-should-not-win"


def test_story_without_api_key_does_not_call_out(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GOOGLE_API_KEY", "")
    with pytest.raises(RuntimeError) as caught:
        app_module.generate_story(b"\xff\xd8\xff", "image/jpeg", "note")
    message = str(caught.value)
    assert "GEMINI_API_KEY" in message
    assert "AIza" not in message


def test_dotenv_fills_only_missing_values(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GEMINI_API_KEY=from-file-key\nOWNER_PASSWORD=from-file-password\nEXTRA_CV_SETTING=from-file\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GEMINI_API_KEY", "already-set")
    os.environ.pop("OWNER_PASSWORD", None)
    os.environ.pop("EXTRA_CV_SETTING", None)
    try:
        app_module.load_local_env(env_file)
        assert os.environ["GEMINI_API_KEY"] == "already-set"
        assert os.environ["OWNER_PASSWORD"] == "from-file-password"
        assert os.environ["EXTRA_CV_SETTING"] == "from-file"
        assert app_module.get_api_key() == "already-set"
    finally:
        os.environ.pop("OWNER_PASSWORD", None)
        os.environ.pop("EXTRA_CV_SETTING", None)
