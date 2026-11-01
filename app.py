"""Collector's Verse — standalone collector app (not SNS Risk Checker)."""
import hashlib
import os
import secrets
import sqlite3
import uuid
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from google import genai
from google.genai import types
from itsdangerous import BadSignature, URLSafeTimedSerializer
from shared_owner_auth import (
    APP_NAME,
    APP_NAME_JA,
    APP_TAGLINE,
    SHARED_OWNER_EMAIL,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent


def load_local_env(path: Path | None = None) -> None:
    """Load a local .env file. Existing environment variables stay as they are."""
    env_path = path or (BASE_DIR / ".env")
    if not env_path.is_file():
        return
    from dotenv import load_dotenv

    load_dotenv(env_path, override=False)


load_local_env()

ON_VERCEL = bool(os.environ.get("VERCEL"))
DATA_DIR = Path(
    os.environ.get("DATA_DIR")
    or (Path("/tmp/collectors-verse") if ON_VERCEL else BASE_DIR / "data")
)
LOCAL_DB_PATH = DATA_DIR / "app.db"
LOCAL_SCHEMA_PATH = BASE_DIR / "db" / "local_schema.sql"

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


def load_secret_key() -> str:
    """Signing key for sessions and password cookies.

    Never derived from a password committed in source. On Vercel, SECRET_KEY
    should be set; GEMINI_API_KEY is only a stable fallback so serverless
    instances agree. Local runs persist a random key under DATA_DIR.
    """
    configured = (os.environ.get("SECRET_KEY") or "").strip()
    if len(configured) >= 32:
        return configured
    if not ON_VERCEL:
        secret_path = DATA_DIR / ".flask_secret"
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if secret_path.is_file():
            existing = secret_path.read_text(encoding="utf-8").strip()
            if len(existing) >= 32:
                return existing
        generated = secrets.token_hex(32)
        secret_path.write_text(generated + "\n", encoding="utf-8")
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
        return generated
    api_key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if len(api_key) >= 16:
        return hashlib.sha256(f"collectors-verse-session:{api_key}".encode()).hexdigest()
    raise RuntimeError(
        "SECRET_KEY must be set. Refusing a signing key derived from a fixed password."
    )


app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
    WTF_CSRF_TIME_LIMIT=60 * 60 * 12,
    WTF_CSRF_SSL_STRICT=ON_VERCEL,
)
csrf = CSRFProtect(app)

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
MODEL_CANDIDATES = (
    GEMINI_MODEL,
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-flash-latest",
)
PER_PERSON_LIMIT = int(os.environ.get("PER_PERSON_LIMIT", "3"))
QUOTA_STOP_MESSAGE = (
    "Gemini API の利用上限に達しました。しばらく待ってから再試行するか、"
    "Google AI Studio のクォータを確認してください。"
)
OWNER_EMAILS = {
    e.strip().lower()
    for e in (os.environ.get("OWNER_EMAILS") or SHARED_OWNER_EMAIL).split(",")
    if e.strip()
}
OWNER_EMAILS.add(SHARED_OWNER_EMAIL.lower())
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LIMIT_MESSAGE = "ログイン試行が多すぎます。しばらく待ってから再度お試しください。"
SIGNUP_LIMIT_MESSAGE = "登録の試行が多すぎます。しばらく待ってから再度お試しください。"
NOTE_MAX_LENGTH = 2000
PASSWORD_COOKIE = "cv_user_ph"
LEGACY_PASSWORD_COOKIE = "cv_owner_ph"
PASSWORD_COOKIE_SALT = "collectors-verse-password-hash"
PASSWORD_COOKIE_MAX_AGE = 60 * 60 * 24 * 365

STORY_PROMPT = """あなたはコレクター向けの物語ライターです。
写真とユーザーのメモからアイテムを推定し、日本語で美しく、肯定的に描写してください。
これは正式な鑑定・真贋判定・価格保証・投資助言ではありません。断定しすぎず、推定であることを示してください。
法令違反・盗品・権利侵害を助長する内容は書かないでください。
必ず次の形式だけ出力してください。

# タイトル
（アイテム名の推定。不確実なら「推定:」を付ける）

## 物語
（歴史・職人・時代背景を2〜4段落。不確かな点は推測と明記）

## 愛着の価値
（なぜ大切に残したくなるか。相場断定はしない）

## シェア用コメント
（SNSに貼れる短い肯定文・1〜3文）

## 注意
- 本結果は参考の物語であり、正式鑑定・価値保証ではありません
- 最終判断は利用者本人が行ってください
"""


def get_api_key() -> str:
    return (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()


def get_local_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LOCAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_local_db() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with get_local_db() as conn:
            conn.executescript(LOCAL_SCHEMA_PATH.read_text(encoding="utf-8"))
            conn.commit()
    except Exception:
        pass


init_local_db()


def current_user() -> dict | None:
    user = session.get("user")
    if isinstance(user, dict) and user.get("id") and user.get("email"):
        return user
    return None


def is_owner(user: dict | None = None) -> bool:
    user = user or current_user()
    return bool(user) and (user.get("email") or "").strip().lower() in OWNER_EMAILS


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("利用にはログインが必要です。", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def env_login_users() -> dict[str, str]:
    """Bootstrap passwords from the environment. Never a password baked into source."""
    users: dict[str, str] = {}
    raw = (os.environ.get("LOGIN_USERS") or "").strip()
    if raw:
        for part in raw.split(","):
            if ":" not in part:
                continue
            email, password = part.split(":", 1)
            email, password = email.strip().lower(), password.strip()
            if email and password:
                users[email] = password
    owner_password = (os.environ.get("OWNER_PASSWORD") or "").strip()
    if owner_password:
        for email in OWNER_EMAILS:
            users.setdefault(email, owner_password)
    return users


def _consteq(left: str, right: str) -> bool:
    left_b = left.encode("utf-8")
    right_b = right.encode("utf-8")
    if len(left_b) != len(right_b):
        return False
    return secrets.compare_digest(left_b, right_b)


def _get_user_row(email: str) -> dict | None:
    email = email.strip().lower()
    try:
        with get_local_db() as conn:
            row = conn.execute(
                "SELECT id, email, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _password_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.secret_key, salt=PASSWORD_COOKIE_SALT)


def _signed_password_hash(email: str) -> str | None:
    """Password hash from a server-signed cookie. Unsigned values are ignored."""
    raw = (request.cookies.get(PASSWORD_COOKIE) or "").strip()
    if not raw:
        return None
    try:
        data = _password_serializer().loads(raw, max_age=PASSWORD_COOKIE_MAX_AGE)
    except BadSignature:
        return None
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    cookie_email = data.get("email")
    cookie_hash = data.get("ph")
    if not isinstance(cookie_email, str) or not isinstance(cookie_hash, str):
        return None
    if cookie_email.strip().lower() != email or not cookie_hash:
        return None
    return cookie_hash


def _get_stored_password_hash(email: str) -> str | None:
    email = email.strip().lower()
    row = _get_user_row(email)
    if row and row.get("password_hash"):
        return row["password_hash"]
    try:
        with get_local_db() as conn:
            crow = conn.execute(
                "SELECT password_hash FROM owner_credentials WHERE email = ?",
                (email,),
            ).fetchone()
            if crow and crow["password_hash"]:
                return crow["password_hash"]
    except Exception:
        pass
    return _signed_password_hash(email)


def _set_stored_password_hash(email: str, password: str, user_id: str | None = None) -> str:
    email = email.strip().lower()
    password_hash = generate_password_hash(password)
    uid = user_id or f"user:{email}"
    try:
        with get_local_db() as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE email = ?",
                    (password_hash, email),
                )
            else:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
                    (uid, email, password_hash),
                )
            conn.execute(
                """INSERT INTO owner_credentials (email, password_hash, updated_at)
                   VALUES (?, ?, datetime('now'))
                   ON CONFLICT(email) DO UPDATE SET
                     password_hash = excluded.password_hash,
                     updated_at = datetime('now')""",
                (email, password_hash),
            )
            conn.commit()
    except Exception:
        pass
    return password_hash


def create_account(email: str, password: str) -> tuple[dict | None, str | None]:
    email = email.strip().lower()
    password = (password or "").strip()
    if not email or "@" not in email:
        return None, "メールアドレスの形式が正しくありません。"
    if email in OWNER_EMAILS:
        return None, "このメールアドレスでは新規登録できません。ログインしてください。"
    if len(password) < 6:
        return None, "パスワードは6文字以上にしてください。"
    if _get_user_row(email):
        return None, "このメールアドレスは既に登録されています。ログインしてください。"
    user_id = str(uuid.uuid4())
    try:
        ph = generate_password_hash(password)
        with get_local_db() as conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
                (user_id, email, ph),
            )
            conn.commit()
        return {"id": user_id, "email": email, "password_hash": ph}, None
    except Exception:
        return None, "アカウント作成に失敗しました。時間をおいて再度お試しください。"


def verify_login_password(email: str, password: str) -> bool:
    email = email.strip().lower()
    password = (password or "").strip()
    if not email or not password:
        return False
    # A stored hash (database or signed cookie) replaces bootstrap passwords.
    stored = _get_stored_password_hash(email)
    if stored:
        try:
            return bool(check_password_hash(stored, password))
        except Exception:
            return False
    expected = env_login_users().get(email)
    if not expected:
        return False
    return _consteq(password, expected)


def _set_password_cookie(resp, email: str, password_hash: str):
    token = _password_serializer().dumps({"email": email.strip().lower(), "ph": password_hash})
    resp.set_cookie(
        PASSWORD_COOKIE,
        token,
        max_age=PASSWORD_COOKIE_MAX_AGE,
        httponly=True,
        samesite="Lax",
        secure=ON_VERCEL,
        path="/",
    )
    resp.delete_cookie(
        LEGACY_PASSWORD_COOKIE,
        path="/",
        httponly=True,
        samesite="Lax",
        secure=ON_VERCEL,
    )
    return resp


def _client_ip() -> str:
    return (request.remote_addr or "unknown").strip() or "unknown"


def _attempt_keys(email: str) -> list[str]:
    keys = [f"ip:{_client_ip()}"]
    if email:
        keys.append(f"email:{email}")
    return keys


def _window_modifier() -> str:
    seconds = int(LOGIN_WINDOW_SECONDS)
    if seconds < 1:
        seconds = 1
    return f"-{seconds} seconds"


def _keys_are_limited(keys: list[str]) -> bool:
    if not keys:
        return False
    try:
        with get_local_db() as conn:
            modifier = _window_modifier()
            for key in keys:
                row = conn.execute(
                    """SELECT COUNT(*) AS c FROM login_attempts
                       WHERE attempt_key = ? AND failed_at >= datetime('now', ?)""",
                    (key, modifier),
                ).fetchone()
                if row and int(row["c"]) >= int(LOGIN_MAX_FAILURES):
                    return True
    except Exception:
        return True
    return False


def _record_keys(keys: list[str]) -> None:
    if not keys:
        return
    with get_local_db() as conn:
        modifier = _window_modifier()
        conn.execute(
            "DELETE FROM login_attempts WHERE failed_at < datetime('now', ?)",
            (modifier,),
        )
        for key in keys:
            conn.execute(
                "INSERT INTO login_attempts (attempt_key, failed_at) VALUES (?, datetime('now'))",
                (key,),
            )
        conn.commit()


def login_is_limited(email: str) -> bool:
    email = (email or "").strip().lower()
    return _keys_are_limited(_attempt_keys(email))


def record_login_failure(email: str) -> None:
    email = (email or "").strip().lower()
    _record_keys(_attempt_keys(email))


def signup_is_limited() -> bool:
    return _keys_are_limited([f"signup-ip:{_client_ip()}"])


def record_signup_attempt() -> None:
    _record_keys([f"signup-ip:{_client_ip()}"])


def clear_login_failures(email: str) -> None:
    email = (email or "").strip().lower()
    with get_local_db() as conn:
        for key in _attempt_keys(email):
            conn.execute("DELETE FROM login_attempts WHERE attempt_key = ?", (key,))
        conn.commit()


def safe_next_url(target: str | None) -> str | None:
    """Same-origin relative path, or None when the target could leave the site."""
    if target is None:
        return None
    candidate = target.strip()
    if not candidate or len(candidate) > 512:
        return None
    if any(ch in candidate for ch in ("\r", "\n", "\t", "\\", "\x00")):
        return None
    if "://" in candidate or candidate.startswith("//"):
        return None
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    if not candidate.startswith("/"):
        return None
    return candidate


def redirect_after_login():
    target = safe_next_url(request.form.get("next")) or safe_next_url(request.args.get("next"))
    return redirect(target or url_for("index"))


def session_user_for_email(email: str) -> dict:
    email = email.strip().lower()
    row = _get_user_row(email)
    if row:
        return {"id": row["id"], "email": email}
    return {"id": f"user:{email}", "email": email}


def trial_used(user_id: str) -> int:
    try:
        with get_local_db() as conn:
            row = conn.execute(
                "SELECT use_count FROM user_trial_usage WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return int(row["use_count"]) if row else 0
    except Exception:
        return 0


def trial_increment(user_id: str) -> int:
    current = trial_used(user_id) + 1
    with get_local_db() as conn:
        conn.execute(
            """INSERT INTO user_trial_usage (user_id, use_count, updated_at)
               VALUES (?, ?, datetime('now'))
               ON CONFLICT(user_id) DO UPDATE SET
                 use_count = excluded.use_count,
                 updated_at = datetime('now')""",
            (user_id, current),
        )
        conn.commit()
    return current


def remaining_for(user: dict) -> dict:
    if is_owner(user):
        return {"used": 0, "remaining": 999, "limit": PER_PERSON_LIMIT, "locked": False, "is_owner": True}
    used = trial_used(user["id"])
    return {
        "used": used,
        "remaining": max(0, PER_PERSON_LIMIT - used),
        "limit": PER_PERSON_LIMIT,
        "locked": used >= PER_PERSON_LIMIT,
        "is_owner": False,
    }


def generate_story(image_bytes: bytes, mime: str, note: str) -> str:
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "サーバーに APIキー（GEMINI_API_KEY）が入っていません。"
            "Vercel の Environment Variables に設定してください。"
        )
    client = genai.Client(api_key=api_key)
    parts = [
        types.Part(text=STORY_PROMPT),
        types.Part(text=f"【ユーザーメモ】\n{note or '（なし）'}"),
        types.Part(inline_data=types.Blob(data=image_bytes, mime_type=mime)),
    ]
    contents = types.Content(role="user", parts=parts)
    last_error: Exception | None = None
    models_to_try: list[str] = []
    for name in MODEL_CANDIDATES:
        if name and name not in models_to_try:
            models_to_try.append(name)

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
            )
            text = (getattr(response, "text", None) or "").strip()
            if text:
                return text
            last_error = RuntimeError("物語を生成できませんでした。")
        except Exception as exc:
            message = str(exc).lower()
            if any(
                token in message
                for token in ("429", "resource_exhausted", "quota", "rate limit")
            ):
                raise RuntimeError(QUOTA_STOP_MESSAGE) from exc
            last_error = RuntimeError(
                f"Geminiへの接続に失敗しました（モデル: {model_name}）。"
                f"詳細: {type(exc).__name__}: {exc}"
            )
            if any(
                token in message
                for token in ("404", "not_found", "no longer available")
            ):
                continue
            raise last_error from exc

    raise last_error or RuntimeError("物語を生成できませんでした。")


def parse_story(text: str) -> dict:
    title = "名称未設定のコレクション"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# ") and "タイトル" not in line:
            title = line[2:].strip() or title
            break
        if "タイトル" in line and i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            if nxt and not nxt.startswith("#"):
                title = nxt
                break
    share = ""
    if "## シェア用コメント" in text:
        share = text.split("## シェア用コメント", 1)[1].strip().split("##")[0].strip()
    affection = ""
    if "## 愛着の価値" in text:
        affection = text.split("## 愛着の価値", 1)[1].strip().split("##")[0].strip()
    return {
        "title": title[:120],
        "story_markdown": text,
        "affection_rationale": affection,
        "share_text": share,
    }


def save_item(owner_id: str, parsed: dict, journal_note: str) -> str:
    item_id = str(uuid.uuid4())
    with get_local_db() as conn:
        conn.execute(
            """INSERT INTO items
               (id, owner_id, title, story_markdown, affection_rationale, share_text, journal_note)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                item_id,
                owner_id,
                parsed["title"],
                parsed["story_markdown"],
                parsed["affection_rationale"],
                parsed["share_text"],
                journal_note,
            ),
        )
        conn.commit()
    return item_id


def list_items(owner_id: str) -> list:
    try:
        with get_local_db() as conn:
            rows = conn.execute(
                "SELECT id, title, created_at FROM items WHERE owner_id = ? ORDER BY created_at DESC",
                (owner_id,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def get_item(item_id: str, owner_id: str) -> dict | None:
    with get_local_db() as conn:
        row = conn.execute(
            "SELECT * FROM items WHERE id = ? AND owner_id = ?",
            (item_id, owner_id),
        ).fetchone()
        return dict(row) if row else None


@app.context_processor
def inject_brand():
    return {"app_name": APP_NAME, "app_name_ja": APP_NAME_JA, "app_tagline": APP_TAGLINE}


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self'; "
        "script-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    resp.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def detect_image_mime(raw: bytes) -> str | None:
    """Trust the file bytes, not the browser-supplied Content-Type."""
    if raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return None


@app.errorhandler(CSRFError)
def handle_csrf_error(_err: CSRFError):
    return ("不正なリクエストです。ページを再読み込みしてやり直してください。", 400)


@app.route("/health")
def health():
    return {"ok": True}


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    email = ""
    next_url = safe_next_url(request.values.get("next")) or ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        if not email or not password:
            error = "メールアドレスとパスワードを入力してください。"
        elif login_is_limited(email):
            error = LOGIN_LIMIT_MESSAGE
        elif verify_login_password(email, password):
            clear_login_failures(email)
            session.clear()
            session.permanent = True
            session["user"] = session_user_for_email(email)
            flash("ログインしました。", "ok")
            resp = make_response(redirect_after_login())
            stored = _get_stored_password_hash(email)
            if stored:
                _set_password_cookie(resp, email, stored)
            return resp
        else:
            record_login_failure(email)
            error = "メールアドレスまたはパスワードが正しくありません。アカウント未作成の場合は新規登録してください。"
    return render_template("login.html", error=error, email=email, next_url=next_url)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    email = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        password2 = (request.form.get("password2") or "").strip()
        agreed = request.form.get("agree_terms") == "on"
        if signup_is_limited():
            error = SIGNUP_LIMIT_MESSAGE
        else:
            record_signup_attempt()
            if not agreed:
                error = "利用規約・免責事項への同意が必要です。"
            elif not email or not password:
                error = "メールアドレスとパスワードを入力してください。"
            elif password != password2:
                error = "確認用パスワードが一致しません。"
            else:
                user, err = create_account(email, password)
                if err:
                    error = err
                else:
                    session.clear()
                    session.permanent = True
                    session["user"] = {"id": user["id"], "email": email}
                    flash("アカウントを作成してログインしました。", "ok")
                    resp = make_response(redirect(url_for("index")))
                    _set_password_cookie(resp, email, user["password_hash"])
                    return resp
    return render_template("signup.html", error=error, email=email)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ログアウトしました。", "ok")
    return redirect(url_for("login"))


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    error = None
    if request.method == "POST":
        cur = (request.form.get("current_password") or "").strip()
        new = (request.form.get("new_password") or "").strip()
        new2 = (request.form.get("new_password2") or "").strip()
        if login_is_limited(user["email"]):
            error = LOGIN_LIMIT_MESSAGE
        elif not verify_login_password(user["email"], cur):
            record_login_failure(user["email"])
            error = "現在のパスワードが正しくありません。"
        elif len(new) < 6:
            error = "新しいパスワードは6文字以上にしてください。"
        elif new != new2:
            error = "確認用パスワードが一致しません。"
        else:
            clear_login_failures(user["email"])
            ph = _set_stored_password_hash(user["email"], new, user_id=user.get("id"))
            flash("パスワードを変更しました。", "ok")
            resp = make_response(redirect(url_for("index")))
            _set_password_cookie(resp, user["email"], ph)
            return resp
    return render_template("change_password.html", error=error)


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user = current_user()
    quota = remaining_for(user)
    error = None
    agreed = False
    if request.method == "POST":
        agreed = request.form.get("agree_terms") == "on"
        if not agreed:
            error = "利用規約・免責事項への同意が必要です。"
        elif quota["locked"] and not is_owner(user):
            error = f"無料トライアルは {PER_PERSON_LIMIT} 回までです。"
        else:
            image = request.files.get("photo")
            note = (request.form.get("journal_note") or "").strip()
            if len(note) > NOTE_MAX_LENGTH:
                error = f"メモは {NOTE_MAX_LENGTH} 文字以内にしてください。"
            elif not image or not image.filename:
                error = "コレクションの写真を選んでください。"
            else:
                raw = image.read()
                mime = detect_image_mime(raw)
                if not raw or not mime:
                    error = "画像ファイルを選んでください。"
                elif len(raw) > 8 * 1024 * 1024:
                    error = "画像は 8MB 以下にしてください。"
                else:
                    try:
                        parsed = parse_story(generate_story(raw, mime, note))
                        item_id = save_item(user["id"], parsed, note)
                        if not is_owner(user):
                            trial_increment(user["id"])
                        return redirect(url_for("item_detail", item_id=item_id))
                    except Exception as exc:
                        msg = str(exc).lower()
                        if any(t in msg for t in ("429", "quota", "resource_exhausted")):
                            error = "AIの利用上限に達しました。しばらくしてから再度お試しください。"
                        elif "api key" in msg or "api_key" in msg or "401" in msg or "403" in msg:
                            error = (
                                "Gemini APIキーが無効か、権限がありません。"
                                "Vercel の GEMINI_API_KEY を確認してください。"
                            )
                        else:
                            error = "物語の生成に失敗しました。時間をおいて再度お試しください。"
        quota = remaining_for(user)
    return render_template(
        "index.html",
        user=user,
        is_owner=is_owner(user),
        quota=quota,
        error=error,
        items=list_items(user["id"]),
        agreed=agreed,
    )


@app.route("/items/<item_id>")
@login_required
def item_detail(item_id: str):
    user = current_user()
    item = get_item(item_id, user["id"])
    if not item:
        flash("アイテムが見つかりません。", "error")
        return redirect(url_for("index"))
    return render_template("item.html", user=user, is_owner=is_owner(user), item=item)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=False)
