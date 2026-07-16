"""Collector's Verse — standalone collector app (not SNS Risk Checker)."""
import hashlib
import os
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

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
from google import genai
from google.genai import types
from shared_owner_auth import (
    APP_NAME,
    APP_NAME_JA,
    APP_TAGLINE,
    FIRST_LOGIN_PASSWORD,
    SHARED_OWNER_EMAIL,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
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
_secret = (os.environ.get("SECRET_KEY") or "").strip()
if not _secret:
    _seed = (os.environ.get("GEMINI_API_KEY") or FIRST_LOGIN_PASSWORD).strip()
    _secret = hashlib.sha256(f"collectors-verse:{_seed}".encode()).hexdigest()
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
)

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
OWNER_PASSWORD = (os.environ.get("OWNER_PASSWORD") or FIRST_LOGIN_PASSWORD).strip()

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
    for email in OWNER_EMAILS:
        users[email] = OWNER_PASSWORD
    return users


def _get_stored_password_hash(email: str) -> str | None:
    email = email.strip().lower()
    try:
        with get_local_db() as conn:
            row = conn.execute(
                "SELECT password_hash FROM owner_credentials WHERE email = ?",
                (email,),
            ).fetchone()
            if row:
                return row["password_hash"]
    except Exception:
        pass
    raw = (request.cookies.get("cv_owner_ph") or "").strip()
    if raw and ":" in raw:
        cookie_email, cookie_hash = raw.split(":", 1)
        if cookie_email.strip().lower() == email and cookie_hash:
            return cookie_hash
    return None


def _set_stored_password_hash(email: str, password: str) -> str:
    email = email.strip().lower()
    password_hash = generate_password_hash(password)
    try:
        with get_local_db() as conn:
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


def verify_login_password(email: str, password: str) -> bool:
    email = email.strip().lower()
    password = (password or "").strip()
    if not email or not password:
        return False
    # Env / first-login password always wins for known users (avoids stale cookie lockout).
    expected = env_login_users().get(email)
    if expected and password == expected.strip():
        return True
    if email in OWNER_EMAILS and password == FIRST_LOGIN_PASSWORD:
        return True
    stored = _get_stored_password_hash(email)
    if stored:
        try:
            if check_password_hash(stored, password):
                return True
        except Exception:
            pass
    return False


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


@app.route("/health")
def health():
    user = current_user()
    api_key = get_api_key()
    return {
        "ok": True,
        "app": APP_NAME,
        "logged_in": bool(user),
        "is_owner": is_owner(user),
        "has_gemini_key": bool(api_key),
        "gemini_key_length": len(api_key),
        "model": GEMINI_MODEL,
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    email = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()
        if not email or not password:
            error = "メールアドレスとパスワードを入力してください。"
        elif verify_login_password(email, password):
            session.clear()
            session.permanent = True
            session["user"] = {"id": f"user:{email}", "email": email}
            flash("ログインしました。", "ok")
            resp = make_response(redirect(request.args.get("next") or url_for("index")))
            # Drop stale password cookie so it cannot block later logins.
            resp.delete_cookie("cv_owner_ph")
            return resp
        else:
            error = "メールアドレスまたはパスワードが正しくありません。"
    return render_template("login.html", error=error, email=email)


@app.route("/logout")
def logout():
    session.clear()
    flash("ログアウトしました。", "ok")
    return redirect(url_for("login"))


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    if not is_owner(user):
        flash("オーナーのみ変更できます。", "error")
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        cur = (request.form.get("current_password") or "").strip()
        new = (request.form.get("new_password") or "").strip()
        new2 = (request.form.get("new_password2") or "").strip()
        if not verify_login_password(user["email"], cur):
            error = "現在のパスワードが正しくありません。"
        elif len(new) < 6:
            error = "新しいパスワードは6文字以上にしてください。"
        elif new != new2:
            error = "確認用パスワードが一致しません。"
        else:
            ph = _set_stored_password_hash(user["email"], new)
            flash("パスワードを変更しました。", "ok")
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie(
                "cv_owner_ph",
                f"{user['email']}:{ph}",
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="Lax",
                secure=ON_VERCEL,
            )
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
            if not image or not image.filename:
                error = "コレクションの写真を選んでください。"
            else:
                raw = image.read()
                mime = image.mimetype or "image/jpeg"
                if not raw or not mime.startswith("image/"):
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
                            detail = str(exc).strip()
                            if len(detail) > 220:
                                detail = detail[:220] + "…"
                            error = f"物語の生成に失敗しました。（{type(exc).__name__}: {detail}）"
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
