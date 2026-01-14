from flask import Flask, render_template, request, redirect, session, url_for, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
import secrets
import os
import calendar as pycal
import html
import re

# 外部API取得用
import requests

# MySQL
import pymysql
from pymysql.cursors import DictCursor
from pymysql.err import IntegrityError

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# -----------------------
# セキュリティ設定（Cookie / Session）
# -----------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False, 
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
)

STATUS_CHOICES = ("未着手", "作業中", "完了", "イベント")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# -----------------------
# MySQL 接続設定（ここを環境に合わせる）
# -----------------------
MYSQL_HOST = "127.0.0.1"
MYSQL_USER = "root"
MYSQL_PASSWORD = "NewPass123!"
MYSQL_DB = "todo_app"
MYSQL_PORT = 3306

def get_db():
    return pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        port=MYSQL_PORT,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )

def init_db():
    conn = get_db()
    conn.close()

# -----------------------
# Clickjacking 対策（X-Frame-Options / CSP）
# -----------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none';"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp

# -----------------------
# CSRF（ワンタイムトークン）対策
# -----------------------
def now_iso():
    return datetime.now().replace(microsecond=0).isoformat()

def issue_csrf_token() -> str:
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    session["csrf_issued_at"] = now_iso()
    return token

def get_csrf_token() -> str:
    tok = session.get("csrf_token")
    if not tok:
        tok = issue_csrf_token()
    return tok

def verify_csrf():
    sent = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")
    if not sent or not saved or not secrets.compare_digest(sent, saved):
        abort(400, description="CSRF token is missing or invalid.")
    # 使い捨て
    issue_csrf_token()

@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token()}


@app.template_filter("dt")
def dt_filter(v, fmt="%Y-%m-%d"):
    
    if not v:
        return ""
    if isinstance(v, str):
        # "YYYY-MM-DD HH:MM:SS" や "YYYY-MM-DDTHH:MM" を想定して雑に吸収
        s = v.replace("T", " ")
        try:
            v = datetime.fromisoformat(s)
        except ValueError:
            return v  # 変換できなければそのまま出す
    try:
        return v.strftime(fmt)
    except Exception:
        return str(v)

# -----------------------
# 祝日API（Holidays JP）ユーティリティ
# -----------------------
HOLIDAY_CACHE = {}  # year -> {"fetched_at": datetime, "data": dict}

def fetch_jp_holidays(year: int) -> dict:
    now = datetime.now()
    cached = HOLIDAY_CACHE.get(year)
    if cached and (now - cached["fetched_at"]) < timedelta(hours=12):
        return cached["data"]

    url = f"https://holidays-jp.github.io/api/v1/{year}/date.json"
    try:
        r = requests.get(url, timeout=3)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            HOLIDAY_CACHE[year] = {"fetched_at": now, "data": data}
            return data
    except Exception:
        pass

    return cached["data"] if cached else {}

# -----------------------
# 日付ユーティリティ（期限分類）
# -----------------------
def parse_iso_date(d: str):
    if not d:
        return None
    try:
        return datetime.strptime(d, "%Y-%m-%d").date()
    except ValueError:
        return None

def due_bucket(due_at_str: str):
    d = None
    if due_at_str:
        d = parse_iso_date(str(due_at_str)[:10])

    today = date.today()

    if d is None:
        return ("none", "期限なし", "due-none", 4)
    if d < today:
        return ("overdue", "期限超過", "due-overdue", 0)
    if d == today:
        return ("today", "今日が期限", "due-today", 1)
    if (d - today).days <= 3:
        return ("soon", "期限まで3日以内", "due-soon", 2)
    return ("later", "期限まで余裕", "due-later", 3)

def sort_key_task(t: dict):
    status = t.get("status", "未着手")
    unfinished_rank = 0 if status != "完了" else 1

    _, _, _, bucket_rank = due_bucket(t.get("due_at"))

    d = None
    if t.get("due_at"):
        d = parse_iso_date(str(t["due_at"])[:10])
    due_sort = d.toordinal() if d else 10**9

    pr_rank = -int(t.get("priority", 2))
    created = str(t.get("created_at") or "")
    return (unfinished_rank, bucket_rank, due_sort, pr_rank, created)

# -----------------------
# 認証ユーティリティ
# -----------------------
def login_required():
    return "user_id" in session

def current_user_id():
    return session.get("user_id")

def is_admin():
    return session.get("role") == "admin"

def admin_required_guard():
    if not login_required():
        return redirect(url_for("login"))
    if not is_admin():
        abort(403)
    return None

def ensure_task_owner(task_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM tasks WHERE id=%s;", (task_id,))
            task = cur.fetchone()
    finally:
        conn.close()

    if not task:
        abort(404)
    if (task["user_id"] != current_user_id()) and (not is_admin()):
        abort(403)
    return task

def upsert_tags_for_task(conn, task_id: int, tags_csv: str):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM task_tags WHERE task_id=%s;", (task_id,))

        names = []
        for raw in (tags_csv or "").split(","):
            n = raw.strip()
            if n:
                names.append(n)

        for name in sorted(set(names)):
            # INSERT OR IGNORE -> INSERT IGNORE
            cur.execute(
                "INSERT IGNORE INTO tags(user_id, name) VALUES(%s,%s);",
                (current_user_id(), name)
            )
            cur.execute(
                "SELECT id FROM tags WHERE user_id=%s AND name=%s;",
                (current_user_id(), name)
            )
            tag_row = cur.fetchone()
            if tag_row:
                cur.execute(
                    "INSERT IGNORE INTO task_tags(task_id, tag_id) VALUES(%s,%s);",
                    (task_id, tag_row["id"])
                )

# -----------------------
# 起動時：接続確認
# -----------------------
init_db()

# -----------------------
# ルーティング
# -----------------------
@app.route("/")
def index():
    if login_required():
        return redirect(url_for("tasks"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        get_csrf_token()
        return render_template("register.html")

    verify_csrf()

    email = (request.form.get("email", "") or "").strip().lower()
    name  = (request.form.get("name", "") or "").strip()
    password = request.form.get("password", "") or ""

    if not email or not name or not password:
        return render_template("register.html", error="メールアドレス・名前・パスワードは必須です。")
    if not EMAIL_RE.match(email):
        return render_template("register.html", error="メールアドレスの形式が正しくありません。")
    if len(password) < 8:
        return render_template("register.html", error="パスワードは8文字以上にしてください。")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users(email, name, password_hash, role, created_at) VALUES(%s,%s,%s,'user',NOW());",
                (email, name, generate_password_hash(password))
            )
        conn.commit()
    except IntegrityError:
        conn.rollback()
        conn.close()
        return render_template("register.html", error="そのメールアドレスは既に使われています。")
    conn.close()
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        get_csrf_token()
        return render_template("login.html")

    verify_csrf()

    email = (request.form.get("email", "") or "").strip().lower()
    password = request.form.get("password", "") or ""

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s;", (email,))
            user = cur.fetchone()
    finally:
        conn.close()

    if (not user) or (not check_password_hash(user["password_hash"], password)):
        return render_template("login.html", error="メールアドレスまたはパスワードが違います。")

    session.clear()
    issue_csrf_token()

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["name"] = user["name"]
    session["role"] = user.get("role") or "user"
    session.permanent = True
    return redirect(url_for("tasks"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# 管理者：ユーザー一覧
@app.route("/admin/users")
def admin_users():
    guard = admin_required_guard()
    if guard:
        return guard

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, name, role, created_at FROM users ORDER BY id;")
            rows = cur.fetchall()
    finally:
        conn.close()

    return render_template("admin_users.html", users=rows)

# -----------------------
# 管理者：ユーザーを管理者に昇格
# -----------------------
@app.route("/admin/users/<int:user_id>/make_admin", methods=["POST"])
def admin_make_admin(user_id):
    guard = admin_required_guard()
    if guard:
        return guard
    verify_csrf()

    # 自分自身を対象にしても害はないが、一応弾いてもOK
    if user_id == current_user_id():
        return redirect(url_for("admin_users"))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, role FROM users WHERE id=%s;", (user_id,))
            target = cur.fetchone()
            if not target:
                abort(404)

            # すでにadminなら何もしない
            if target["role"] == "admin":
                conn.rollback()
                return redirect(url_for("admin_users"))

            cur.execute("UPDATE users SET role='admin' WHERE id=%s;", (user_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin_users"))

# -----------------------
# 管理者：一般ユーザー削除（adminは削除しない）
# -----------------------
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    guard = admin_required_guard()
    if guard:
        return guard
    verify_csrf()

    # 自分を消す事故防止
    if user_id == current_user_id():
        abort(400, description="自分自身は削除できません。")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, role FROM users WHERE id=%s;", (user_id,))
            target = cur.fetchone()
            if not target:
                abort(404)

            # 管理者は削除不可
            if target["role"] == "admin":
                abort(403, description="管理者ユーザーは削除できません。")

            # 依存データを消す（FKのCASCADEが無い想定で手動削除）
            # 1) 対象ユーザーのtask ids取得
            cur.execute("SELECT id FROM tasks WHERE user_id=%s;", (user_id,))
            task_ids = [r["id"] for r in cur.fetchall()]

            if task_ids:
                # task_tags -> subtasks/memos -> tasks
                fmt = ",".join(["%s"] * len(task_ids))

                cur.execute(f"DELETE FROM task_tags WHERE task_id IN ({fmt});", task_ids)
                cur.execute(f"DELETE FROM subtasks WHERE task_id IN ({fmt});", task_ids)
                cur.execute(f"DELETE FROM memos WHERE task_id IN ({fmt});", task_ids)

                cur.execute("DELETE FROM tasks WHERE user_id=%s;", (user_id,))

            # tags（ユーザー固有なら削除）
            cur.execute("DELETE FROM tags WHERE user_id=%s;", (user_id,))

            # 最後に users
            cur.execute("DELETE FROM users WHERE id=%s;", (user_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


# -----------------------
# タスク一覧 + フィルタ/検索 + 右カレンダー
# -----------------------
@app.route("/tasks")
def tasks():
    if not login_required():
        return redirect(url_for("login"))

    status = request.args.get("status", "").strip()
    if status in ("すべて", "全て", "all", "ALL"):
        status = ""

    q = request.args.get("q", "").strip()
    tag = request.args.get("tag", "").strip()
    sort = request.args.get("sort", "due").strip()
    date_str = request.args.get("date", "").strip()

    now_dt = datetime.now()
    y = int(request.args.get("y", now_dt.year))
    m = int(request.args.get("m", now_dt.month))

    start = datetime(y, m, 1)
    next_start = datetime(y + 1, 1, 1) if m == 12 else datetime(y, m + 1, 1)

    cal = pycal.Calendar(firstweekday=6)
    cal_weeks = cal.monthdayscalendar(y, m)
    cal_prev_y, cal_prev_m = (y - 1, 12) if m == 1 else (y, m - 1)
    cal_next_y, cal_next_m = (y + 1, 1) if m == 12 else (y, m + 1)

    cal_holidays = fetch_jp_holidays(y)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # 月内のdue一覧（右カレンダー表示用）
            cur.execute("""
                SELECT title, due_at
                FROM tasks
                WHERE user_id=%s
                  AND due_at IS NOT NULL
                  AND due_at >= %s
                  AND due_at < %s;
            """, (current_user_id(), start, next_start))
            due_rows = cur.fetchall()

            cal_titles_by_date = {}
            for r in due_rows:
                d = str(r["due_at"])[:10]
                cal_titles_by_date.setdefault(d, []).append(r["title"])

            # タスク一覧検索
            params = [current_user_id()]
            where = ["t.user_id=%s"]

            if status:
                where.append("t.status=%s")
                params.append(status)

            if q:
                where.append("(t.title LIKE %s OR t.description LIKE %s)")
                params.extend([f"%{q}%", f"%{q}%"])

            if date_str:
                where.append("t.due_at IS NOT NULL AND DATE(t.due_at)=%s")
                params.append(date_str)

            join_tag = ""
            if tag:
                join_tag = """
                    JOIN task_tags tt ON tt.task_id = t.id
                    JOIN tags g ON g.id = tt.tag_id
                """
                where.append("g.name=%s")
                params.append(tag)

            sql = f"""
                SELECT DISTINCT t.*
                FROM tasks t
                {join_tag}
                WHERE {" AND ".join(where)};
            """
            cur.execute(sql, params)
            rows = cur.fetchall()

            cur.execute("SELECT name FROM tags WHERE user_id=%s ORDER BY name;", (current_user_id(),))
            tags = cur.fetchall()

    finally:
        conn.close()

    tasks_list = [dict(r) for r in rows]
    for t in tasks_list:
        _, label, css, _ = due_bucket(t.get("due_at"))
        t["due_label"] = label
        t["due_css"] = css
        t["is_unfinished"] = (t.get("status") != "完了")

    if sort in ("due", "auto", ""):
        tasks_list.sort(key=sort_key_task)
    elif sort == "priority":
        tasks_list.sort(key=lambda x: (0 if x.get("status") != "完了" else 1, -int(x.get("priority", 2))))
    elif sort == "created":
        tasks_list.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
    else:
        tasks_list.sort(key=sort_key_task)

    return render_template(
        "tasks.html",
        tasks=tasks_list,
        tags=tags,
        status=status,
        q=q,
        tag=tag,
        sort=sort,
        date=date_str,

        cal_year=y,
        cal_month=m,
        cal_weeks=cal_weeks,
        cal_titles_by_date=cal_titles_by_date,
        cal_today=now_dt.strftime("%Y-%m-%d"),
        cal_prev_y=cal_prev_y, cal_prev_m=cal_prev_m,
        cal_next_y=cal_next_y, cal_next_m=cal_next_m,

        cal_holidays=cal_holidays,
    )

# -----------------------
# 一覧から：ステータス即変更
# -----------------------
@app.route("/tasks/<int:task_id>/status", methods=["POST"])
def task_quick_status(task_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()
    ensure_task_owner(task_id)

    new_status = request.form.get("status", "未着手").strip()
    if new_status not in STATUS_CHOICES:
        new_status = "未着手"

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tasks
                SET status=%s, updated_at=NOW()
                WHERE id=%s AND user_id=%s;
            """, (new_status, task_id, current_user_id()))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("tasks"))

# -----------------------
# 一覧から：優先度即変更
# -----------------------
@app.route("/tasks/<int:task_id>/priority", methods=["POST"])
def task_quick_priority(task_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()
    ensure_task_owner(task_id)

    try:
        priority = int(request.form.get("priority", "2"))
    except ValueError:
        priority = 2
    if priority not in (1, 2, 3):
        priority = 2

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tasks
                SET priority=%s, updated_at=NOW()
                WHERE id=%s AND user_id=%s;
            """, (priority, task_id, current_user_id()))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("tasks"))

# -----------------------
# タスク作成
# -----------------------
@app.route("/tasks/new", methods=["GET", "POST"])
def task_new():
    if not login_required():
        return redirect(url_for("login"))

    if request.method == "GET":
        due = request.args.get("due", "").strip()
        default_due = f"{due}T23:55" if due else ""
        return render_template("task_form.html", mode="new", task=None, tags_csv="", default_due=default_due)

    verify_csrf()

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", "未着手").strip()
    try:
        priority = int(request.form.get("priority", "2"))
    except ValueError:
        priority = 2
    due_at = request.form.get("due_at", "").strip()
    tags_csv = request.form.get("tags", "").strip()

    if status not in STATUS_CHOICES:
        status = "未着手"
    if priority not in (1, 2, 3):
        priority = 2

    if not title:
        return render_template("task_form.html", mode="new", task=None, tags_csv=tags_csv, default_due=due_at, error="タイトルは必須です。")

    due_dt = None
    if due_at:
        try:
            # input[type=datetime-local] は "YYYY-MM-DDTHH:MM"
            due_dt = datetime.fromisoformat(due_at)
        except ValueError:
            return render_template("task_form.html", mode="new", task=None, tags_csv=tags_csv, default_due=due_at, error="期限の形式が不正です。")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tasks(user_id, title, description, status, priority, due_at, created_at, updated_at)
                VALUES(%s,%s,%s,%s,%s,%s,NOW(),NOW());
            """, (current_user_id(), title, description, status, priority, due_dt))
            task_id = cur.lastrowid

            # memos: INSERT OR IGNORE -> INSERT IGNORE
            cur.execute("""
                INSERT IGNORE INTO memos(task_id, content, updated_at)
                VALUES(%s,%s,NOW());
            """, (task_id, ""))

            upsert_tags_for_task(conn, task_id, tags_csv)

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

# -----------------------
# タスク詳細（メモ/サブタスク）
# -----------------------
@app.route("/tasks/<int:task_id>")
def task_detail(task_id):
    if not login_required():
        return redirect(url_for("login"))

    task = ensure_task_owner(task_id)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT g.name
                FROM tags g
                JOIN task_tags tt ON tt.tag_id = g.id
                WHERE tt.task_id=%s
                ORDER BY g.name;
            """, (task_id,))
            tag_rows = cur.fetchall()
            tags = [r["name"] for r in tag_rows]

            cur.execute("SELECT * FROM subtasks WHERE task_id=%s ORDER BY id;", (task_id,))
            subtasks = cur.fetchall()

            cur.execute("SELECT * FROM memos WHERE task_id=%s;", (task_id,))
            memo = cur.fetchone()
    finally:
        conn.close()

    return render_template("task_detail.html", task=task, tags=tags, subtasks=subtasks, memo=memo)

# -----------------------
# タスク編集
# -----------------------
@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
def task_edit(task_id):
    if not login_required():
        return redirect(url_for("login"))

    task = ensure_task_owner(task_id)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT g.name FROM tags g
                JOIN task_tags tt ON tt.tag_id=g.id
                WHERE tt.task_id=%s ORDER BY g.name;
            """, (task_id,))
            tag_rows = cur.fetchall()
            tags_csv = ", ".join([r["name"] for r in tag_rows])

            if request.method == "GET":
                default_due = ""
                if task.get("due_at"):
                    # MySQL DATETIME -> 画面入力用 "YYYY-MM-DDTHH:MM"
                    default_due = str(task["due_at"]).replace(" ", "T")[:16]
                return render_template("task_form.html", mode="edit", task=task, tags_csv=tags_csv, default_due=default_due)

            verify_csrf()

            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            status = request.form.get("status", "未着手").strip()
            try:
                priority = int(request.form.get("priority", "2"))
            except ValueError:
                priority = 2
            due_at = request.form.get("due_at", "").strip()
            tags_csv_new = request.form.get("tags", "").strip()

            if status not in STATUS_CHOICES:
                status = "未着手"
            if priority not in (1, 2, 3):
                priority = 2

            if not title:
                return render_template("task_form.html", mode="edit", task=task, tags_csv=tags_csv_new, default_due=due_at, error="タイトルは必須です。")

            due_dt = None
            if due_at:
                try:
                    due_dt = datetime.fromisoformat(due_at)
                except ValueError:
                    return render_template("task_form.html", mode="edit", task=task, tags_csv=tags_csv_new, default_due=due_at, error="期限の形式が不正です。")

            cur.execute("""
                UPDATE tasks
                SET title=%s, description=%s, status=%s, priority=%s, due_at=%s, updated_at=NOW()
                WHERE id=%s AND user_id=%s;
            """, (title, description, status, priority, due_dt, task_id, current_user_id()))

            upsert_tags_for_task(conn, task_id, tags_csv_new)

        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

# -----------------------
# タスク削除
# -----------------------
@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
def task_delete(task_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()
    ensure_task_owner(task_id)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tasks WHERE id=%s AND user_id=%s;", (task_id, current_user_id()))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("tasks"))

# -----------------------
# サブタスク追加/トグル/削除
# -----------------------
@app.route("/tasks/<int:task_id>/subtasks/add", methods=["POST"])
def subtask_add(task_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()
    ensure_task_owner(task_id)

    title = request.form.get("title", "").strip()
    if not title:
        return redirect(url_for("task_detail", task_id=task_id))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO subtasks(task_id, title, is_done, created_at) VALUES(%s,%s,0,NOW());",
                (task_id, title)
            )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

@app.route("/subtasks/<int:subtask_id>/toggle", methods=["POST"])
def subtask_toggle(subtask_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM subtasks WHERE id=%s;", (subtask_id,))
            st = cur.fetchone()
        if not st:
            abort(404)

        ensure_task_owner(st["task_id"])

        with conn.cursor() as cur2:
            cur2.execute("""
                UPDATE subtasks
                SET is_done = CASE WHEN is_done=1 THEN 0 ELSE 1 END
                WHERE id=%s;
            """, (subtask_id,))
        conn.commit()
        task_id = st["task_id"]
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

@app.route("/subtasks/<int:subtask_id>/delete", methods=["POST"])
def subtask_delete(subtask_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM subtasks WHERE id=%s;", (subtask_id,))
            st = cur.fetchone()
        if not st:
            abort(404)

        ensure_task_owner(st["task_id"])

        with conn.cursor() as cur2:
            cur2.execute("DELETE FROM subtasks WHERE id=%s;", (subtask_id,))
        conn.commit()
        task_id = st["task_id"]
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

# -----------------------
# メモ更新（MySQL版：ON DUPLICATE KEY UPDATE）
# -----------------------
@app.route("/tasks/<int:task_id>/memo", methods=["POST"])
def memo_update(task_id):
    if not login_required():
        return redirect(url_for("login"))
    verify_csrf()
    ensure_task_owner(task_id)

    content = request.form.get("content", "")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO memos(task_id, content, updated_at)
                VALUES(%s,%s,NOW())
                ON DUPLICATE KEY UPDATE
                  content=VALUES(content),
                  updated_at=NOW();
            """, (task_id, content))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("task_detail", task_id=task_id))

# -----------------------
# カレンダー（別ページ）
# -----------------------
@app.route("/calendar")
def calendar_view():
    if not login_required():
        return redirect(url_for("login"))

    today = datetime.now()
    year = int(request.args.get("y", today.year))
    month = int(request.args.get("m", today.month))

    start = datetime(year, month, 1)
    next_start = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, due_at, status, priority
                FROM tasks
                WHERE user_id=%s
                  AND due_at IS NOT NULL
                  AND due_at >= %s
                  AND due_at < %s
                ORDER BY due_at ASC;
            """, (current_user_id(), start, next_start))
            rows = cur.fetchall()
    finally:
        conn.close()

    tasks_by_date = {}
    for r in rows:
        d = str(r["due_at"])[:10]
        tasks_by_date.setdefault(d, []).append(r)

    cal = pycal.Calendar(firstweekday=6)
    weeks = cal.monthdayscalendar(year, month)

    prev_y, prev_m = (year - 1, 12) if month == 1 else (year, month - 1)
    next_y, next_m = (year + 1, 1) if month == 12 else (year, month + 1)

    holidays = fetch_jp_holidays(year)

    return render_template(
        "calendar.html",
        year=year, month=month,
        weeks=weeks,
        tasks_by_date=tasks_by_date,
        holidays=holidays,
        today_str=today.strftime("%Y-%m-%d"),
        prev_y=prev_y, prev_m=prev_m,
        next_y=next_y, next_m=next_m,
    )

# -----------------------
# カレンダー連携（iCalendar .ics）
# -----------------------
@app.route("/calendar.ics")
def calendar_ics():
    if not login_required():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM tasks
                WHERE user_id=%s AND due_at IS NOT NULL
                ORDER BY due_at ASC;
            """, (current_user_id(),))
            tasks_rows = cur.fetchall()
    finally:
        conn.close()

    def ics_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//TodoApp//JP//EN",
    ]

    for t in tasks_rows:
        due = t["due_at"]
        if isinstance(due, str):
            due = datetime.fromisoformat(due)

        dtstart = due.strftime("%Y%m%dT%H%M%S")
        dtend = (due + timedelta(minutes=30)).strftime("%Y%m%dT%H%M%S")
        uid = f"task-{t['id']}@todoapp.local"

        lines.append("BEGIN:VEVENT")
        lines.append(f"UID:{uid}")
        lines.append(f"DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}")
        lines.append(f"DTSTART:{dtstart}")
        lines.append(f"DTEND:{dtend}")
        lines.append(f"SUMMARY:{ics_escape(str(t['title']))}")
        desc = (t.get("description") or "") + f"\\nStatus: {t['status']}\\nPriority: {t['priority']}"
        lines.append(f"DESCRIPTION:{ics_escape(desc)}")
        lines.append("END:VEVENT")

    lines.append("END:VCALENDAR")
    body = "\r\n".join(lines) + "\r\n"

    return Response(body, mimetype="text/calendar", headers={
        "Content-Disposition": "attachment; filename=todo_calendar.ics"
    })

# -----------------------
# 400/403/404
# -----------------------
@app.errorhandler(400)
def bad_request(e):
    msg = html.escape(getattr(e, "description", "Bad Request"))
    return render_template("error.html", code=400, message=msg), 400

@app.errorhandler(403)
def forbidden(e):
    msg = html.escape(getattr(e, "description", "Forbidden"))
    return render_template("error.html", code=403, message=msg), 403

@app.errorhandler(404)
def not_found(e):
    msg = html.escape(getattr(e, "description", "Not Found"))
    return render_template("error.html", code=404, message=msg), 404

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
