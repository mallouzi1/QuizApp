#!/usr/bin/env python3
"""
Quiz App — an intentionally insecure web application for SECURITY EDUCATION.

⚠️  WARNING: This app contains DELIBERATE security vulnerabilities used to
    teach web-security concepts (similar to OWASP WebGoat / DVWA).
    DO NOT deploy this on a public server or use it with real data.
    Run it ONLY on a local machine / trusted lab network.

Each known weakness is tagged in the code with `# VULN:` so it can be
found, discussed, and (as an exercise) fixed. See README.md for the full list.

Runs on Python's standard library only — no third-party packages required.
"""

import html
import http.server
import json
import os
import sqlite3
import urllib.parse
from http.cookies import SimpleCookie

DB_PATH = os.path.join(os.path.dirname(__file__), "quiz.db")
HOST = "127.0.0.1"
PORT = 8000

# ---------------------------------------------------------------------------
# Database setup / seed data
# ---------------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE,
               password TEXT,          -- VULN: passwords stored in plaintext
               is_admin INTEGER DEFAULT 0
           )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS questions (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               prompt TEXT,
               option_a TEXT,
               option_b TEXT,
               option_c TEXT,
               option_d TEXT,
               correct TEXT             -- 'a' | 'b' | 'c' | 'd'
           )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS scores (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT,
               score INTEGER,
               comment TEXT             -- VULN: rendered without escaping (stored XSS)
           )"""
    )

    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            [("admin", "admin123", 1), ("student", "password", 0)],
        )

    if c.execute("SELECT COUNT(*) FROM questions").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO questions (prompt, option_a, option_b, option_c, option_d, correct) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("What does HTTP stand for?",
                 "HyperText Transfer Protocol", "High Transfer Text Protocol",
                 "Hyperlink Transfer Protocol", "Host Transfer Protocol", "a"),
                ("Which port does HTTPS use by default?",
                 "80", "8080", "443", "22", "c"),
                ("What language runs in the browser?",
                 "Python", "JavaScript", "C++", "Rust", "b"),
                ("SQL injection targets which layer?",
                 "The CSS", "The database", "The DNS", "The CPU cache", "b"),
                ("What does XSS stand for?",
                 "Extra Style Sheets", "Cross-Site Scripting",
                 "XML Style System", "Cross System Standard", "b"),
            ],
        )
    conn.commit()
    conn.close()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Naive in-memory session store
# ---------------------------------------------------------------------------
# VULN: session id is just the username (predictable / forgeable), and there
#       is no signing or expiry. An attacker can set sid=admin in their cookie.
SESSIONS = {}


def current_user(headers):
    cookie = SimpleCookie(headers.get("Cookie", ""))
    if "sid" in cookie:
        sid = cookie["sid"].value
        return SESSIONS.get(sid)
    return None


# ---------------------------------------------------------------------------
# HTML rendering helpers
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Quiz App</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }}
 nav a {{ margin-right: 1rem; }}
 .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
 .banner {{ background: #fff3cd; border: 1px solid #ffe69c; padding: .5rem 1rem; border-radius: 6px; }}
 button {{ padding: .4rem .8rem; }}
 input {{ padding: .4rem; }}
</style></head><body>
<div class="banner">⚠️ Intentionally insecure demo app — for security education only.</div>
<nav>
  <a href="/">Home</a>
  <a href="/quiz">Take Quiz</a>
  <a href="/leaderboard">Leaderboard</a>
  <a href="/login">Login</a>
  <a href="/admin">Admin</a>
</nav>
<hr>
{body}
</body></html>"""


def render(body):
    return PAGE.format(body=body).encode()


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body, status=200, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # VULN: no security headers (CSP, X-Frame-Options, etc.)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    # ----- GET -------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self.page_home()
        elif path == "/quiz":
            self.page_quiz()
        elif path == "/leaderboard":
            self.page_leaderboard()
        elif path == "/login":
            self.page_login()
        elif path == "/admin":
            self.page_admin()
        elif path == "/search":
            self.page_search(qs)
        elif path == "/api/users":
            self.api_users()
        else:
            self._send(render("<p>404 Not Found</p>"), status=404)

    # ----- POST ------------------------------------------------------------
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        path = urllib.parse.urlparse(self.path).path

        if path == "/login":
            self.do_login(form)
        elif path == "/submit":
            self.do_submit(form)
        else:
            self._send(render("<p>404 Not Found</p>"), status=404)

    # ----- Pages -----------------------------------------------------------
    def page_home(self):
        user = current_user(self.headers)
        who = f"<p>Logged in as <b>{html.escape(user['username'])}</b>.</p>" if user else "<p>Not logged in.</p>"
        body = f"""
        <h1>Welcome to the Quiz App</h1>
        {who}
        <p>This is a small demo quiz application. Try the
        <a href="/quiz">quiz</a>, then check the
        <a href="/leaderboard">leaderboard</a>.</p>
        <div class="card">
          <h3>Search questions</h3>
          <form action="/search" method="get">
            <input name="q" placeholder="keyword...">
            <button>Search</button>
          </form>
        </div>"""
        self._send(render(body))

    def page_quiz(self):
        rows = db().execute("SELECT * FROM questions ORDER BY id").fetchall()
        items = []
        for q in rows:
            items.append(f"""
            <div class="card">
              <p><b>Q{q['id']}. {html.escape(q['prompt'])}</b></p>
              <label><input type="radio" name="q{q['id']}" value="a"> {html.escape(q['option_a'])}</label><br>
              <label><input type="radio" name="q{q['id']}" value="b"> {html.escape(q['option_b'])}</label><br>
              <label><input type="radio" name="q{q['id']}" value="c"> {html.escape(q['option_c'])}</label><br>
              <label><input type="radio" name="q{q['id']}" value="d"> {html.escape(q['option_d'])}</label>
            </div>""")
        # VULN: no CSRF token on this state-changing form
        body = f"""
        <h1>Quiz</h1>
        <form action="/submit" method="post">
          {''.join(items)}
          <div class="card">
            <label>Your name: <input name="username" value="guest"></label><br><br>
            <label>Leave a comment:<br>
              <input name="comment" style="width:100%" placeholder="Good quiz!"></label>
          </div>
          <button type="submit">Submit answers</button>
        </form>"""
        self._send(render(body))

    def page_leaderboard(self):
        rows = db().execute("SELECT username, score, comment FROM scores ORDER BY score DESC, id DESC LIMIT 50").fetchall()
        if not rows:
            inner = "<p>No scores yet — be the first!</p>"
        else:
            lines = []
            for r in rows:
                # VULN: stored XSS — comment is inserted into HTML without escaping
                lines.append(
                    f"<tr><td>{html.escape(r['username'])}</td>"
                    f"<td>{r['score']}</td>"
                    f"<td>{r['comment'] or ''}</td></tr>"
                )
            inner = ("<table border='1' cellpadding='6'>"
                     "<tr><th>User</th><th>Score</th><th>Comment</th></tr>"
                     + "".join(lines) + "</table>")
        self._send(render(f"<h1>Leaderboard</h1>{inner}"))

    def page_login(self):
        body = """
        <h1>Login</h1>
        <form action="/login" method="post">
          <p><input name="username" placeholder="username"></p>
          <p><input name="password" type="password" placeholder="password"></p>
          <button type="submit">Log in</button>
        </form>
        <p style="color:#888">Demo accounts: admin/admin123, student/password</p>"""
        self._send(render(body))

    def page_admin(self):
        user = current_user(self.headers)
        # VULN: broken access control — only checks that *some* user is logged
        #       in, not that they are an admin. Any logged-in user sees this,
        #       and the session id is forgeable anyway.
        if not user:
            self._send(render("<p>Please <a href='/login'>log in</a> first.</p>"), status=403)
            return
        rows = db().execute("SELECT id, username, password, is_admin FROM users").fetchall()
        lines = "".join(
            f"<tr><td>{r['id']}</td><td>{html.escape(r['username'])}</td>"
            f"<td>{html.escape(r['password'])}</td><td>{r['is_admin']}</td></tr>"
            for r in rows
        )
        body = f"""
        <h1>Admin panel</h1>
        <p>All users (passwords shown in plaintext — yikes):</p>
        <table border='1' cellpadding='6'>
          <tr><th>ID</th><th>Username</th><th>Password</th><th>Admin?</th></tr>
          {lines}
        </table>"""
        self._send(render(body))

    def page_search(self, qs):
        q = qs.get("q", [""])[0]
        conn = db()
        # VULN: SQL injection — user input concatenated directly into the query.
        #       Try:  /search?q=x' OR '1'='1
        sql = ("SELECT id, prompt FROM questions WHERE prompt LIKE '%" + q + "%'")
        try:
            rows = conn.execute(sql).fetchall()
            results = "".join(
                f"<li>Q{r['id']}: {html.escape(r['prompt'])}</li>" for r in rows
            ) or "<li>No matches.</li>"
        except Exception as e:
            results = f"<li>SQL error: {html.escape(str(e))}</li>"  # VULN: leaks DB errors
        # VULN: reflected XSS — the raw query is echoed back into the page
        body = f"""
        <h1>Search results for: {q}</h1>
        <ul>{results}</ul>
        <p><a href="/">Back</a></p>"""
        self._send(render(body))

    def api_users(self):
        # VULN: unauthenticated API leaks the full user table including passwords
        rows = db().execute("SELECT id, username, password, is_admin FROM users").fetchall()
        data = [dict(r) for r in rows]
        self._send(json.dumps(data, indent=2), content_type="application/json")

    # ----- Actions ---------------------------------------------------------
    def do_login(self, form):
        username = form.get("username", "")
        password = form.get("password", "")
        conn = db()
        # VULN: SQL injection in auth — login bypass with:
        #       username:  admin'--      password: anything
        sql = (f"SELECT * FROM users WHERE username = '{username}' "
               f"AND password = '{password}'")
        try:
            row = conn.execute(sql).fetchone()
        except Exception as e:
            self._send(render(f"<p>Login error: {html.escape(str(e))}</p>"), status=500)
            return
        if row:
            sid = row["username"]  # VULN: predictable session id
            SESSIONS[sid] = dict(row)
            self._send(
                render(f"<p>Welcome, {html.escape(row['username'])}! "
                       f"<a href='/'>Home</a></p>"),
                extra_headers={"Set-Cookie": f"sid={sid}; Path=/"},  # VULN: no HttpOnly/Secure/SameSite
            )
        else:
            self._send(render("<p>Invalid credentials. <a href='/login'>Try again</a></p>"), status=401)

    def do_submit(self, form):
        rows = db().execute("SELECT id, correct FROM questions").fetchall()
        score = sum(1 for q in rows if form.get(f"q{q['id']}") == q["correct"])
        username = form.get("username", "guest")
        comment = form.get("comment", "")
        conn = db()
        # Parameterized here (good!) — but `comment` is later rendered unescaped.
        conn.execute(
            "INSERT INTO scores (username, score, comment) VALUES (?, ?, ?)",
            (username, score, comment),
        )
        conn.commit()
        body = f"""
        <h1>Results</h1>
        <p>You scored <b>{score}</b> out of {len(rows)}.</p>
        <p><a href="/leaderboard">See the leaderboard</a></p>"""
        self._send(render(body))

    def log_message(self, fmt, *args):
        # Quieter logging
        return


def main():
    init_db()
    print(f"Quiz app running at http://{HOST}:{PORT}")
    print("⚠️  Intentionally insecure — run locally only. Ctrl+C to stop.")
    server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
