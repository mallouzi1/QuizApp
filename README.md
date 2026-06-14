# Quiz App (intentionally insecure — for security education)

A tiny multiple-choice quiz web app written in pure Python (standard library
only — no `pip install` needed). It is **deliberately insecure** and is meant
to be used the way [OWASP WebGoat](https://owasp.org/www-project-webgoat/) or
[DVWA](https://github.com/digininja/DVWA) are: as a safe target for learning
and teaching common web-application vulnerabilities.

> **Do not deploy this on a public server or use it with real data.**
> Run it only on your local machine or an isolated lab network.

## Run it

```bash
python3 app.py
```

Then open <http://127.0.0.1:8000>.

Demo accounts:

| username | password   | role  |
|----------|------------|-------|
| admin    | admin123   | admin |
| student  | password   | user  |

## What it does

- Take a multiple-choice quiz and get scored.
- Leave a name + comment that show up on a leaderboard.
- Log in; an "admin" panel lists users.
- Search questions by keyword.

## Intentional vulnerabilities (the teaching points)

Every weakness is tagged in `app.py` with a `# VULN:` comment. Search the file
for `VULN` to find them all.

| # | Vulnerability | Where | Try it |
|---|---------------|-------|--------|
| 1 | **SQL injection** (search) | `page_search` | `/search?q=x' OR '1'='1` |
| 2 | **SQL injection / auth bypass** | `do_login` | username `admin'--`, any password |
| 3 | **Reflected XSS** | `page_search` | `/search?q=<script>alert(1)</script>` |
| 4 | **Stored XSS** | `do_submit` → `page_leaderboard` | comment `<script>alert(1)</script>` |
| 5 | **Plaintext passwords** | `users` table | see `/admin` or `/api/users` |
| 6 | **Broken access control** | `page_admin` | any logged-in user reaches admin |
| 7 | **Forgeable session** | `do_login` | session id = username; set `sid=admin` cookie |
| 8 | **Insecure cookie flags** | `do_login` | no `HttpOnly` / `Secure` / `SameSite` |
| 9 | **Sensitive data exposure** | `api_users` | `GET /api/users` dumps all credentials |
| 10 | **No CSRF protection** | quiz/submit forms | state change with no token |
| 11 | **Verbose error leakage** | SQL handlers | DB errors echoed to the user |
| 12 | **Missing security headers** | `_send` | no CSP, X-Frame-Options, etc. |

## Suggested exercises

For each item above:
1. Reproduce the vulnerability.
2. Explain the root cause and impact.
3. Fix it (e.g. parameterized queries, output escaping, password hashing with
   `hashlib`/`bcrypt`, real session tokens, role checks, CSRF tokens, security
   headers) and verify the exploit no longer works.

## License

MIT — see [LICENSE](LICENSE). Provided for educational use, with no warranty.
