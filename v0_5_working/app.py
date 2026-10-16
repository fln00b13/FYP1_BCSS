from flask import Flask, request, render_template_string
import sqlite3
import html

app = Flask(__name__)
DB_PATH = "lab.db"

HOME = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>FPTK Local Test Lab</title>
<style>body{font:16px/1.5 system-ui;max-width:900px;margin:40px auto;padding:0 20px;color:#18212f}code{background:#f1f3f5;padding:2px 5px;border-radius:4px}.card{border:1px solid #d9dee7;border-radius:10px;padding:16px;margin:12px 0} .warn{color:#8a4b00}</style></head><body>
<h1>FPTK — Local Test Lab</h1>
<p>This intentionally small application contains known test conditions for your scanner.</p>
<div class="card"><h2>SQL injection test routes</h2><ul>
<li><a href="/lab/sqli/vulnerable?term=alice">Vulnerable SQL query</a></li>
<li><a href="/lab/sqli/secure?term=alice">Parameterized SQL query</a></li>
<li><a href="/lab/sqli/noisy?term=alice">Secure route with a generic database-related message</a></li></ul></div>
<div class="card"><h2>Input reflection test routes</h2><ul>
<li><a href="/lab/xss/vulnerable?term=hello">Raw reflection (unsafe output handling)</a></li>
<li><a href="/lab/xss/secure?term=hello">HTML-escaped reflection</a></li></ul></div>
<p class="warn"><strong>Local lab only:</strong> these deliberately vulnerable examples are for learning. Keep this server bound to 127.0.0.1 and do not deploy it publicly.</p>
</body></html>
"""


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL)")
    conn.execute("INSERT OR IGNORE INTO users(id, username) VALUES (1, 'alice'), (2, 'bob')")
    conn.commit()
    return conn


@app.route("/")
def home():
    return render_template_string(HOME)


@app.route("/lab/sqli/vulnerable")
def sqli_vulnerable():
    term = request.args.get("term", "")
    conn = connect_db()
    try:
        # INTENTIONALLY VULNERABLE: used only in this local training lab.
        query = "SELECT username FROM users WHERE username = '" + term + "'"
        rows = conn.execute(query).fetchall()
        return {"route": "sqli-vulnerable", "matches": [r[0] for r in rows]}
    except sqlite3.Error as exc:
        return {"route": "sqli-vulnerable", "error": str(exc)}, 400
    finally:
        conn.close()


@app.route("/lab/sqli/secure")
def sqli_secure():
    term = request.args.get("term", "")
    conn = connect_db()
    try:
        rows = conn.execute("SELECT username FROM users WHERE username = ?", (term,)).fetchall()
        return {"route": "sqli-secure", "matches": [r[0] for r in rows]}
    finally:
        conn.close()


@app.route("/lab/sqli/noisy")
def sqli_noisy():
    # Secure implementation, deliberately contains generic words that a weak
    # keyword-only scanner might mistake for a database error.
    return {"message": "Database request completed; no error occurred.", "results": []}


@app.route("/lab/xss/vulnerable")
def xss_vulnerable():
    term = request.args.get("term", "")
    # INTENTIONALLY UNSAFE OUTPUT HANDLING for local scanner testing.
    return f"<!doctype html><html><body><h1>Search result</h1><div id='result'>{term}</div></body></html>"


@app.route("/lab/xss/secure")
def xss_secure():
    term = request.args.get("term", "")
    return f"<!doctype html><html><body><h1>Search result</h1><div id='result'>{html.escape(term)}</div></body></html>"


# Additional SQL injection test routes

@app.route("/lab/sqli/vulnerable-prefix")
def sqli_vulnerable_prefix():
    term = request.args.get("term", "")
    conn = connect_db()
    try:
        # Intentionally vulnerable: user input is inserted into SQL.
        query = (
            "SELECT username FROM users "
            "WHERE username LIKE '%" + term + "%'"
        )
        rows = conn.execute(query).fetchall()
        return {
            "route": "sqli-vulnerable-prefix",
            "matches": [row[0] for row in rows],
        }
    except sqlite3.Error as exc:
        return {"route": "sqli-vulnerable-prefix", "error": str(exc)}, 400
    finally:
        conn.close()


@app.route("/lab/sqli/secure-prefix")
def sqli_secure_prefix():
    term = request.args.get("term", "")
    conn = connect_db()
    try:
        # Secure counterpart: parameterized query.
        rows = conn.execute(
            "SELECT username FROM users WHERE username LIKE ?",
            (f"%{term}%",),
        ).fetchall()
        return {
            "route": "sqli-secure-prefix",
            "matches": [row[0] for row in rows],
        }
    finally:
        conn.close()


@app.route("/lab/sqli/secure-error")
def sqli_secure_error():
    # Secure route with database-related wording.
    # Useful for testing whether keyword-only rules produce false positives.
    return {
        "message": "Database query completed; SQL error count: 0.",
        "results": [],
    }


# Additional XSS test routes

@app.route("/lab/xss/vulnerable-attribute")
def xss_vulnerable_attribute():
    term = request.args.get("term", "")
    # Intentionally unsafe: input is inserted into an HTML attribute.
    return (
        "<!doctype html><html><body>"
        f'<input id="search" value="{term}">'
        "</body></html>"
    )


@app.route("/lab/xss/secure-attribute")
def xss_secure_attribute():
    term = request.args.get("term", "")
    # Escape HTML special characters, including quotation marks.
    safe_term = html.escape(term, quote=True)
    return (
        "<!doctype html><html><body>"
        f'<input id="search" value="{safe_term}">'
        "</body></html>"
    )


@app.route("/lab/xss/no-reflection")
def xss_no_reflection():
    # Secure control case: accept input but do not return it in the response.
    return (
        "<!doctype html><html><body>"
        "<h1>Search completed</h1>"
        "<p>No search term is displayed.</p>"
        "</body></html>"
    )

if __name__ == "__main__":
    # Bind to loopback only. Do not change to 0.0.0.0 for this lab.
    app.run(host="127.0.0.1", port=5000, debug=False)
