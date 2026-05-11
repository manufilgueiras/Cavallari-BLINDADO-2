from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, abort, make_response, flash
from markupsafe import escape
import os
import json
import sqlite3
from datetime import datetime, timezone

app = Flask(__name__)


app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self';"
    return response


USERS = {
    "admin": {"password": generate_password_hash("KicksBranco1803"), "role": "administrator"},
    "analista": {"password": generate_password_hash("PedroMetido1808"), "role": "security_analyst"},
}

REPORTS = {
    1: {"owner": "Equipe Alpha", "title": "Relatório Interno 01", "content": "Checklist de exposição de portas e serviços."},
    2: {"owner": "Equipe Beta", "title": "Relatório Interno 02", "content": "Não deixar diretórios sensíveis acessíveis."},
    3: {"owner": "Equipe Gama", "title": "Relatório Interno 03", "content": "Evitar credenciais padrão em produção."},
}

USERS_FILE = os.path.join(app.root_path, "users.json")

def seed_users_file():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(USERS, f, ensure_ascii=False, indent=2)

def load_users():
    seed_users_file()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

ACCESS_DB_PATH = os.path.join(app.root_path, "access_logs.db")
DATA_DB_PATH = os.path.join(app.root_path, "corp_data.db")

def get_data_connection():
    conn = sqlite3.connect(DATA_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(ACCESS_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_agent TEXT,
            path TEXT,
            method TEXT,
            consent INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "desconhecido"

@app.before_request
def register_access():
    if request.path.startswith("/static/"):
        return
    consent = 1 if request.cookies.get("anchieta_cookie_consent") == "accepted" else 0
    conn = sqlite3.connect(ACCESS_DB_PATH)
    conn.execute(
        "INSERT INTO access_log (ip, user_agent, path, method, consent, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            get_client_ip(),
            request.headers.get("User-Agent", "")[:300],
            request.path,
            request.method,
            consent,
            datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        ),
    )
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    news = [
        {"title": "Laboratório Anchieta v2.6 liberado", "tag": "NOVO"},
        {"title": "Painel interno com métricas em tempo real", "tag": "LAB"},
        {"title": "Documentos históricos preservados para auditoria", "tag": "INFO"},
    ]
    return render_template("index.html", news=news)

@app.route("/search")
def search():
    q = request.args.get("q", "").lower()
    sample = ["Mapa de rede local", "Checklist de auditoria", "Documentação do portal"]
    

    prova_result = None
    if "ajuda" in q:
        prova_result = {"title": "Suporte", "content": "Consulte o manual administrativo."}
        
    return render_template("search.html", q=q, sample=sample, prova=prova_result)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    error = None
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        users = load_users()
        if user in users and check_password_hash(users[user]["password"], pwd):
            session["user"] = user
            return redirect(url_for("dashboard"))
        error = "Credenciais inválidas."
    return render_template("admin.html", error=error)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("admin"))
    users = load_users()
    return render_template("dashboard.html", user=session["user"], role=users[session["user"]]["role"])

@app.route("/records")
def records():
    if "user" not in session:
        return redirect(url_for("admin"))
    conn = get_data_connection()
    employees = conn.execute("SELECT * FROM employees ORDER BY id").fetchall()
    conn.close()
    return render_template("records.html", employees=employees)

@app.route("/tickets")
def tickets():
    if "user" not in session:
        return redirect(url_for("admin"))
    conn = get_data_connection()
    tickets = conn.execute("SELECT * FROM support_tickets ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("tickets.html", tickets=tickets)

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("admin"))
    # Segurança IDOR: Idealmente aqui validaríamos se o ID pertence ao logado
    user_id = request.args.get("id", "1")
    profiles = {
        "1": {"name": "Equipe Alpha", "sector": "SOC", "email": "alpha@anchieta.lab"},
        "2": {"name": "Equipe Beta", "sector": "Blue Team", "email": "beta@anchieta.lab"},
    }
    profile = profiles.get(user_id, profiles["1"])
    return render_template("profile.html", profile=profile, user_id=user_id)


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada com sucesso.", "success")
    return redirect(url_for("index"))

@app.route("/access_log")
def access_log():
    if "user" not in session:
        return redirect(url_for("admin"))
    conn = sqlite3.connect(ACCESS_DB_PATH)
    rows = conn.execute("SELECT ip, user_agent, path, method, consent, created_at FROM access_log ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    logs = [{"ip": r[0], "user_agent": r[1], "path": r[2], "method": r[3], "consent": r[4], "created_at": r[5]} for r in rows]
    return render_template("access_log.html", logs=logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)