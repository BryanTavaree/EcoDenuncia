import os
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import (
    Flask, jsonify, request, session, send_from_directory,
    redirect, url_for, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ecodenuncia.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_PAGES = {
    "index.html", "sobre.html", "informacoes.html", "nova_denuncia.html",
    "continuar_denuncia.html", "confirmar_denuncia.html", "login.html",
    "cadastro.html", "esqueceu_senha.html", "mapa.html",
    "minhas_denuncias.html", "detalhes_denuncia.html", "perfil.html",
}
ALLOWED_ASSETS = {".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico"}

app = Flask(__name__)
app.secret_key = os.environ.get("ECODENUNCIA_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # até 5 MB por requisição
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            senha_hash TEXT NOT NULL,
            criado_em TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS denuncias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocolo TEXT NOT NULL UNIQUE,
            usuario_id INTEGER NULL,
            tipo TEXT NOT NULL,
            local TEXT NOT NULL,
            descricao TEXT NOT NULL,
            foto_arquivo TEXT NULL,
            modo TEXT NOT NULL CHECK (modo IN ('anonima', 'conta')),
            status TEXT NOT NULL DEFAULT 'Recebida',
            criada_em TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL

        );

        CREATE TABLE IF NOT EXISTS recuperacoes_senha (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expira_em REAL NOT NULL,
    usado_em REAL NULL,
    FOREIGN KEY (usuario_id)
        REFERENCES usuarios(id) ON DELETE CASCADE
); 
        """)


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def current_user():
    user_id = session.get("usuario_id")
    if not user_id:
        return None
    with get_db() as db:
        row = db.execute(
            "SELECT id, nome, email, criado_em FROM usuarios WHERE id = ?",
            (user_id,)
        ).fetchone()
    return dict(row) if row else None


def login_required_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("usuario_id"):
            return jsonify({"erro": "Faça login para acessar este recurso."}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/<path:filename>")
def existing_files(filename):
    # Só entrega páginas HTML conhecidas e arquivos estáticos; não expõe o banco nem app.py.
    if filename in ALLOWED_PAGES and (BASE_DIR / filename).is_file():
        return send_from_directory(BASE_DIR, filename)
    path = Path(filename)
    if len(path.parts) == 1 and path.suffix.lower() in ALLOWED_ASSETS:
        if (BASE_DIR / filename).is_file():
            return send_from_directory(BASE_DIR, filename)
    abort(404)


@app.get("/api/status")
def api_status():
    return jsonify({"ok": True, "mensagem": "EcoDenúncia backend está funcionando."})


@app.post("/api/cadastro")
def api_cadastro():
    data = request.get_json(silent=True) or request.form
    nome = str(data.get("nome", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    senha = str(data.get("senha", data.get("password", "")))

    if not nome or not email or not senha:
        return jsonify({"erro": "Informe nome, e-mail e senha."}), 400
    if len(senha) < 8:
        return jsonify({"erro": "A senha deve ter pelo menos 8 caracteres."}), 400

    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, criado_em) VALUES (?, ?, ?, ?)",
                (nome, email, generate_password_hash(senha), now_iso())
            )
            user_id = cur.lastrowid
        session["usuario_id"] = user_id
        return jsonify({"ok": True, "usuario": {"id": user_id, "nome": nome, "email": email}}), 201
    except sqlite3.IntegrityError:
        return jsonify({"erro": "Já existe uma conta com esse e-mail."}), 409


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or request.form
    email = str(data.get("email", "")).strip().lower()
    senha = str(data.get("senha", data.get("password", "")))
    with get_db() as db:
        user = db.execute(
            "SELECT id, nome, email, senha_hash FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()
    if not user or not check_password_hash(user["senha_hash"], senha):
        return jsonify({"erro": "E-mail ou senha incorretos."}), 401
    session["usuario_id"] = user["id"]
    return jsonify({"ok": True, "usuario": {"id": user["id"], "nome": user["nome"], "email": user["email"]}})

# Recuperação de senha para desenvolvimento local.
# IMPORTANTE: não exponha o token pela API em produção.
RECOVERY_DEV_MODE = True


@app.post("/api/recuperar-senha")
def api_recuperar_senha():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email:
        return jsonify({"erro": "Informe o e-mail cadastrado."}), 400

    resposta = {
        "ok": True,
        "mensagem": (
            "Se o e-mail estiver cadastrado, será possível "
            "prosseguir com a recuperação."
        )
    }

    with get_db() as db:
        user = db.execute(
            "SELECT id FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()

        if not user:
            return jsonify(resposta)

        # Invalida tokens anteriores ainda não utilizados.
        db.execute("""
            UPDATE recuperacoes_senha
            SET usado_em = ?
            WHERE usuario_id = ? AND usado_em IS NULL
        """, (time.time(), user["id"]))

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        # O token expira em 15 minutos.
        db.execute("""
            INSERT INTO recuperacoes_senha
            (usuario_id, token_hash, expira_em, usado_em)
            VALUES (?, ?, ?, NULL)
        """, (
            user["id"],
            token_hash,
            time.time() + 900
        ))

    # Somente para testes no computador local.
    # Em produção, o token deve ser enviado por e-mail.
    if RECOVERY_DEV_MODE:
        resposta["token_desenvolvimento"] = token

    return jsonify(resposta)


@app.post("/api/redefinir-senha")
def api_redefinir_senha():
    data = request.get_json(silent=True) or {}

    token = str(data.get("token", "")).strip()
    senha = str(data.get("senha", ""))

    if not token or not senha:
        return jsonify({
            "erro": "Informe o token e a nova senha."
        }), 400

    if len(senha) < 8:
        return jsonify({
            "erro": "A nova senha deve ter pelo menos 8 caracteres."
        }), 400

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    agora = time.time()

    with get_db() as db:
        recuperacao = db.execute("""
            SELECT id, usuario_id
            FROM recuperacoes_senha
            WHERE token_hash = ?
              AND usado_em IS NULL
              AND expira_em > ?
        """, (token_hash, agora)).fetchone()

        if not recuperacao:
            return jsonify({
                "erro": "Token inválido, expirado ou já utilizado."
            }), 400

        nova_senha_hash = generate_password_hash(senha)

        db.execute("""
            UPDATE usuarios
            SET senha_hash = ?
            WHERE id = ?
        """, (
            nova_senha_hash,
            recuperacao["usuario_id"]
        ))

        db.execute("""
            UPDATE recuperacoes_senha
            SET usado_em = ?
            WHERE id = ? AND usado_em IS NULL
        """, (agora, recuperacao["id"]))

    # Encerra a sessão atual após redefinir a senha.
    session.clear()

    return jsonify({
        "ok": True,
        "mensagem": "Senha redefinida com sucesso. Faça login novamente."
    })


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def api_me():
    user = current_user()
    return jsonify({"autenticado": bool(user), "usuario": user})


@app.post("/api/denuncias")
def api_criar_denuncia():
    # JSON ou formulário multipart; anonymous reports are not linked to a user.
    data = request.form if request.form else (request.get_json(silent=True) or {})
    tipo = str(data.get("tipo", "")).strip()
    local = str(data.get("local", "")).strip()
    descricao = str(data.get("descricao", "")).strip()
    modo = str(data.get("modo", "anonima")).strip().lower()

    if not tipo or not local or not descricao:
        return jsonify({"erro": "Preencha tipo, local e descrição."}), 400
    if modo not in ("anonima", "conta"):
        return jsonify({"erro": "Modo de denúncia inválido."}), 400

    user = current_user()
    if modo == "conta" and not user:
        return jsonify({"erro": "Entre na sua conta para enviar uma denúncia identificada."}), 401

    foto_arquivo = None
    photo = request.files.get("foto")
    if photo and photo.filename:
        ext = Path(photo.filename).suffix.lower()
        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
            return jsonify({"erro": "A foto deve estar em JPG, PNG ou WEBP."}), 400
        safe_name = secure_filename(photo.filename)
        unique_name = f"{secrets.token_hex(12)}_{safe_name}"
        photo.save(UPLOAD_DIR / unique_name)
        foto_arquivo = unique_name

    protocolo = "ED-" + secrets.token_hex(4).upper()
    usuario_id = user["id"] if modo == "conta" and user else None

    with get_db() as db:
        db.execute("""
            INSERT INTO denuncias
            (protocolo, usuario_id, tipo, local, descricao, foto_arquivo, modo, status, criada_em)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Recebida', ?)
        """, (protocolo, usuario_id, tipo, local, descricao, foto_arquivo, modo, now_iso()))

    return jsonify({
        "ok": True, "protocolo": protocolo, "status": "Recebida",
        "modo": modo, "foto_salva": bool(foto_arquivo)
    }), 201


@app.get("/api/denuncias")
@login_required_json
def api_minhas_denuncias():
    user_id = session["usuario_id"]
    with get_db() as db:
        rows = db.execute("""
            SELECT protocolo, tipo, local, descricao, modo, status, criada_em, foto_arquivo
            FROM denuncias WHERE usuario_id = ? ORDER BY id DESC
        """, (user_id,)).fetchall()
    return jsonify({"denuncias": [dict(row) for row in rows]})


@app.get("/api/denuncias/<protocolo>")
def api_detalhe_denuncia(protocolo):
    with get_db() as db:
        row = db.execute("""
            SELECT protocolo, tipo, local, descricao, modo, status, criada_em, foto_arquivo, usuario_id
            FROM denuncias WHERE protocolo = ?
        """, (protocolo,)).fetchone()
    if not row:
        return jsonify({"erro": "Denúncia não encontrada."}), 404

    # Details are only returned to the account that owns an identified report.
    # Anonymous reports should be looked up later using a separate private protocol/token flow.
    user = current_user()
    if row["modo"] == "conta" and (not user or user["id"] != row["usuario_id"]):
        return jsonify({"erro": "Você não tem permissão para ver esta denúncia."}), 403

    result = dict(row)
    result.pop("usuario_id", None)
    return jsonify(result)


@app.get("/uploads/<path:filename>")
def uploaded_file(filename):
    # Evidence images are not exposed publicly by this route.
    # A protected evidence-view route will be added when the UI access rules are integrated.
    abort(404)


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"erro": "O arquivo enviado excede o limite de 5 MB."}), 413


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"erro": "Recurso não encontrado."}), 404
    return "Página não encontrada.", 404


init_db()

if __name__ == "__main__":
    print("EcoDenúncia iniciado. Abra http://127.0.0.1:5000")
    print("Para parar o servidor, pressione Ctrl+C.")
    app.run(host="127.0.0.1", port=5000, debug=True)
