"""Публичный веб-интерфейс и relay для Agent Voice Portal. Разворачивается на Render."""
import hmac
import os
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from flask import Flask, jsonify, request, Response, send_from_directory

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
API_SECRET = os.environ.get("RELAY_API_SECRET", "")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")

LOCK = threading.RLock()
COMMANDS = deque()
SESSIONS = {}
EMAIL_EVENTS = {}


def authorized():
    supplied = request.headers.get("X-Relay-Secret", "")
    return bool(API_SECRET) and hmac.compare_digest(supplied, API_SECRET)


def html_page(title, message, status=200):
    page = ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{title}</title><body style='font:16px system-ui;max-width:650px;margin:10vh auto;padding:20px'>"
            f"<h2>{title}</h2><p>{message}</p></body></html>")
    return Response(page, status=status, content_type="text/html; charset=utf-8",
                    headers={"Cache-Control": "no-store"})


@app.get("/")
def index():
    return send_from_directory(ROOT / "static", "index.html", max_age=0)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "agent-voice-portal"})


def email_format_valid(address):
    address = str(address or "").strip()
    return len(address) <= 254 and bool(EMAIL_RE.fullmatch(address))


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    inn = str(data.get("inn", "")).strip()
    email = str(data.get("email", "")).strip()
    if not email_format_valid(email):
        return jsonify({"error": "Введите email в корректном формате, например name@example.com."}), 400
    if not inn or len(inn) > 20:
        return jsonify({"error": "Введите ИНН."}), 400
    session_id = secrets.token_urlsafe(32)
    with LOCK:
        SESSIONS[session_id] = {
            "session_id": session_id, "inn": inn, "email": email,
            "login_status": "checking", "workflow_status": "checking_inn",
            "stage": "checking_inn", "events": [], "created": time.time(),
        }
        COMMANDS.append({"type": "login_validate", "session_id": session_id,
                         "inn": inn, "email": email})
    return jsonify({"ok": True, "session_id": session_id}), 202


@app.get("/api/session/<session_id>")
def get_session(session_id):
    with LOCK:
        session = SESSIONS.get(session_id)
        if not session:
            return jsonify({"error": "session_not_found", "message": "Сессия истекла. Обновите страницу и войдите снова."}), 404
        return jsonify({k: v for k, v in session.items() if k != "created"})


@app.post("/api/session/<session_id>/command")
def send_command(session_id):
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text or len(text) > 4000:
        return jsonify({"error": "Команда пустая или слишком длинная."}), 400
    with LOCK:
        session = SESSIONS.get(session_id)
        if not session:
            return jsonify({"error": "Сессия не найдена. Обновите страницу и войдите снова."}), 404
        if session["login_status"] != "valid":
            return jsonify({"error": "Сначала необходимо пройти проверку ИНН."}), 403
        if session.get("workflow_status") == "invalid":
            return jsonify({"error": "Сессия заблокирована."}), 403
        COMMANDS.append({"type": "user_message", "session_id": session_id,
                         "inn": session["inn"], "email": session["email"], "text": text})
    return jsonify({"ok": True, "queued": True}), 202


@app.post("/api/worker/next")
def worker_next():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    with LOCK:
        command = COMMANDS.popleft() if COMMANDS else None
    return jsonify({"command": command})


@app.post("/api/worker/publish")
def worker_publish():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    session_id = str(data.get("session_id", ""))
    with LOCK:
        session = SESSIONS.get(session_id)
        if not session:
            # Browser may have closed; local SQLite remains authoritative.
            return jsonify({"ok": True, "ignored": True})
        if "login_status" in data:
            session["login_status"] = data["login_status"]
        if "workflow_status" in data:
            session["workflow_status"] = data["workflow_status"]
        if "stage" in data:
            session["stage"] = data["stage"]
        known = {str(e.get("id")) for e in session["events"]}
        for event in data.get("events", []) or []:
            event_id = str(event.get("id", ""))
            if event_id not in known:
                session["events"].append(event)
                known.add(event_id)
        session["events"] = session["events"][-500:]
    return jsonify({"ok": True})


# Существующий одноразовый relay для кликов по ссылкам из писем.
@app.post("/api/register")
def register():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    purpose = data.get("purpose", "confirmation")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return jsonify({"error": "invalid token"}), 400
    with LOCK:
        EMAIL_EVENTS[token] = {"purpose": str(purpose)[:40], "clicked": False, "created": time.time()}
    return jsonify({"ok": True}), 201


@app.get("/action")
def action():
    token = request.args.get("token", "")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return html_page("Ссылка недействительна", "В ссылке отсутствует корректный токен.", 410)
    with LOCK:
        item = EMAIL_EVENTS.get(token)
        if not item or item["clicked"]:
            item = None
        else:
            item["clicked"] = True
            item["clicked_at"] = time.time()
    if item:
        return html_page("Подтверждение принято", "Действие зарегистрировано в учебной системе. Можно вернуться на сайт.")
    return html_page("Ссылка недействительна или уже использована", "Запрос не зарегистрирован. Вернитесь на сайт и проверьте состояние заказа.", 410)


@app.get("/api/status/<token>")
def status(token):
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    with LOCK:
        item = EMAIL_EVENTS.get(token)
        if not item:
            return jsonify({"error": "not found"}), 404
        return jsonify({"clicked": bool(item["clicked"]), "purpose": item["purpose"]})


@app.post("/api/finish/<token>")
def finish(token):
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    with LOCK:
        EMAIL_EVENTS.pop(token, None)
    return jsonify({"ok": True})


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not_found"}), 404
    return html_page("Страница не найдена", "Проверьте адрес.", 404)
