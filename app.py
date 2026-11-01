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
ACTIVE_INN = None
ACTIVE_SESSION = None
ACTIVE_STAGE = None
ACTIVE_LAST_SEEN = 0.0
ACTIVE_LOCK_REQUIRED = False
ACTIVE_ONLINE = False


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
    global ACTIVE_INN, ACTIVE_SESSION, ACTIVE_STAGE, ACTIVE_LAST_SEEN, ACTIVE_LOCK_REQUIRED, ACTIVE_ONLINE
    data = request.get_json(silent=True) or {}
    inn = str(data.get("inn", "")).strip()
    email = str(data.get("email", "")).strip()
    if not email_format_valid(email):
        return jsonify({"error": "Введите email в корректном формате, например name@example.com."}), 400
    if not inn or len(inn) > 20:
        return jsonify({"error": "Введите ИНН."}), 400

    session_id = secrets.token_urlsafe(32)
    with LOCK:
        # Активный браузерный диалог блокирует вход любого второго клиента,
        # в том числе с тем же ИНН (иначе можно открыть две параллельные вкладки).
        # Таймаут используется только как аварийное освобождение зависшей вкладки.
        if ACTIVE_ONLINE and time.time() - ACTIVE_LAST_SEEN > 30:
            ACTIVE_ONLINE = False
            ACTIVE_SESSION = None
            if not ACTIVE_LOCK_REQUIRED:
                ACTIVE_INN = ACTIVE_STAGE = None
                ACTIVE_LAST_SEEN = 0.0

        if ACTIVE_ONLINE:
            return jsonify({"ok": True, "busy": True,
                            "message": "Сейчас обслуживается другой клиент. Пожалуйста, подождите, пока его заказ будет завершён."}), 202

        # После выхода клиента блокировка остаётся, если заказ уже перешёл
        # к отправке счёта/договора или ожидает внешнего подтверждения.
        # В таком состоянии повторный вход разрешён только с тем же ИНН.
        if ACTIVE_LOCK_REQUIRED and ACTIVE_INN and ACTIVE_INN != inn:
            return jsonify({"ok": True, "busy": True,
                            "message": "Сейчас обслуживается другой клиент. Его заказ ещё не завершён. Пожалуйста, подождите."}), 202

        ACTIVE_INN, ACTIVE_SESSION, ACTIVE_STAGE = inn, session_id, "checking_inn"
        ACTIVE_LAST_SEEN = time.time()
        ACTIVE_ONLINE = True
        # Не сбрасываем ACTIVE_LOCK_REQUIRED при повторном входе того же ИНН.
        SESSIONS[session_id] = {"session_id": session_id, "inn": inn, "email": email,
                                "login_status": "checking", "workflow_status": "checking_inn",
                                "stage": "checking_inn", "events": [], "created": time.time()}
        COMMANDS.append({"type": "login_validate", "session_id": session_id,
                         "inn": inn, "email": email})
    return jsonify({"ok": True, "session_id": session_id}), 202

@app.get("/api/session/<session_id>")
def get_session(session_id):
    global ACTIVE_LAST_SEEN, ACTIVE_ONLINE
    with LOCK:
        session = SESSIONS.get(session_id)
        if session and ACTIVE_SESSION == session_id:
            ACTIVE_LAST_SEEN = time.time()
            ACTIVE_ONLINE = True
        if not session:
            return jsonify({"error": "session_not_found", "message": "Сессия истекла. Обновите страницу и войдите снова."}), 404
        response_session = {k: v for k, v in session.items() if k != "created"}
        if ACTIVE_SESSION != session_id and response_session.get("login_status") not in {"invalid", "busy"}:
            response_session["login_status"] = "busy"
            response_session["workflow_status"] = "busy"
            response_session["stage"] = "busy"
            response_session["events"] = [{
                "id": f"inactive-{session_id}", "agent": "secretary",
                "text": "Эта сессия больше не активна. Сейчас обслуживается другой клиент или требуется повторный вход.",
                "kind": "warning", "speak": False, "created_at": None,
            }]
        return jsonify(response_session)


@app.post("/api/logout/<session_id>")
def logout(session_id):
    global ACTIVE_INN, ACTIVE_SESSION, ACTIVE_STAGE, ACTIVE_LAST_SEEN, ACTIVE_LOCK_REQUIRED, ACTIVE_ONLINE
    with LOCK:
        session = SESSIONS.get(session_id)
        if session and ACTIVE_SESSION == session_id:
            ACTIVE_ONLINE = False
            ACTIVE_SESSION = None
            ACTIVE_LAST_SEEN = 0.0
            # До отправки платёжного письма незавершённый черновик не блокирует
            # следующего клиента. После начала отправки письма блокировка остаётся.
            if not ACTIVE_LOCK_REQUIRED or ACTIVE_STAGE in {"invalid", "busy"}:
                ACTIVE_INN = ACTIVE_STAGE = None
                ACTIVE_LOCK_REQUIRED = False
    return jsonify({"ok": True})

@app.post("/api/session/<session_id>/command")
def send_command(session_id):
    global ACTIVE_STAGE
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text or len(text) > 4000:
        return jsonify({"error": "Команда пустая или слишком длинная."}), 400
    with LOCK:
        session = SESSIONS.get(session_id)
        if not session:
            return jsonify({"error": "Сессия не найдена. Обновите страницу и войдите снова."}), 404
        if ACTIVE_SESSION != session_id or not ACTIVE_ONLINE:
            return jsonify({"error": "Эта сессия больше не активна. Обновите страницу и войдите снова."}), 409
        if session["login_status"] != "valid":
            return jsonify({"error": "Сначала необходимо пройти проверку ИНН."}), 403
        if session.get("workflow_status") == "invalid":
            return jsonify({"error": "Сессия заблокирована."}), 403
        # Проверяем одновременно и статус, и точный этап. Нельзя отправить
        # сообщение во время работы агентов, ожидания письма/оплаты/подписи,
        # паузы после ошибки или на любом другом этапе.
        current_stage = session.get("stage")
        current_status = session.get("workflow_status")
        allowed_input = (
            (current_stage == "ready" and current_status == "ready")
            or (current_stage == "completed" and current_status == "completed")
            or (current_stage == "awaiting_items_confirmation" and current_status == "waiting_user")
        )
        if not allowed_input:
            return jsonify({"error": "Сейчас система не ожидает ответа. Дождитесь вопроса секретаря или бухгалтера."}), 409
        session["workflow_status"] = "working"
        session["stage"] = "processing_parse"
        if ACTIVE_SESSION == session_id:
            ACTIVE_STAGE = "processing_parse"
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
    global ACTIVE_INN, ACTIVE_SESSION, ACTIVE_STAGE, ACTIVE_LAST_SEEN, ACTIVE_LOCK_REQUIRED, ACTIVE_ONLINE
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
            if ACTIVE_SESSION == session_id:
                ACTIVE_STAGE = data["stage"]
        if "lock_required" in data and ACTIVE_SESSION == session_id:
            ACTIVE_LOCK_REQUIRED = bool(data["lock_required"])
        if data.get("login_status") in {"invalid", "busy"} and ACTIVE_SESSION == session_id:
            ACTIVE_INN = ACTIVE_SESSION = ACTIVE_STAGE = None
            ACTIVE_LAST_SEEN = 0.0
            ACTIVE_LOCK_REQUIRED = False
            ACTIVE_ONLINE = False
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
