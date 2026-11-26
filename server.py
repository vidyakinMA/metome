import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import threading
from datetime import datetime

import websockets

# BASE_DIR — где лежит упакованный client.html (в exe это _MEIPASS-архив)
# APP_DIR  — папка рядом с программой: БД и личный звук уведомлений живут там,
#            чтобы сохранялись между запусками и файл звука можно было менять
IS_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))))
APP_DIR = os.path.dirname(os.path.abspath(sys.executable if IS_FROZEN else __file__))

DB_FILE = os.path.join(APP_DIR, "messenger.db")
HOST = "0.0.0.0"
HTTP_PORT = 8080
WS_PORT = 8081


# ========== БАЗА ДАННЫХ ==========
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            login TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            avatar TEXT NOT NULL DEFAULT '',
            friend_code TEXT UNIQUE,
            tg_author TEXT NOT NULL DEFAULT '',
            bio TEXT NOT NULL DEFAULT '',
            tag TEXT NOT NULL DEFAULT '',
            last_seen REAL NOT NULL DEFAULT 0,
            created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_codes (
            phone TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            is_group INTEGER NOT NULL DEFAULT 0,
            is_channel INTEGER NOT NULL DEFAULT 0,
            owner_id INTEGER NOT NULL DEFAULT 0,
            is_public INTEGER NOT NULL DEFAULT 0,
            invite TEXT,
            avatar TEXT NOT NULL DEFAULT '',
            bio TEXT NOT NULL DEFAULT '',
            is_saved INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chat_members (
            chat_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            PRIMARY KEY (chat_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'text',
            ts REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            media TEXT NOT NULL DEFAULT '',
            caption TEXT NOT NULL DEFAULT '',
            ts REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            mime TEXT NOT NULL DEFAULT '',
            data BLOB NOT NULL,
            ts REAL NOT NULL
        );
        """
    )
    # миграция: добавляем колонки профиля, если их ещё нет (для существующих баз)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "avatar" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
    if "friend_code" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN friend_code TEXT")
    if "tg_author" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN tg_author TEXT NOT NULL DEFAULT ''")
    if "last_seen" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_seen REAL NOT NULL DEFAULT 0")
    if "bio" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''")
    if "tag" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN tag TEXT NOT NULL DEFAULT ''")
    if "email" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "login" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN login TEXT")
    # для существующих пользователей подставляем login из name (если пусто)
    conn.execute("UPDATE users SET login = name WHERE login IS NULL OR login = ''")
    # таблица сессий (запомнить меня)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires INTEGER NOT NULL
        );"""
    )
    # отношения между пользователями: блокировка, беззвучный, контакт
    conn.execute(
        """CREATE TABLE IF NOT EXISTS user_relations (
            user_id INTEGER NOT NULL,
            other_id INTEGER NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            muted INTEGER NOT NULL DEFAULT 0,
            is_contact INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, other_id)
        );"""
    )
    # миграция колонок chats (каналы)
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(chats)").fetchall()}
    if "is_saved" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN is_saved INTEGER NOT NULL DEFAULT 0")
    if "is_channel" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN is_channel INTEGER NOT NULL DEFAULT 0")
    if "owner_id" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN owner_id INTEGER NOT NULL DEFAULT 0")
    if "is_public" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0")
    if "invite" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN invite TEXT")
    if "avatar" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
    if "bio" not in ccols:
        conn.execute("ALTER TABLE chats ADD COLUMN bio TEXT NOT NULL DEFAULT ''")
    # миграция колонок chat_members (роль)
    mcols = {r[1] for r in conn.execute("PRAGMA table_info(chat_members)").fetchall()}
    if "role" not in mcols:
        conn.execute("ALTER TABLE chat_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
    # миграция колонок messages (тип)
    mscols = {r[1] for r in conn.execute("PRAGMA table_info(messages)").fetchall()}
    if "type" not in mscols:
        conn.execute("ALTER TABLE messages ADD COLUMN type TEXT NOT NULL DEFAULT 'text'")
    conn.commit()
    conn.close()


def hash_password(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def valid_login(login):
    """Ник: только латиница, цифры, подчёркивание/точка/дефис, 3-20 символов.
    Без кириллицы, без пробелов, без «абракадабры» (без гласных не допускаем)."""
    import re as _re
    s = (login or "").strip()
    if len(s) < 3 or len(s) > 20:
        return False
    if not _re.match(r"^[A-Za-z][A-Za-z0-9_.-]*$", s):
        return False
    # требуем хотя бы одну гласную латиницы — отсекаем бессмысленные наборы согласных
    if not _re.search(r"[aeiouAEIOU]", s):
        return False
    return True


def valid_password(pw):
    """Пароль: 4-16 символов."""
    return isinstance(pw, str) and 4 <= len(pw) <= 16


def valid_phone(phone):
    """Проверка формата российского мобильного номера.
    Принимаем +7XXXXXXXXXX / 8XXXXXXXXXX / 7XXXXXXXXXX. Приводим к 10 цифрам,
    девятый код должен быть мобильным (9xx, диапазон 90-99). Существование
    конкретного номера без обращения к оператору проверить нельзя,
    поэтому отклоняем очевидно неверные (малый размер, не 9-й код)."""
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) == 11 and digits[0] in ("7", "8"):
        digits = digits[1:]
    if len(digits) != 10:
        return False
    if not digits.startswith("9"):
        return False
    # блокируем заведомо служебный диапазон 940 (не мобильный общего доступа)
    if digits.startswith("940"):
        return False
    return True


def now_ts():
    return datetime.now().timestamp()


# ========== СОСТОЯНИЕ СЕРВЕРА ==========
# user_id -> websocket
connections = {}
# websocket -> user_id
ws_to_user = {}
# код подтверждения действует 10 минут
CODE_TTL = 600
# сессия «запомнить меня» действует 30 дней
SESSION_TTL = 30 * 24 * 3600


def make_token():
    """Случайный токен сессии (запомнить меня)."""
    return secrets.token_urlsafe(32)


async def send(ws, payload):
    """Отправка JSON в сокет без вылета при закрытом соединении."""
    try:
        await ws.send(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass


def public_user(row):
    keys = row.keys()
    return {
        "id": row["id"],
        "phone": row["phone"],
        "email": row["email"] if "email" in keys else row["phone"],
        "name": row["name"],
        "avatar": row["avatar"],
        "friend_code": row["friend_code"],
        "tg_author": row["tg_author"],
        "bio": row["bio"] if "bio" in keys else "",
        "tag": row["tag"] if "tag" in keys else "",
        "last_seen": row["last_seen"] if "last_seen" in keys else 0,
    }


# ========== ОБРАБОТКА ЗАПРОСОВ ==========
async def handle(msg, ws):
    t = msg.get("t")
    if t == "register":
        await handle_register(msg, ws)
    elif t == "login":
        await handle_login(msg, ws)
    elif t == "list_users":
        await handle_list_users(msg, ws)
    elif t == "create_chat":
        await handle_create_chat(msg, ws)
    elif t == "create_channel":
        await handle_create_channel(msg, ws)
    elif t == "get_chat_info":
        await handle_get_chat_info(msg, ws)
    elif t == "update_chat":
        await handle_update_chat(msg, ws)
    elif t == "add_members":
        await handle_add_members(msg, ws)
    elif t == "remove_member":
        await handle_remove_member(msg, ws)
    elif t == "leave_chat":
        await handle_leave_chat(msg, ws)
    elif t == "find_channels":
        await handle_find_channels(msg, ws)
    elif t == "join_chat":
        await handle_join_chat(msg, ws)
    elif t == "get_chats":
        await handle_get_chats(msg, ws)
    elif t == "open_chat":
        await handle_open_chat(msg, ws)
    elif t == "send":
        await handle_send(msg, ws)
    elif t == "set_relation":
        await handle_set_relation(msg, ws)
    elif t == "get_relations":
        await handle_get_relations(msg, ws)
    elif t == "get_user_info":
        await handle_get_user_info(msg, ws)
    elif t == "delete_account":
        await handle_delete_account(msg, ws)
    elif t == "logout":
        await handle_logout(msg, ws)
    elif t == "update_profile":
        await handle_update_profile(msg, ws)
    elif t == "get_friend_code":
        await handle_get_friend_code(msg, ws)
    elif t == "set_friend_code":
        await handle_set_friend_code(msg, ws)
    elif t == "find_by_code":
        await handle_find_by_code(msg, ws)
    elif t == "get_profile":
        await handle_get_profile(msg, ws)
    elif t == "ping":
        # держим онлайн-статус; ничего больше не отвечаем
        pass
    elif t == "typing":
        await handle_typing(msg, ws)
    elif t == "post_story":
        await handle_post_story(msg, ws)
    elif t == "get_stories":
        await handle_get_stories(msg, ws)
    elif t == "ws_upload":
        await handle_ws_upload(msg, ws)
    else:
        await send(ws, {"ok": False, "t": t, "error": "unknown"})


async def handle_register(msg, ws):
    login = str(msg.get("login", "")).strip()
    password = msg.get("password", "")
    name = str(msg.get("name", "")).strip()
    if not valid_login(login):
        await send(ws, {"ok": False, "t": "register", "error": "bad_login"})
        return
    if not valid_password(password):
        await send(ws, {"ok": False, "t": "register", "error": "weak_password"})
        return
    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()
    if exists:
        conn.close()
        await send(ws, {"ok": False, "t": "register", "error": "already_registered"})
        return
    cur = conn.execute(
        "INSERT INTO users(phone, login, password_hash, name, friend_code, created) VALUES(?,?,?,?,?,?)",
        (login, login, hash_password(password), name or login, make_friend_code(), datetime.now().isoformat()),
    )
    user_id = cur.lastrowid
    token = make_token()
    conn.execute(
        "INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)",
        (token, user_id, int(now_ts()) + SESSION_TTL),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    u = public_user(row)
    u["token"] = token
    await send(
        ws,
        {"ok": True, "t": "register", "user": u},
    )


async def handle_login(msg, ws):
    login = str(msg.get("login", "")).strip()
    password = msg.get("password", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    conn.close()
    if not row or row["password_hash"] != hash_password(password):
        await send(ws, {"ok": False, "t": "login", "error": "bad_credentials"})
        return
    # создаём сессию (запомнить меня)
    token = make_token()
    conn2 = get_db()
    conn2.execute(
        "INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)",
        (token, row["id"], int(now_ts()) + SESSION_TTL),
    )
    conn2.commit()
    conn2.close()
    u = public_user(row)
    u["token"] = token
    await send(ws, {"ok": True, "t": "login", "user": u})


async def handle_list_users(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "list_users", "error": "not_auth"})
        return
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY name").fetchall()
    conn.close()
    await send(
        ws,
        {"ok": True, "t": "list_users", "users": [public_user(r) for r in rows]},
    )


async def handle_create_chat(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "create_chat", "error": "not_auth"})
        return
    members = msg.get("members", [])  # list of user ids
    if not isinstance(members, list) or not members:
        await send(ws, {"ok": False, "t": "create_chat", "error": "bad_members"})
        return
    is_group = bool(msg.get("is_group", False))
    name = str(msg.get("name", "")).strip()
    conn = get_db()
    user_ids = set(members)
    user_ids.add(me)
    # пересоздаём целые id
    rowids = conn.execute(
        "SELECT id FROM users WHERE id IN (%s)" % ",".join("?" * len(user_ids)),
        list(user_ids),
    ).fetchall()
    if len(rowids) != len(user_ids):
        conn.close()
        await send(ws, {"ok": False, "t": "create_chat", "error": "bad_user"})
        return
    cur = conn.execute(
        "INSERT INTO chats(name, is_group, created) VALUES(?,?,?)",
        (name, 1 if is_group else 0, datetime.now().isoformat()),
    )
    chat_id = cur.lastrowid
    for uid in user_ids:
        conn.execute(
            "INSERT OR IGNORE INTO chat_members(chat_id, user_id) VALUES(?,?)",
            (chat_id, uid),
        )
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "create_chat", "chat_id": chat_id})


def make_invite():
    """Случайный invite-код для канала/группы (используется в ссылке)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(12))


def ensure_saved_chat(uid):
    """Гарантируем наличие личного чата «Me» (Избранное) для пользователя."""
    conn = get_db()
    row = conn.execute(
        "SELECT cm.chat_id FROM chat_members cm JOIN chats c ON c.id=cm.chat_id "
        "WHERE cm.user_id=? AND c.is_saved=1 LIMIT 1",
        (uid,),
    ).fetchone()
    if row:
        conn.close()
        return row["chat_id"]
    # создаём персональный чат
    cur = conn.execute(
        "INSERT INTO chats(name, is_group, is_channel, owner_id, is_public, is_saved, created) "
        "VALUES(?,?,?,?,?,?,?)",
        ("Me", 0, 0, uid, 0, 1, datetime.now().isoformat()),
    )
    chat_id = cur.lastrowid
    conn.execute(
        "INSERT OR IGNORE INTO chat_members(chat_id, user_id, role) VALUES(?,?,?)",
        (chat_id, uid, "owner"),
    )
    conn.commit()
    conn.close()
    return chat_id


def chat_public(c, is_member=False):
    return {
        "id": c["id"],
        "name": c["name"] or "",
        "is_group": bool(c["is_group"]),
        "is_channel": bool(c["is_channel"]),
        "owner_id": c["owner_id"],
        "is_public": bool(c["is_public"]),
        "invite": c["invite"],
        "avatar": c["avatar"],
        "bio": c["bio"],
        "member": is_member,
    }


async def handle_create_channel(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "create_channel", "error": "not_auth"})
        return
    is_channel = bool(msg.get("is_channel", False))
    is_public = bool(msg.get("is_public", False))
    name = str(msg.get("name", "")).strip() or ("Новый канал" if is_channel else "Новая группа")
    members = msg.get("members", [])
    if not isinstance(members, list):
        members = []
    conn = get_db()
    invite = make_invite()
    cur = conn.execute(
        "INSERT INTO chats(name, is_group, is_channel, owner_id, is_public, invite, created) VALUES(?,?,?,?,?,?,?)",
        (name, 0 if is_channel else 1, 1 if is_channel else 0, me, 1 if is_public else 0,
         invite, datetime.now().isoformat()),
    )
    chat_id = cur.lastrowid
    conn.execute(
        "INSERT OR IGNORE INTO chat_members(chat_id, user_id, role) VALUES(?,?,?)",
        (chat_id, me, "owner"),
    )
    for uid in set(members):
        try:
            uid = int(uid)
        except Exception:
            continue
        if uid == me:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO chat_members(chat_id, user_id, role) VALUES(?,?,?)",
            (chat_id, uid, "member"),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
    conn.close()
    await send(ws, {"ok": True, "t": "create_channel", "chat": chat_public(row, True)})


async def handle_get_chat_info(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_chat_info", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    conn = get_db()
    c = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
    if not c:
        conn.close()
        await send(ws, {"ok": False, "t": "get_chat_info", "error": "not_found"})
        return
    member = conn.execute(
        "SELECT role FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    conn.close()
    info = chat_public(c, bool(member))
    info["my_role"] = member["role"] if member else ""
    # список участников
    if member:
        conn = get_db()
        rows = conn.execute(
            """SELECT u.*, cm.role FROM chat_members cm JOIN users u ON u.id=cm.user_id
               WHERE cm.chat_id=? ORDER BY cm.role DESC, u.name""",
            (chat_id,),
        ).fetchall()
        conn.close()
        info["members"] = [public_user(r) | {"role": r["role"]} for r in rows]
    await send(ws, {"ok": True, "t": "get_chat_info", "chat": info})


async def handle_update_chat(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "update_chat", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    conn = get_db()
    member = conn.execute(
        "SELECT role FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    if not member or member["role"] != "owner":
        conn.close()
        await send(ws, {"ok": False, "t": "update_chat", "error": "forbidden"})
        return
    c = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
    name = str(msg.get("name", ""))
    avatar = msg.get("avatar")
    bio = str(msg.get("bio", ""))
    is_public = msg.get("is_public")
    new_name = name if name != "" else c["name"]
    co = "UPDATE chats SET name=?, bio=?"
    params = [new_name, bio]
    if avatar is not None:
        co += ", avatar=?"
        params.append(avatar)
    if is_public is not None:
        co += ", is_public=?"
        params.append(1 if is_public else 0)
    co += " WHERE id=?"
    params.append(chat_id)
    conn.execute(co, params)
    conn.commit()
    c2 = conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()
    conn.close()
    await send(ws, {"ok": True, "t": "update_chat", "chat": chat_public(c2, True)})


async def handle_add_members(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "add_members", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    member = conn_check_role(chat_id, me)
    if member != "owner":
        await send(ws, {"ok": False, "t": "add_members", "error": "forbidden"})
        return
    uids = [int(x) for x in msg.get("members", []) if str(x).isdigit()]
    conn = get_db()
    for uid in uids:
        conn.execute(
            "INSERT OR IGNORE INTO chat_members(chat_id, user_id, role) VALUES(?,?,?)",
            (chat_id, uid, "member"),
        )
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "add_members", "chat_id": chat_id})


def conn_check_role(chat_id, uid):
    conn = get_db()
    r = conn.execute(
        "SELECT role FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, uid)
    ).fetchone()
    conn.close()
    return r["role"] if r else None


async def handle_remove_member(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "remove_member", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    uid = int(msg.get("user_id", 0))
    if conn_check_role(chat_id, me) != "owner":
        await send(ws, {"ok": False, "t": "remove_member", "error": "forbidden"})
        return
    if uid == me:
        await send(ws, {"ok": False, "t": "remove_member", "error": "self"})
        return
    conn = get_db()
    conn.execute("DELETE FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, uid))
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "remove_member", "chat_id": chat_id, "user_id": uid})


async def handle_leave_chat(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "leave_chat", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    conn = get_db()
    owner = conn.execute(
        "SELECT role FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    if owner and owner["role"] == "owner":
        # владелец уйти не может (или удалить канал), запрещаем простое удаление себя
        conn.close()
        await send(ws, {"ok": False, "t": "leave_chat", "error": "owner_cannot_leave"})
        return
    conn.execute("DELETE FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me))
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "leave_chat", "chat_id": chat_id})


async def handle_find_channels(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "find_channels", "error": "not_auth"})
        return
    q = str(msg.get("q", "")).strip()
    conn = get_db()
    if q:
        rows = conn.execute(
            "SELECT * FROM chats WHERE is_channel=1 AND is_public=1 AND name LIKE ? ORDER BY id DESC LIMIT 30",
            ("%" + q + "%",),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM chats WHERE is_channel=1 AND is_public=1 ORDER BY id DESC LIMIT 30"
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        conn = get_db()
        m = conn.execute(
            "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (r["id"], me)
        ).fetchone()
        conn.close()
        out.append(chat_public(r, bool(m)))
    await send(ws, {"ok": True, "t": "find_channels", "channels": out})


async def handle_join_chat(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "join_chat", "error": "not_auth"})
        return
    invite = str(msg.get("invite", "")).strip()
    chat_id = msg.get("chat_id")
    conn = get_db()
    if invite:
        c = conn.execute("SELECT * FROM chats WHERE invite=?", (invite,)).fetchone()
    elif chat_id is not None:
        c = conn.execute("SELECT * FROM chats WHERE id=?", (int(chat_id),)).fetchone()
    else:
        conn.close()
        await send(ws, {"ok": False, "t": "join_chat", "error": "bad_code"})
        return
    if not c:
        conn.close()
        await send(ws, {"ok": False, "t": "join_chat", "error": "not_found"})
        return
    # приватный канал можно вступить только по ссылке; публичный — по ссылке или поиску
    if not c["is_public"] and not invite:
        conn.close()
        await send(ws, {"ok": False, "t": "join_chat", "error": "forbidden"})
        return
    already = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (c["id"], me)
    ).fetchone()
    if not already:
        conn.execute(
            "INSERT OR IGNORE INTO chat_members(chat_id, user_id, role) VALUES(?,?,?)",
            (c["id"], me, "member"),
        )
        conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "join_chat", "chat": None, "chat_id": c["id"]})


async def handle_get_chats(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_chats", "error": "not_auth"})
        return
    ensure_saved_chat(me)  # личный чат «Me» (Избранное) всегда есть
    conn = get_db()
    rows = conn.execute(
        """SELECT c.id, c.name, c.is_group, c.is_channel, c.is_public, c.invite, c.owner_id, c.avatar, c.is_saved,
                  (SELECT COUNT(*) FROM messages m WHERE m.chat_id=c.id) as cnt,
                  (SELECT body FROM messages m WHERE m.chat_id=c.id
                   ORDER BY m.id DESC LIMIT 1) as last
           FROM chats c
           JOIN chat_members cm ON cm.chat_id=c.id
           WHERE cm.user_id=?
           ORDER BY c.id DESC""",
        (me,),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "name": r["name"] or (f"Группа #{r['id']}" if r["is_group"] else (f"Канал #{r['id']}" if r["is_channel"] else f"Чат #{r['id']}")),
                "is_group": bool(r["is_group"]),
                "is_channel": bool(r["is_channel"]),
                "is_public": bool(r["is_public"]),
                "invite": r["invite"],
                "owner_id": r["owner_id"],
                "avatar": r["avatar"],
                "is_saved": bool(r["is_saved"]),
                "count": r["cnt"],
                "last": r["last"],
            }
        )
    await send(ws, {"ok": True, "t": "get_chats", "chats": out})


async def handle_open_chat(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "open_chat", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    conn = get_db()
    member = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    if not member:
        conn.close()
        await send(ws, {"ok": False, "t": "open_chat", "error": "forbidden"})
        return
    msgs = conn.execute(
        """SELECT m.id, m.sender_id, m.body, m.type, m.ts, u.name
           FROM messages m JOIN users u ON u.id=m.sender_id
           WHERE m.chat_id=? ORDER BY m.id ASC""",
        (chat_id,),
    ).fetchall()
    conn.close()
    await send(
        ws,
        {
            "ok": True,
            "t": "open_chat",
            "chat_id": chat_id,
            "messages": [
                {
                    "id": m["id"],
                    "sender_id": m["sender_id"],
                    "sender_name": m["name"],
                    "body": m["body"],
                    "type": m["type"],
                    "ts": m["ts"],
                }
                for m in msgs
            ],
        },
    )


async def handle_send(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "send", "error": "not_auth"})
        return
    chat_id = int(msg.get("chat_id", 0))
    body = str(msg.get("body", "")).strip()
    mtype = str(msg.get("type", "text"))
    media_id = msg.get("media_id")
    if not body and not media_id:
        return
    conn = get_db()
    member = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    if not member:
        conn.close()
        await send(ws, {"ok": False, "t": "send", "error": "forbidden"})
        return
    # для медиа-сообщений подставляем ссылку FILE:<id>; для гео сохраняем координаты
    if media_id is not None:
        f = conn.execute("SELECT id, name, mime FROM files WHERE id=?", (int(media_id),)).fetchone()
        if not f:
            conn.close()
            await send(ws, {"ok": False, "t": "send", "error": "bad_file"})
            return
        if mtype == "geo" and body:
            storage = "FILE:" + str(f["id"]) + "|" + body  # body = geo:lat,lon
        else:
            storage = "FILE:" + str(f["id"])
        ts = now_ts()
        cur = conn.execute(
            "INSERT INTO messages(chat_id, sender_id, body, type, ts) VALUES(?,?,?,?,?)",
            (chat_id, me, storage, mtype, ts),
        )
        msg_id = cur.lastrowid
    else:
        ts = now_ts()
        cur = conn.execute(
            "INSERT INTO messages(chat_id, sender_id, body, type, ts) VALUES(?,?,?,?,?)",
            (chat_id, me, body, mtype, ts),
        )
        msg_id = cur.lastrowid
    # список участников
    rows = conn.execute(
        "SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,)
    ).fetchall()
    conn.commit()
    conn.close()
    payload = {
        "ok": True,
        "t": "message",
        "message": {
            "id": msg_id,
            "chat_id": chat_id,
            "sender_id": me,
            "body": body if media_id is None else storage,
            "type": mtype,
            "ts": ts,
        },
    }
    # разослать всем участникам в реальном времени
    for r in rows:
        uid = r["user_id"]
        ws_to = connections.get(uid)
        if ws_to and ws_to != ws:
            await send(ws_to, payload)
    await send(ws, payload)


async def handle_set_relation(msg, ws):
    """Установить/снять отношение к пользователю: заблокировать, беззвучный, добавить/удалить контакт."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "set_relation", "error": "not_auth"})
        return
    other = int(msg.get("user_id", 0))
    action = str(msg.get("action", "")).strip()
    value = bool(msg.get("value", True))
    if other <= 0 or other == me:
        await send(ws, {"ok": False, "t": "set_relation", "error": "bad_user"})
        return
    if action not in ("block", "mute", "contact"):
        await send(ws, {"ok": False, "t": "set_relation", "error": "bad_action"})
        return
    conn = get_db()
    # узнаем текущее состояние
    row = conn.execute(
        "SELECT * FROM user_relations WHERE user_id=? AND other_id=?", (me, other)
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO user_relations(user_id, other_id, blocked, muted, is_contact) VALUES(?,?,?,?,?)",
            (me, other, 0, 0, 0),
        )
        conn.commit()
    if action == "block":
        conn.execute("UPDATE user_relations SET blocked=? WHERE user_id=? AND other_id=?",
                     (1 if value else 0, me, other))
    elif action == "mute":
        conn.execute("UPDATE user_relations SET muted=? WHERE user_id=? AND other_id=?",
                     (1 if value else 0, me, other))
    elif action == "contact":
        conn.execute("UPDATE user_relations SET is_contact=? WHERE user_id=? AND other_id=?",
                     (1 if value else 0, me, other))
    conn.commit()
    row2 = conn.execute(
        "SELECT * FROM user_relations WHERE user_id=? AND other_id=?", (me, other)
    ).fetchone()
    conn.close()
    await send(ws, {
        "ok": True, "t": "set_relation", "user_id": other, "action": action, "value": value,
        "blocked": bool(row2["blocked"]), "muted": bool(row2["muted"]),
        "is_contact": bool(row2["is_contact"]),
    })


async def handle_get_relations(msg, ws):
    """Отдаёт карту отношений (блокировка/беззвучный/контакт) для текущего пользователя."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_relations", "error": "not_auth"})
        return
    conn = get_db()
    rows = conn.execute(
        "SELECT other_id, blocked, muted, is_contact FROM user_relations WHERE user_id=?", (me,)
    ).fetchall()
    conn.close()
    rel = {}
    for r in rows:
        rel[str(r["other_id"])] = {
            "blocked": bool(r["blocked"]),
            "muted": bool(r["muted"]),
            "is_contact": bool(r["is_contact"]),
        }
    await send(ws, {"ok": True, "t": "get_relations", "relations": rel})


async def handle_get_user_info(msg, ws):
    """Отдаёт публичное досье пользователя + статус отношений с ним."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_user_info", "error": "not_auth"})
        return
    uid = int(msg.get("user_id", 0))
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    rel = conn.execute(
        "SELECT * FROM user_relations WHERE user_id=? AND other_id=?", (me, uid)
    ).fetchone()
    conn.close()
    if not row:
        await send(ws, {"ok": False, "t": "get_user_info", "error": "not_found"})
        return
    u = public_user(row)
    u["blocked"] = bool(rel["blocked"]) if rel else False
    u["muted"] = bool(rel["muted"]) if rel else False
    u["is_contact"] = bool(rel["is_contact"]) if rel else False
    await send(ws, {"ok": True, "t": "get_user_info", "user": u})


async def handle_delete_account(msg, ws):
    """Полное удаление аккаунта пользователя (все данные)."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "delete_account", "error": "not_auth"})
        return
    password = msg.get("password", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (me,)).fetchone()
    if not row or row["password_hash"] != hash_password(password):
        conn.close()
        await send(ws, {"ok": False, "t": "delete_account", "error": "bad_credentials"})
        return
    # удаляем все связанные данные
    conn.execute("DELETE FROM users WHERE id=?", (me,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (me,))
    conn.execute("DELETE FROM files WHERE owner_id=?", (me,))
    conn.execute("DELETE FROM stories WHERE user_id=?", (me,))
    conn.execute("DELETE FROM user_relations WHERE user_id=? OR other_id=?", (me, me))
    # удаляем сообщения пользователя и чаты, где он владелец
    conn.execute("DELETE FROM messages WHERE sender_id=?", (me,))
    conn.execute("DELETE FROM chat_members WHERE user_id=?", (me,))
    # чаты, где пользователь был единственным участником или владельцем — удаляем
    lone = conn.execute(
        """SELECT cm.chat_id FROM chat_members cm
           WHERE cm.chat_id IN (SELECT chat_id FROM chat_members WHERE user_id=?)
           GROUP BY cm.chat_id HAVING COUNT(*)=1""",
        (me,),
    ).fetchall()
    for r in lone:
        conn.execute("DELETE FROM messages WHERE chat_id=?", (r["chat_id"],))
        conn.execute("DELETE FROM chat_members WHERE chat_id=?", (r["chat_id"],))
        conn.execute("DELETE FROM chats WHERE id=?", (r["chat_id"],))
    conn.commit()
    conn.close()
    # отвязываем сокет
    ws_to_user.pop(ws, None)
    connections.pop(me, None)
    await send(ws, {"ok": True, "t": "delete_account"})


async def handle_logout(msg, ws):
    me = ws_to_user.pop(ws, None)
    if me is not None and connections.get(me) == ws:
        connections.pop(me, None)
    await send(ws, {"ok": True, "t": "logout"})


def make_friend_code():
    """Уникальный 6-символьный код. Латиница+цифры без похожих символов."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        # проверка уникальности
        conn = get_db()
        exists = conn.execute(
            "SELECT 1 FROM users WHERE friend_code=?", (code,)
        ).fetchone()
        conn.close()
        if not exists:
            return code


def ensure_friend_code(uid):
    """Гарантируем, что у пользователя есть код. Возвращает код."""
    conn = get_db()
    row = conn.execute(
        "SELECT friend_code FROM users WHERE id=?", (uid,)
    ).fetchone()
    if row and row["friend_code"]:
        conn.close()
        return row["friend_code"]
    code = make_friend_code()
    conn.execute("UPDATE users SET friend_code=? WHERE id=?", (code, uid))
    conn.commit()
    conn.close()
    return code


async def handle_get_friend_code(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_friend_code", "error": "not_auth"})
        return
    code = ensure_friend_code(me)
    await send(ws, {"ok": True, "t": "get_friend_code", "friend_code": code})


async def handle_set_friend_code(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "set_friend_code", "error": "not_auth"})
        return
    # генерируем новый уникальный код
    code = make_friend_code()
    conn = get_db()
    # исключим текущий код себя из проверки уникальности (код уже мог быть тот же)
    conn.execute("UPDATE users SET friend_code=? WHERE id=?", (code, me))
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "set_friend_code", "friend_code": code})


async def handle_get_profile(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_profile", "error": "not_auth"})
        return
    code = ensure_friend_code(me)
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (me,)).fetchone()
    conn.close()
    u = public_user(row)
    u["friend_code"] = code
    await send(ws, {"ok": True, "t": "get_profile", "user": u})


async def handle_update_profile(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "update_profile", "error": "not_auth"})
        return
    name = str(msg.get("name", "")).strip()
    avatar = msg.get("avatar", "")  # base64 или "": сброс
    tg_author = str(msg.get("tg_author", "")).strip()
    bio = str(msg.get("bio", "")).strip()
    tag = str(msg.get("tag", "")).strip()
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id=?", (me,)).fetchone()
    new_name = name if name else cur["name"]
    new_tg = tg_author if tg_author != "" else cur["tg_author"]
    new_bio = bio if bio != "" else cur["bio"]
    new_tag = tag if tag != "" else cur["tag"]
    # ограничим размер аватара (примерно 512 КБ base64)
    if len(avatar) > 800000:
        conn.close()
        await send(ws, {"ok": False, "t": "update_profile", "error": "avatar_too_big"})
        return
    conn.execute(
        "UPDATE users SET name=?, avatar=?, tg_author=?, bio=?, tag=? WHERE id=?",
        (new_name, avatar, new_tg, new_bio, new_tag, me),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id=?", (me,)).fetchone()
    conn.close()
    code = ensure_friend_code(me)
    await send(ws, {"ok": True, "t": "update_profile", "user": public_user(row)})


async def handle_find_by_code(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "find_by_code", "error": "not_auth"})
        return
    code = str(msg.get("code", "")).strip().upper()
    if not code:
        await send(ws, {"ok": False, "t": "find_by_code", "error": "bad_code"})
        return
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE friend_code=?", (code,)
    ).fetchone()
    conn.close()
    if not row:
        await send(ws, {"ok": False, "t": "find_by_code", "error": "not_found"})
        return
    if row["id"] == me:
        await send(ws, {"ok": False, "t": "find_by_code", "error": "self"})
        return
    result = public_user(row)
    await send(ws, {"ok": True, "t": "find_by_code", "user": result})


async def handle_typing(msg, ws):
    """Уведомляет участников чата, что пользователь печатает."""
    me = ws_to_user.get(ws)
    if me is None:
        return
    chat_id = int(msg.get("chat_id", 0))
    conn = get_db()
    member = conn.execute(
        "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, me)
    ).fetchone()
    if not member:
        conn.close()
        return
    rows = conn.execute(
        "SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,)
    ).fetchall()
    conn.close()
    payload = {"ok": True, "t": "typing", "chat_id": chat_id, "user_id": me}
    for r in rows:
        uid = r["user_id"]
        if uid == me:
            continue
        ws_to = connections.get(uid)
        if ws_to and ws_to != ws:
            await send(ws_to, payload)


async def handle_post_story(msg, ws):
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "post_story", "error": "not_auth"})
        return
    media = msg.get("media", "")
    caption = str(msg.get("caption", "")).strip()
    if not media:
        await send(ws, {"ok": False, "t": "post_story", "error": "bad_media"})
        return
    if len(media) > 2_500_000:
        await send(ws, {"ok": False, "t": "post_story", "error": "too_big"})
        return
    ts = now_ts()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO stories(user_id, media, caption, ts) VALUES(?,?,?,?)",
        (me, media, caption, ts),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    # рассылаем событие появления сторис всем авторизованным (для обновления кружочков)
    notify_story(me, {"id": sid, "user_id": me, "media": "", "caption": caption, "ts": ts})
    await send(ws, {"ok": True, "t": "post_story", "story": sid})


def notify_story(user_id, story_meta):
    payload = {"ok": True, "t": "story_updated", "user_id": story_meta["user_id"]}
    for uid, w in list(connections.items()):
        if uid != user_id:
            send_sync(w, payload)


async def handle_ws_upload(msg, ws):
    """Загрузка файла через WebSocket (облачный режим): base64 в data."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "ws_upload", "error": "not_auth"})
        return
    name = str(msg.get("name", "")).strip()
    mime = str(msg.get("mime", "application/octet-stream"))
    b64 = msg.get("data", "")
    if not b64 or not name:
        await send(ws, {"ok": False, "t": "ws_upload", "error": "bad_file"})
        return
    try:
        import base64 as _b64
        filedata = _b64.b64decode(b64.split(",", 1)[-1] if isinstance(b64, str) and "," in b64 else b64)
    except Exception:
        await send(ws, {"ok": False, "t": "ws_upload", "error": "bad_file"})
        return
    if len(filedata) > 15 * 1024 * 1024:
        await send(ws, {"ok": False, "t": "ws_upload", "error": "too_big"})
        return
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO files(owner_id, name, mime, data, ts) VALUES(?,?,?,?,?)",
        (me, name, mime, filedata, now_ts()),
    )
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    await send(ws, {"ok": True, "t": "ws_upload", "id": fid, "name": name, "mime": mime})


def send_sync(ws, payload):
    import asyncio as _asyncio
    try:
        _asyncio.ensure_future(send(ws, payload))
    except Exception:
        pass


async def handle_get_stories(msg, ws):
    """Отдаёт активные сторис (последние 24ч) для отображения на кружочках."""
    me = ws_to_user.get(ws)
    if me is None:
        await send(ws, {"ok": False, "t": "get_stories", "error": "not_auth"})
        return
    window = now_ts() - 24 * 3600
    conn = get_db()
    rows = conn.execute(
        """SELECT s.id, s.user_id, s.media, s.caption, s.ts, u.name, u.avatar
           FROM stories s JOIN users u ON u.id=s.user_id
           WHERE s.ts>=? ORDER BY s.ts DESC""",
        (window,),
    ).fetchall()
    conn.close()
    # группируем по пользователю
    groups = {}
    for r in rows:
        g = groups.setdefault(
            r["user_id"],
            {"user_id": r["user_id"], "name": r["name"], "avatar": r["avatar"], "stories": []},
        )
        g["stories"].append(
            {"id": r["id"], "media": r["media"], "caption": r["caption"], "ts": r["ts"]}
        )
    await send(
        ws,
        {"ok": True, "t": "get_stories", "groups": list(groups.values())},
    )
def read_html():
    path = os.path.join(BASE_DIR, "client.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ========== HTTP + WEBSOCKET ==========
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handle_http_request(self, html_content):
    """HTTP-ответ для одного запроса. self — объект запроса с path/headers/wfile."""
    path = self.path
    if path in ("/", "/index.html") or path.startswith("/?"):
        data = html_content
        ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    elif path.startswith("/file/"):
        fid = path.split("/", 3)[-1].split("?")[0]
        try:
            fid = int(fid)
        except Exception:
            self.send_response(400); self.end_headers(); return
        conn = get_db()
        f = conn.execute("SELECT id, name, mime, data FROM files WHERE id=?", (fid,)).fetchone()
        conn.close()
        if not f:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", f["mime"] or "application/octet-stream")
        self.send_header("Content-Length", str(len(f["data"])))
        self.end_headers()
        self.wfile.write(f["data"])
    elif path.startswith("/notification."):
        fname = path.lstrip("/").split("?")[0]
        data = None
        fp = os.path.join(APP_DIR, fname)
        if os.path.exists(fp):
            with open(fp, "rb") as f:
                data = f.read()
        else:
            fp2 = os.path.join(BASE_DIR, fname)
            if os.path.exists(fp2):
                with open(fp2, "rb") as f:
                    data = f.read()
        if data is not None:
            ctype = "audio/wav" if fname.endswith(".wav") else "audio/mpeg"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()
    else:
        self.send_response(404); self.end_headers()


def serve_client():
    html = read_html()
    content = html.encode("utf-8")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            handle_http_request(self, content)

        def do_POST(self):
            # загрузка файла: multipart/form-data, поля name, mime, user_id, file
            if not self.path.startswith("/upload"):
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > 15 * 1024 * 1024:
                self.send_response(413)
                self.end_headers()
                return
            body = self.rfile.read(length)
            # простой разбор multipart
            ctype = self.headers.get("Content-Type", "")
            boundary = None
            for part in ctype.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[len("boundary="):].strip('"')
            if not boundary:
                self.send_response(400)
                self.end_headers()
                return
            delim = ("--" + boundary).encode()
            name = ""
            mime = "application/octet-stream"
            filedata = b""
            uid = 0
            for chunk in body.split(delim):
                chunk = chunk.strip(b"\r\n")
                if not chunk or chunk == b"--":
                    continue
                try:
                    hdr, data = chunk.split(b"\r\n\r\n", 1)
                except Exception:
                    continue
                disp = ""
                for line in hdr.split(b"\r\n"):
                    ls = line.decode("latin1")
                    if ls.lower().startswith("content-disposition:"):
                        disp = ls
                def _param(s, key):
                    for tok in s.split(";"):
                        tok = tok.strip()
                        if tok.startswith(key + "="):
                            return tok[len(key) + 1:].strip('"')
                    return ""
                fname_p = _param(disp, "filename")
                if fname_p:
                    name = fname_p
                    filedata = data
                else:
                    field = _param(disp, "name")
                    if field == "mime":
                        mime = data.decode("utf-8", "replace")
                    elif field == "user_id":
                        try:
                            uid = int(data.decode())
                        except Exception:
                            uid = 0
            if not name or not filedata or uid <= 0:
                self.send_response(400)
                self.end_headers()
                return
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO files(owner_id, name, mime, data, ts) VALUES(?,?,?,?,?)",
                (uid, name, mime, filedata, now_ts()),
            )
            fid = cur.lastrowid
            conn.commit()
            conn.close()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            body_out = json.dumps({"ok": True, "id": fid, "name": name, "mime": mime}).encode("utf-8")
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((HOST, HTTP_PORT), H)
    srv.serve_forever()


async def ws_handler(ws):
    # первый фрейм после коннекта — пустой; пользователь авторизуется вызовом входа
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        t = msg.get("t")
        # активность авторизованного пользователя обновляет last_seen (онлайн)
        me_here = ws_to_user.get(ws)
        if me_here is not None and t != "ping":
            try:
                ca = get_db()
                ca.execute("UPDATE users SET last_seen=? WHERE id=?", (now_ts() + 90, me_here))
                ca.commit()
                ca.close()
            except Exception:
                pass
        # после успешного login/register привязываем сокет к user
        if t != "authorize":
            await handle(msg, ws)
        # поддержка явной авторизации: по токену (запомнить меня) или по user_id
        if t == "authorize":
            conn = get_db()
            uid = None
            u = None
            token = msg.get("token")
            if token:
                s = conn.execute(
                    "SELECT user_id FROM sessions WHERE token=? AND expires>?", (token, now_ts())
                ).fetchone()
                if s:
                    uid = s["user_id"]
                    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if u is None:
                try:
                    uid2 = int(msg.get("user_id", 0))
                except Exception:
                    uid2 = 0
                u = conn.execute("SELECT * FROM users WHERE id=?", (uid2,)).fetchone()
                if u:
                    uid = uid2
            conn.close()
            if u is not None and uid is not None:
                old_ws = connections.get(uid)
                if old_ws and old_ws != ws:
                    ws_to_user.pop(old_ws, None)
                connections[uid] = ws
                ws_to_user[ws] = uid
                conn2 = get_db()
                conn2.execute("UPDATE users SET last_seen=? WHERE id=?",
                              (now_ts() + 90, uid))
                conn2.commit()
                conn2.close()
                await send(ws, {"ok": True, "t": "authorize", "user": public_user(u)})
            else:
                await send(ws, {"ok": False, "t": "authorize", "error": "bad_user"})
            continue


def purge_inactive():
    """Удаляет аккаунты, не активные дольше 31 дня, и все их данные."""
    cutoff = now_ts() - 31 * 24 * 3600
    conn = get_db()
    rows = conn.execute("SELECT id FROM users WHERE last_seen < ?", (cutoff,)).fetchall()
    for r in rows:
        uid = r["id"]
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM files WHERE owner_id=?", (uid,))
        conn.execute("DELETE FROM stories WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM user_relations WHERE user_id=? OR other_id=?", (uid, uid))
        conn.execute("DELETE FROM messages WHERE sender_id=?", (uid,))
        conn.execute("DELETE FROM chat_members WHERE user_id=?", (uid,))
        lone = conn.execute(
            """SELECT cm.chat_id FROM chat_members cm
               WHERE cm.chat_id IN (SELECT chat_id FROM chat_members WHERE user_id=?)
               GROUP BY cm.chat_id HAVING COUNT(*)=1""",
            (uid,),
        ).fetchall()
        for cl in lone:
            conn.execute("DELETE FROM messages WHERE chat_id=?", (cl["chat_id"],))
            conn.execute("DELETE FROM chat_members WHERE chat_id=?", (cl["chat_id"],))
            conn.execute("DELETE FROM chats WHERE id=?", (cl["chat_id"],))
    conn.commit()
    conn.close()
    if rows:
        print(f"Автоудаление: {len(rows)} неактивных аккаунтов")


async def main():
    init_db()
    purge_inactive()  # автоудаление неактивных аккаунтов (>31 дня)
    cloud = os.environ.get("CLOUD", "").lower() in ("1", "true", "yes")
    if not cloud:
        # локальный режим: HTTP на 8080 + WS на 8081
        threading.Thread(target=serve_client, daemon=True).start()
        # автооткрытие клиента в браузере локально (в облаке не открываем)
        def _open_browser():
            import time
            import webbrowser
            time.sleep(1.2)
            try:
                webbrowser.open(f"http://localhost:{HTTP_PORT}")
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()
        async with websockets.serve(handler, HOST, WS_PORT, max_size=5 * 1024 * 1024):
            print(f"MeTOMe server:")
            print(f"  client: http://localhost:{HTTP_PORT}")
            print(f"  ws:     ws://localhost:{WS_PORT}")
            await asyncio.Future()
    else:
        # облачный режим: единый порт PORT. И HTTP, и WebSocket живут на websockets;
        # файлы передаются через WebSocket (base64), обычные GET (HTML/файлы) — process_request.
        port = int(os.environ.get("PORT", "8080"))
        html = read_html().encode("utf-8")

        def http_response(path):
            # возвращает (status, headers_list, body) или None
            if path in ("/", "/index.html"):
                return (200, [("Content-Type", "text/html; charset=utf-8")], html)
            if path.startswith("/file/"):
                fid = path.split("/", 3)[-1]
                try:
                    fid = int(fid)
                except Exception:
                    return (400, [], b"")
                conn = get_db()
                f = conn.execute("SELECT mime, data FROM files WHERE id=?", (fid,)).fetchone()
                conn.close()
                if f:
                    return (200, [("Content-Type", f["mime"] or "application/octet-stream")], f["data"])
                return (404, [], b"")
            if path.startswith("/notification."):
                fname = path.lstrip("/")
                fp = os.path.join(APP_DIR, fname)
                if not os.path.exists(fp):
                    fp = os.path.join(BASE_DIR, fname)
                if os.path.exists(fp):
                    with open(fp, "rb") as f:
                        data = f.read()
                    ctype = "audio/wav" if fname.endswith(".wav") else "audio/mpeg"
                    return (200, [("Content-Type", ctype)], data)
                return (404, [], b"")
            if path.startswith("/upload"):
                # в облаке загрузка файлов идёт через WebSocket
                return (405, [], b"")
            return (404, [], b"")

        async def process_request(conn, request):
            # request — объект Request (.path/.method/.headers)
            try:
                upg = request.headers.get("Upgrade", "")
            except Exception:
                upg = ""
            if "websocket" in upg.lower():
                return None
            try:
                from websockets.http11 import Response as _Resp, Headers as _Headers
            except Exception:
                _Resp = None
            path = getattr(request, "path", "").split("?", 1)[0]
            res = http_response(path)
            if res is not None:
                status, hlist, body = res
                if _Resp is not None:
                    h = _Headers()
                    for k, v in hlist:
                        h[k] = v
                    return _Resp(status, "OK" if status == 200 else "Error", h, body)
                return (status, hlist, body)
            return None

        async def combined(ws):
            await ws_handler(ws)

        async with websockets.serve(combined, HOST, port, max_size=5 * 1024 * 1024,
                                    process_request=process_request):
            print(f"MeTOMe cloud server on :{port}")
            await asyncio.Future()


async def handler(ws):
    try:
        await ws_handler(ws)
    finally:
        uid = ws_to_user.pop(ws, None)
        if uid is not None and connections.get(uid) == ws:
            connections.pop(uid, None)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("shutdown")