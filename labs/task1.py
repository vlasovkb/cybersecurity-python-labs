"""Завдання 1: модель користувача, сеансу, журналу аудиту та облікового запису.

Модуль лише описує класи. Демонстрація винесена в ``main.py`` (команда
``demo``) і не виконується при імпорті.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar

# --- Параметри безпеки -------------------------------------------------------
PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 600_000  # рекомендована OWASP кількість ітерацій для PBKDF2-SHA256
SALT_SIZE_BYTES = 16
SESSION_TIMEOUT_SEC = 900  # 15 хвилин бездіяльності

# Локальна частина: латинська літера + ще 2..63 символи (разом 3-64) з літер,
# цифр або "_"; далі "@" і домен щонайменше з однією крапкою (спрощена перевірка).
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)

# --- Дозволені дії журналу аудиту --------------------------------------------
ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"
ACTION_SESSION_TIMEOUT = "session_timeout"
# Журнал приймає лише відомі коди дій, тому в нього неможливо випадково
# записати довільний текст (наприклад, пароль).
ALLOWED_ACTIONS = frozenset(
    {ACTION_LOGIN_SUCCESS, ACTION_LOGIN_FAILURE, ACTION_LOGOUT, ACTION_SESSION_TIMEOUT}
)


def utc_now() -> datetime:
    """Поточний час UTC з часовим поясом (без неоднозначності локального часу)."""
    return datetime.now(UTC)


def _require_aware(value: datetime, name: str) -> datetime:
    """Перевіряє, що значення є datetime із часовим поясом."""
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


# --- Користувач --------------------------------------------------------------
class User:
    """Користувач системи.

    Пароль ніколи не зберігається у відкритому вигляді: у приватних атрибутах
    лежать лише випадкова сіль і PBKDF2-хеш.
    """

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a non-empty string")
        if not isinstance(role, str) or not role.strip():
            raise ValueError("role must be a non-empty string")
        if not isinstance(active, bool):
            raise TypeError("active must be a bool")

        self.username = username.strip()
        self.role = role.strip()
        self.active = active
        self.email = email  # проходить через сеттер -> валідація
        # Приватні атрибути (name mangling: _User__password_hash / _User__password_salt)
        self.__password_salt = b""
        self.__password_hash = b""
        self.set_password(password)

    # -- email із валідацією ---------------------------------------------------
    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or EMAIL_PATTERN.fullmatch(value) is None:
            raise ValueError(f"invalid email address: {value!r}")
        self._email = value

    # -- робота з паролем ------------------------------------------------------
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            PBKDF2_HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        """Генерує нову сіль і зберігає PBKDF2-хеш пароля."""
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_salt = salt
        self.__password_hash = self._derive_key(password, salt)

    def check_password(self, password: str) -> bool:
        """Порівнює хеш у сталий час (``hmac.compare_digest``)."""
        if not isinstance(password, str):
            return False
        candidate = self._derive_key(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return (
            f"{type(self).__name__}(username={self.username}, email={self.email}, "
            f"role={self.role}, active={self.active})"
        )


# --- Адміністратор (наслідування: Admin "is a" User) ---------------------------
class Admin(User):
    """Користувач із набором дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, password, role="admin", active=active)
        # Нова множина для кожного об'єкта: змінюваного типового аргументу немає.
        self.permissions: set[str] = set()
        for permission in permissions or ():
            self.grant_permission(permission)

    @staticmethod
    def _clean(permission: str) -> str:
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("permission must be a non-empty string")
        return permission.strip()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(self._clean(permission))

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(self._clean(permission))

    def has_permission(self, permission: str) -> bool:
        return self._clean(permission) in self.permissions

    def __str__(self) -> str:
        shown = ", ".join(sorted(self.permissions)) or "none"
        return f"{super().__str__()} permissions=[{shown}]"


# --- Сеанс ---------------------------------------------------------------------
class Session:
    """Сеанс користувача. Увесь час — UTC із часовим поясом."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        if not isinstance(ip, str):
            raise TypeError("ip must be a string")
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {ip!r}") from exc

        self.ip = ip
        self.login_time = _require_aware(login_time or utc_now(), "login_time")
        self.last_activity = _require_aware(
            last_activity or self.login_time, "last_activity"
        )

    def touch(self, now: datetime | None = None) -> None:
        """Оновлює час останньої активності."""
        self.last_activity = (
            _require_aware(now, "now") if now is not None else utc_now()
        )

    def is_active(self, timeout_sec: int, now: datetime | None = None) -> bool:
        """True, якщо з останньої активності минуло менше ``timeout_sec`` секунд.

        Параметр ``now`` потрібен лише для детермінованої демонстрації та тестів.
        """
        if (
            isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, int)
            or timeout_sec <= 0
        ):
            raise ValueError("timeout_sec must be a positive integer")
        current = _require_aware(now, "now") if now is not None else utc_now()
        return current - self.last_activity < timedelta(seconds=timeout_sec)


# --- Журнал аудиту ---------------------------------------------------------------
@dataclass(frozen=True)
class AuditEntry:
    """Один незмінний запис журналу: час UTC, користувач, дія."""

    timestamp: datetime
    username: str
    action: str

    def __str__(self) -> str:
        moment = self.timestamp.isoformat(timespec="seconds")
        return f"{moment} | {self.username:<12} | {self.action}"


class AuditLog:
    """Журнал аудиту. Паролі в нього не потрапляють: приймаються лише коди дій."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def add_log(self, username: str, action: str) -> AuditEntry:
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"unknown audit action: {action!r}")
        entry = AuditEntry(timestamp=utc_now(), username=username, action=action)
        self._entries.append(entry)
        return entry

    def show_all(self) -> None:
        if not self._entries:
            print("(audit log is empty)")
            return
        for entry in self._entries:
            print(entry)


# --- Обліковий запис (композиція: UserAccount "has a" User, Session, AuditLog) ---
class UserAccount:
    """Об'єднує користувача, його поточний сеанс і журнал аудиту."""

    # Дозволені ключі для account[...] і типи їхніх значень.
    # Хеш і сіль пароля через ключі недоступні.
    _KEY_TYPES: ClassVar[dict[str, tuple[type, ...]]] = {
        "user": (User,),
        "session": (Session, type(None)),
        "audit_log": (AuditLog,),
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("user must be a User instance")
        if session is not None and not isinstance(session, Session):
            raise TypeError("session must be a Session instance or None")
        if audit_log is not None and not isinstance(audit_log, AuditLog):
            raise TypeError("audit_log must be an AuditLog instance")
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація. Сеанс створюється лише після успішної перевірки."""
        credentials_ok = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if not credentials_ok:
            self.audit_log.add_log(str(username), ACTION_LOGIN_FAILURE)
            return False

        session = Session(ip)
        session.touch()
        self.session = session
        self.audit_log.add_log(self.user.username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self, now: datetime | None = None) -> bool:
        """Є сеанс, і він не прострочений.

        Успішна перевірка продовжує сеанс (``touch``), невдала — ні: прострочений
        сеанс закривається і фіксується в аудиті як ``session_timeout``.
        """
        if self.session is None or not self.user.active:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC, now):
            self.session.touch(now)
            return True
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_SESSION_TIMEOUT)
        return False

    def logout(self) -> bool:
        """Завершує сеанс і фіксує подію. False, якщо сеансу не було."""
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    def __getitem__(self, key: str) -> object:
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        if key not in self._KEY_TYPES:
            raise KeyError(key)
        if not isinstance(value, self._KEY_TYPES[key]):
            expected = " or ".join(t.__name__ for t in self._KEY_TYPES[key])
            raise TypeError(f"{key!r} expects {expected}, got {type(value).__name__}")
        setattr(self, key, value)

    def __str__(self) -> str:
        state = "authenticated" if self.session is not None else "no session"
        entries = len(self.audit_log.entries)
        return f"UserAccount({self.user.username}, {state}, audit_entries={entries})"
