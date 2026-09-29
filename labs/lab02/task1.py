"""Завдання 1: Модель користувача, сесії, журналу аудиту та облікового запису."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
from typing import Any

PBKDF2_ITERATIONS = 100_000
SALT_SIZE_BYTES = 16
SESSION_TIMEOUT_SEC = 900

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
)


class User:
    """Базовий клас користувача системи."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        password: str | None = None,
        active: bool = True,
    ) -> None:
        if not username or not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім.")
        self.username: str = username.strip()
        self.email: str = email
        self.role: str = role
        self.active: bool = active
        self.__password_salt: bytes = b""
        self.__password_hash: bytes = b""

        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        """Повертає email користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Перевіряє формат email через регулярний вираз та встановлює значення."""
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешує пароль за допомогою PBKDF2-HMAC-SHA256 із випадковою сіллю."""
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має бути рядком довжиною щонайменше 4 символи.")
        self.__password_salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою безпечного порівняння hmac.compare_digest."""
        if not self.__password_hash or not self.__password_salt:
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status={status})"
        )


class Admin(User):
    """Клас адміністратора, що наслідує User та додає управління правами доступу."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(
            username=username,
            email=email,
            role="admin",
            password=password,
            active=active,
        )
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає право доступу адміністратору."""
        if not permission or not permission.strip():
            raise ValueError("Назва дозволу не може бути порожньою.")
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        """Відкликає право доступу адміністратора."""
        self.permissions.discard(permission.strip())

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність вказаного дозволу."""
        return permission.strip() in self.permissions

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"status={status}, permissions=[{perms}])"
        )


class Session:
    """Клас користувацької сесії з контролем часу активності в UTC."""

    def __init__(self, ip: str) -> None:
        if not ip or not ip.strip():
            raise ValueError("IP-адреса сесії не може бути порожньою.")
        now = datetime.now(timezone.utc)
        self.ip: str = ip.strip()
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:
        """Оновлює час останньої активності сесії поточним часом UTC."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут з моменту останньої активності."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії (timeout_sec) має бути додатним числом.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        return (
            f"Session(ip='{self.ip}', login_time='{self.login_time.isoformat()}', "
            f"last_activity='{self.last_activity.isoformat()}')"
        )


@dataclass(frozen=True)
class AuditEntry:
    """Запис у журналі аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій безпеки."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        """Повертає копію списку записів аудиту."""
        return list(self._entries)

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис із поточним часом UTC."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> None:
        """Виводить усі записи журналу аудиту в консоль."""
        print("=== Audit Log Entries ===")
        if not self._entries:
            print("(Журнал порожній)")
            return
        for entry in self._entries:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")


class UserAccount:
    """Обліковий запис, що об'єднує User, Session та AuditLog (композиція)."""

    _ALLOWED_KEYS: dict[str, type | tuple[type, ...]] = {
        "user": User,
        "session": (Session, type(None)),
        "audit_log": AuditLog,
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("Поле 'user' має бути екземпляром класу User.")
        if session is not None and not isinstance(session, Session):
            raise TypeError("Поле 'session' має бути екземпляром Session або None.")
        if audit_log is not None and not isinstance(audit_log, AuditLog):
            raise TypeError("Поле 'audit_log' має бути екземпляром AuditLog.")

        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Аутентифікує користувача, створює сесію при успіху та логує результат."""
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False

        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(self.user.username, "login_success")
        return True

    def is_authenticated(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевіряє наявність активної сесії без її продовження."""
        if self.session is None or not self.user.active:
            return False
        return self.session.is_active(timeout_sec)

    def logout(self) -> None:
        """Завершує поточну сесію та фіксує вихід у журналі аудиту."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        expected_type = self._ALLOWED_KEYS[key]
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Неправильний тип для ключа '{key}': отримано {type(value).__name__}."
            )
        setattr(self, key, value)


def run_demo() -> None:
    """Демонстрація роботи всіх класів Завдання 1."""
    print("=== Демонстрація Завдання 1 (ООП) ===\n")

    user = User(
        username="khrystyna",
        email="khrystyna.kuchma@lpnu.ua",
        password="StrongPass!23",
    )
    admin = Admin(
        username="sec_admin",
        email="admin.sec@lpnu.ua",
        password="AdminSecret#99",
        permissions=["read_logs", "ban_ip"],
    )
    print(f"Створено користувача: {user}")
    print(f"Створено адміністратора: {admin}\n")

    print("--- Перевірка зміни та валідації email ---")
    user.email = "kuchma.kb201@lpnu.ua"
    print(f"Email успішно змінено на: {user.email}")
    try:
        user.email = "invalid-email-format"
    except ValueError as exc:
        print(f"Валідація спрацювала (очікувана помилка): {exc}\n")

    print("--- Права адміністратора ---")
    admin.grant_permission("manage_firewall")
    print(f"Після додавання права: {admin}")
    print(f"Чи має право 'ban_ip'? {admin.has_permission('ban_ip')}")
    admin.revoke_permission("ban_ip")
    print(f"Після відкликання 'ban_ip': {admin}\n")

    print("--- Робота з UserAccount та сесіями ---")
    account = UserAccount(user=user)

    ok_fail = account.login("khrystyna", "WrongPassword", "192.168.1.15")
    print(
        f"Спроба входу з неправильним паролем: {ok_fail}, "
        f"is_authenticated={account.is_authenticated()}"
    )

    ok_success = account.login("khrystyna", "StrongPass!23", "192.168.1.15")
    print(
        f"Спроба входу з правильним паролем: {ok_success}, "
        f"is_authenticated={account.is_authenticated()}"
    )
    print(f"Доступ через __getitem__ account['user']: {account['user']}")

    if account.session is not None:
        account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 60)
    print(
        f"Перевірка після спливу таймауту ({SESSION_TIMEOUT_SEC} с): "
        f"is_authenticated={account.is_authenticated()}"
    )

    account.login("khrystyna", "StrongPass!23", "10.0.0.5")
    account.logout()
    print(f"Після виклику logout(): is_authenticated={account.is_authenticated()}\n")

    account.audit_log.show_all()