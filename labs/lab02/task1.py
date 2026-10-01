# завдання 1: Модель користувача, сесії, журналу аудиту та облікового запису

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

# правила безпеки
PBKDF2_ITERATIONS = 100_000  # скільки разів алгоритм буде перемішувати пароль
SALT_SIZE_BYTES = 16
SESSION_TIMEOUT_SEC = (
    900  # 15 хвилин, час, після якого неактивного користувача викине з системи
)
# шаблон пошти щось@щось.ком
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
)


# створення "картки працівника"
class User:
    # це функція-будівельник. вона запускається автоматично, коли ми створюємо нового користувача
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        password: str | None = None,
        active: bool = True,
    ) -> None:
        # перевірка, чи не є ім'я користувача порожнім рядком або рядком лише з пробілів
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
        # дозволяє програмі просто прочитати пошту, коли хтось пише user.email
        return self._email

    # а це спрацює, коли хтось спробує змінити пошту(user.email = нова@пошта)
    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_REGEX.match(
            value
        ):  # перевіряємо чи взагалі це текст і звіряємо з нашим шаблоном
            raise ValueError(f"Некоректний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str) -> None:
        #Хешує пароль за допомогою PBKDF2-HMAC-SHA256 із випадковою сіллю
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має бути рядком довжиною щонайменше 4 символи.")
        # генеруємо 16 байт солі
        self.__password_salt = os.urandom(SALT_SIZE_BYTES)
        # беремо пароль, перетворюємо на байти, додаємо сіль і мішаємо 100 тисяч разів
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою безпечного порівняння hmac.compare_digest"""
        if not self.__password_hash or not self.__password_salt:
            return False
        # коли людина хоче зайти, ми беремо введений пароль, додаємо нашу сіль і мішаємо
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        # порівнюємо результат із тим, що збережено. Якщо співпало, пароль правильний
        return hmac.compare_digest(self.__password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача"""
        self.active = False

    def __str__(self) -> str:
        # це метод, який визначає, як картка виглядатиме(визначаєсо слово для статусу)
        status = "active" if self.active else "inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status={status})"
        )


# Директорська картка
class Admin(User):
    """Клас адміністратора, що наслідує User та додає управління правами доступу"""

    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        permissions: list[str] | set[str] | None = None,
        active: bool = True,
    ) -> None:
        # super() каже: клас User, налаштуй мені ім'я, пошту і пароль за своїми правилами
        super().__init__(
            username=username,
            email=email,
            role="admin",
            password=password,
            active=active,
        )
        # записуємо права. Якщо нам передали якийсь список, робимо з нього унікальну множину (set).
        # якщо нічого не передали, створюємо порожню множину set()
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає право доступу адміністратору"""
        # перевіряємо, чи не передали нам порожню назву права
        if not permission or not permission.strip():
            raise ValueError("Назва дозволу не може бути порожньою.")
        # додаємо право в нашу множину (множина автоматично ігнорує дублікати)
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        """Відкликає право доступу адміністратора"""
        # Видаляємо право з множини (метод discard не видає помилку, якщо такого права і так не було)
        self.permissions.discard(permission.strip())

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність вказаного дозволу"""
        # перевіряє, чи є слово у множині( тру або фолс)
        return permission.strip() in self.permissions

    def __str__(self) -> str:
        # як виглядає картка директора при друку
        status = "active" if self.active else "inactive"
        # склеюємо всі права через кому (або пишемо "none", якщо їх немає)
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "none"
        return (
            f"Admin(username='{self.username}', email='{self.email}', "
            f"status={status}, permissions=[{perms}])"
        )


# Таймер присутності
class Session:
    """Клас користувацької сесії з контролем часу активності в UTC"""

    def __init__(self, ip: str) -> None:
        # перевіряємо, чи вказали IP-адресу комп'ютера
        if not ip or not ip.strip():
            raise ValueError("IP-адреса сесії не може бути порожньою.")
        now = datetime.now(timezone.utc)  # записуємо точний світовий час
        # зберігаємо IP-адресу без зайвих пробілів.
        self.ip: str = ip.strip()
        # час заходу у систему
        self.login_time: datetime = now
        # час останнього кліку мишкою ( на початку він співпадає з часом заходу)
        self.last_activity: datetime = now

    def touch(self) -> None:
        """Оновлює час останньої активності сесії поточним часом UTC"""
        # кожен раз, коли користувач щось робить, ми скидаємо цей таймер на "зараз"
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут з моменту останньої активності"""
        # Перевіряємо, щоб таймаут не був від'ємним або нулем
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії (timeout_sec) має бути додатним числом.")
        # дивимось котра зараз година
        now = datetime.now(timezone.utc)
        # вВіднімаємо від "зараз" час останнього кліку. Якщо ця різниця менша або дорівнює
        # дозволеним 900 секундам — значить, сесія ще активна (повертаємо True)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        # для красового друку таймера
        return (
            f"Session(ip='{self.ip}', login_time='{self.login_time.isoformat()}', "
            f"last_activity='{self.last_activity.isoformat()}')"
        )


@dataclass(
    frozen=True
)  # frozen=True означає, що цей запис "заморожений", його неможливо відредагувати після створення
class AuditEntry:
    """Запис у журналі аудиту"""

    timestamp: datetime  # коли
    username: str  # хто
    action: str  # що


class AuditLog:
    """Журнал аудиту подій безпеки"""

    def __init__(self) -> None:
        # На старті створюємо порожній список для зберігання записів
        self._entries: list[AuditEntry] = []

    @property
    def entries(self) -> list[AuditEntry]:
        """Повертає копію списку записів аудиту"""
        # ми не віддаємо оригінальний список, ми повертаємо його копію list(...)
        # щоб ніхто випадково не стер історію
        return list(self._entries)

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис із поточним часом UTC"""
        # cтворюємо нову "сторіночку" запису
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        # додаємо цю сторіночку в кінець нашого списку-журналу
        self._entries.append(entry)

    def show_all(self) -> None:
        """Виводить усі записи журналу аудиту в консоль"""
        print("=== Audit Log Entries ===")
        if not self._entries:
            print("(Журнал порожній)")
            return
        # якщо записи є, перебираємо їх по одному
        for entry in self._entries:
            # Рік-Місяць-День Година:Хвилина:Секунда
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{ts}] user='{entry.username}' | action='{entry.action}'")


class UserAccount:
    """Обліковий запис, що об'єднує User, Session та AuditLog (композиція)"""

    _ALLOWED_KEYS: ClassVar[dict[str, type | tuple[type, ...]]] = {
        "user": User,
        "session": (Session, type(None)),
        "audit_log": AuditLog,
    }

    def __init__(
        self,
        user: User,  # обов'язково треба дати картку
        session: Session | None = None,  # таймера може поки не бути
        audit_log: AuditLog | None = None,  # журнал може бути свій, або створимо новий
    ) -> None:
        # перевіряємо, чи нам дали саме ті об'єкти, які ми просили (захист від помилок)
        if not isinstance(user, User):
            raise TypeError("Поле 'user' має бути екземпляром класу User.")
        if session is not None and not isinstance(session, Session):
            raise TypeError("Поле 'session' має бути екземпляром Session або None.")
        if audit_log is not None and not isinstance(audit_log, AuditLog):
            raise TypeError("Поле 'audit_log' має бути екземпляром AuditLog.")

        self.user: User = user
        self.session: Session | None = session
        # якщо журнал не дали, то створюємо свій власний: AuditLog()
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Спроба зайти в с-му"""
        # Перевіряємо три умови провалу:
        # 1. Ім'я не збігається з тим, що на картці?
        # 2. Або картка деактивована?
        # 3. Або ввели неправильний пароль?
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            # якщо хоч щось не так — пишемо в журнал провал ("login_failure")
            self.audit_log.add_log(username, "login_failure")
            return False
        # якщо всі перевірки пройдені: створюємо новий таймер (сесію) з IP-адресою
        self.session = Session(ip=ip)
        # "Торкаємося" таймера, щоб він почав відлік
        self.session.touch()
        # Записуємо в журнал успішний вхід
        self.audit_log.add_log(self.user.username, "login_success")
        return True

    def is_authenticated(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        """Перевіряє наявність активної сесії без її продовження"""
        # Якщо таймера взагалі немає, або картку раптово заблокували — значить не в системі
        if self.session is None or not self.user.active:
            return False
        # Інакше питаємо сам таймер: "ти ще активний в межах 900 секунд?"
        return self.session.is_active(timeout_sec)

    def logout(self) -> None:
        """Завершує поточну сесію та фіксує вихід у журналі аудиту."""
        # Якщо ми були в системі (був таймер):
        if self.session is not None:
            # Знищуємо таймер.
            self.session = None
            # Записуємо в журнал подію виходу.
            self.audit_log.add_log(self.user.username, "logout")

    # Спеціальний метод, який дозволяє писати account["user"] замість account.user.
    def __getitem__(self, key: str) -> Any:
        # Якщо хтось просить ключ, якого немає в нашому списку дозволених (наприклад, секретний пароль):
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        # Віддаємо потрібний атрибут.
        return getattr(self, key)

    # Спеціальний метод для запису: account["session"] = нова_сесія.
    def __setitem__(self, key: str, value: Any) -> None:
        # Перевіряємо, чи дозволено змінювати цей ключ.
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий або заборонений ключ: '{key}'")
        # Дізнаємося, який тип даних очікується для цього ключа.
        expected_type = self._ALLOWED_KEYS[key]
        # Перевіряємо, чи не намагаються нам підсунути число замість таймера.
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Неправильний тип для ключа '{key}': отримано {type(value).__name__}."
            )
        # Якщо все ок, оновлюємо значення.
        setattr(self, key, value)
