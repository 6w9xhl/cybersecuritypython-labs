import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"password", "123456", "admin", "test", "welcome", "qwerty"}

import random

# 3 випадкові індекси і дублікати паролів
for _ in range(3):
    random_index = random.randint(0, len(passwords) - 1)
    passwords.append(passwords[random_index])


def analyze_password(password, criteria, forbidden, all_passwords):
    length = len(password)
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    # не буква і не цифра
    has_special = any(not char.isalnum() for char in password)

    # кількість виконаних умов
    conditions_met = sum([has_digit, has_upper, has_special, has_lower])

    # заборонений
    if password in forbidden or length < criteria["min_length"]:
        return "Заборонений"

    # дуже сильний
    # перевірка на унікальність: якщо кількість входжень у список більше 1, то не унікальний
    is_unique = all_passwords.count(password) == 1
    if conditions_met >= 3 and length >= criteria["min_length"] + 4 and is_unique:
        return "Дуже сильний"

    # сильний
    # відповідає всім 4 групам символів, але коротший або не унікальний
    if conditions_met >= 4:
        return "Сильний"

    # середній
    # мінімальна довжина і деякі (але не всі) критерії
    if length >= criteria["min_length"] and conditions_met >= 2:
        return "Середній"

    # слабкий
    # якщо виконується хоча б один критерій з груп символів
    if conditions_met >= 1:
        return "Слабкий"

    return "Не визначено"


print(
    f"Аналізатор надійності паролів | Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
)
print("-" * 60)
print(f"{'Пароль':<20} | {'Оцінка надійності'}")
print("-" * 60)

for pwd in passwords:
    result = analyze_password(pwd, criteria, forbidden_passwords, passwords)
    print(f"{pwd:<20} | {result}")
print("-" * 60)
