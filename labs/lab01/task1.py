import os
import random
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

# фіксує початкову довжину списку, щоб обирати дублікати лише з оригінальних паролів
initial_length = len(passwords)
for _ in range(3):
    random_index = random.randint(0, initial_length - 1)
    passwords.append(passwords[random_index])


def analyze_password(password, criteria_dict, forbidden, all_passwords):
    length = len(password)
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    # заборонений(якшо в заблокованих або довжина менше 8)
    if password in forbidden or length < criteria_dict["min_length"]:
        return "Заборонений"

    # перевіряєм, чи виконуються вимоги зі словника criteria
    digits_ok = not criteria_dict.get("require_digits", False) or has_digit
    upper_ok = not criteria_dict.get("require_upper", False) or has_upper
    special_ok = not criteria_dict.get("require_special", False) or has_special

    # пароль відповідає всім обов'язковим критеріям безпеки
    meets_all_criteria = digits_ok and upper_ok and special_ok

    # Перевірка на унікальність у всьому списку
    is_unique = all_passwords.count(password) == 1

    # виконані всі критерії символів, довжина >= 12 (8+4), і унікальність
    if meets_all_criteria and length >= criteria_dict["min_length"] + 4 and is_unique:
        return "Дуже сильний"

    # містить усі потрібні символи(або не унікальний або менше 12 симв)
    if meets_all_criteria:
        return "Сильний"

    # підраховуєм кількість наявних груп символів (цифри, великі, малі, спеціальні)
    groups_present = sum([has_digit, has_upper, has_special, has_lower])

    #  середній. мінімальна довжина дотримана, (мінімум 2 групи)
    if groups_present >= 2:
        return "Середній"

    # слабкий: не заборонений і виконує хоча б один з критеріїв безпеки
    if groups_present >= 1:
        return "Слабкий"

    return "Не визначено"


print(
    f"Аналізатор надійності паролів | Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
)
print("-" * 65)
print(f"{'Пароль':<20} | {'Оцінка надійності'}")
print("-" * 65)

for pwd in passwords:
    result = analyze_password(pwd, criteria, forbidden_passwords, passwords)
    print(f"{pwd:<20} | {result}")
print("-" * 65)
