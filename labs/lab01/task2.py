import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

users = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

resources = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user", "suspended_acc"}

# вивід списку ресурсів
print("--- Ресурси системи  ---")
for res_name, res_level in resources:
    # рівні безпеки від 1 до 4, а індекси в кортежі від 0 до 3
    level_name = security_levels[res_level - 1]
    print(f"Ресурс: {res_name:<20} | Рівень: {level_name} ({res_level})")

print("\n--- Результати перевірки доступу ---")


# алгоритм перевірки доступу
def check_access(username, resource_level):
    # якшо користувача немає в словнику
    if username not in users:
        return "DENY (User not found)"

    # якшо користувач заблокований
    if username in blocked_users:
        return "DENY (User is blocked)"

    # якшо акаунт неактивний
    if not users[username]["active"]:
        return "DENY (Account inactive)"

    # перевірка рівня допуску
    if users[username]["clearance"] >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


# для фул перевірки додам неіснуючого користувача до списку
test_users = list(users.keys()) + ["unknown_hacker"]

# перевірка кожного користувача до кожного ресурсу
for current_user in test_users:
    print("-" * 60)
    for res_name, res_level in resources:
        access_result = check_access(current_user, res_level)
        print(f"user={current_user:<15} resource={res_name:<20} -> {access_result}")
