from typing import Any

STUDENT_NAME = "Кучма Христина Юріївна"
GROUP_NAME = "КБ-201"
VARIANT_NUMBER = 1


def get_student_info() -> dict[str, Any]:
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
