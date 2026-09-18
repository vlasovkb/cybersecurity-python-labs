import random

from shared.student import STUDENT_NAME, VARIANT_NUMBER


PASSWORDS = [
    "UserPass1!",
    "temp",
    "Cyber$ecur1ty",
    "guest",
    "P0w3rful@Pass",
    "login",
    "Defens3#2023",
    "abc123",
    "Elit3@Secur",
    "demo",
]

CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "temp",
    "guest",
    "login",
    "demo",
    "abc123",
    "user",
}


def check_password(password, all_passwords):
    min_length = CRITERIA["min_length"]

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_special = any(not char.isalnum() for char in password)
    has_lower = any(char.islower() for char in password)

    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    all_required = has_digit and has_upper and has_special

    if all_required:
        if (
            len(password) >= min_length + 4
            and all_passwords.count(password) == 1
        ):
            return "Дуже сильний"
        return "Сильний"

    criteria_count = sum(
        (has_digit, has_upper, has_special, has_lower)
    )

    if criteria_count >= 2:
        return "Середній"

    return "Слабкий"


def main():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print()

    all_passwords = PASSWORDS.copy()
    random_indices = random.sample(range(len(PASSWORDS)), 3)

    for index in random_indices:
        all_passwords.append(PASSWORDS[index])

    print("Аналіз паролів:")
    print("-" * 55)
    print(f"{'Пароль':<22} Рівень")
    print("-" * 55)

    for password in all_passwords:
        level = check_password(password, all_passwords)
        print(f"{password:<22} {level}")

    print("-" * 55)


if __name__ == "__main__":
    main()
