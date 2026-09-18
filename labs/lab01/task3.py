import csv
import hashlib
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from shared.student import STUDENT_NAME, VARIANT_NUMBER


MIN_PASSWORD_LENGTH = 8
SALT = f"{VARIANT_NUMBER:05d}"

DATA_DIR = Path(__file__).parent / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"


class ValidationError(Exception):


def generate_hash(password: str, salt: str = "00000") -> str:
    """Створює SHA-1 хеш пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Пароль занадто короткий.")

    return hashlib.sha1(
        (password + salt).encode("utf-8")
    ).hexdigest()


def create_user(username, password):
    password_hash = generate_hash(password, SALT)
    return username, password_hash


def create_users(users_list):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with USERS_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for username, password in users_list:
            writer.writerow(create_user(username, password))


def load_users():
    users_db = []

    with USERS_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) == 2:
                users_db.append(tuple(row))

    return users_db


def print_users(users_db):
    print("-" * 75)
    print(f"{'Username':<20} Hash")
    print("-" * 75)

    for username, password_hash in users_db:
        print(f"{username:<20} {password_hash}")

    print("-" * 75)


def log_event(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        result = "failure"

        try:
            success = function(*args, **kwargs)
            if success:
                result = "success"
            return success
        finally:
            DATA_DIR.mkdir(parents=True, exist_ok=True)

            username = (
                args[0] if args else kwargs.get("username")
            )
            event = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": list(args),
                "kwargs": kwargs,
            }

            events = []
            if LOG_FILE.exists():
                try:
                    with LOG_FILE.open("r", encoding="utf-8") as file:
                        loaded = json.load(file)
                        if isinstance(loaded, list):
                            events = loaded
                except (json.JSONDecodeError, OSError):
                    events = []

            events.append(event)

            with LOG_FILE.open("w", encoding="utf-8") as file:
                json.dump(
                    events,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

    return wrapper


users_db = []


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError(
            "Логін або пароль не можуть бути порожніми."
        )

    password_hash = generate_hash(password, SALT)

    for user, saved_hash in users_db:
        if user == username:
            return password_hash == saved_hash

    return False


def main():
    global users_db

    print(f"Студент: {STUDENT_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("Алгоритм: SHA-1")
    print(f"Сіль: {SALT}")
    print()

    users_to_register = (
        ("user01", "Password1!"),
        ("user02", "Security2@"),
        ("user03", "Python3#Lab"),
        ("user04", "Network4!"),
        ("user05", "Cyber5$Lab"),
        ("user06", "Admin6@Pass"),
        ("user07", "Secure7#Key"),
        ("user08", "Student8!"),
        ("user09", "Access9$"),
        ("user10", "System10@"),
    )

    try:
        create_users(users_to_register)
        users_db = load_users()

        print("База користувачів:")
        print_users(users_db)

        print()
        print("Спроби входу:")
        print("user01 / Password1!:", login("user01", "Password1!"))
        print("user01 / wrongpass:", login("user01", "wrongpass"))
        print("unknown / Password1!:", login("unknown", "Password1!"))

    except FileNotFoundError:
        print("Файл не знайдено.")
    except PermissionError:
        print("Недостатньо прав доступу.")
    except IOError:
        print("Помилка введення/виведення.")
    except ValidationError as error:
        print(f"Помилка валідації: {error}")
    except ValueError as error:
        print(f"Помилка значення: {error}")


if __name__ == "__main__":
    main()
