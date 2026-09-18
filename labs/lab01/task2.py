from shared.student import STUDENT_NAME, VARIANT_NUMBER


USERS = {
    "security_chief": {
        "role": "security_officer",
        "clearance": 4,
        "department": "Security",
        "active": True,
    },
    "network_admin": {
        "role": "network_admin",
        "clearance": 3,
        "department": "Network",
        "active": True,
    },
    "help_desk": {
        "role": "support",
        "clearance": 1,
        "department": "Support",
        "active": True,
    },
    "auditor_ext": {
        "role": "auditor",
        "clearance": 3,
        "department": "Audit",
        "active": True,
    },
    "temp_worker": {
        "role": "temporary",
        "clearance": 1,
        "department": "Temp",
        "active": False,
    },
}

RESOURCES = [
    ("incident_reports", 4),
    ("network_topology", 3),
    ("user_manual", 1),
    ("vulnerability_scans", 3),
    ("root_access", 4),
    ("help_tickets", 1),
    ("penetration_tests", 4),
    ("firewall_rules", 3),
    ("software_licenses", 2),
    ("faq_docs", 1),
]

SECURITY_LEVELS = (
    "Unrestricted",
    "Limited",
    "Sensitive",
    "Classified",
)

BLOCKED_USERS = {
    "temp_worker",
    "fired_employee",
    "compromised_acc",
}


def check_access(username, resource_level):
    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user = USERS[username]

    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def main():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print()

    print("Ресурси:")
    print("-" * 55)

    for resource_name, level in RESOURCES:
        level_name = SECURITY_LEVELS[level - 1]
        print(f"{resource_name:<25} {level_name}")

    print()
    print("Перевірка доступу:")
    print("-" * 75)

    for username in USERS:
        for resource_name, level in RESOURCES:
            allowed, reason = check_access(username, level)

            if allowed:
                result = "ALLOW"
            else:
                result = f"DENY ({reason})"

            print(
                f"user=[{username}] resource=[{resource_name}] "
                f"-> {result}"
            )


if __name__ == "__main__":
    main()
