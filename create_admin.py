from getpass import getpass
from werkzeug.security import generate_password_hash

from app import get_db_connection


ADMIN_EMAIL = "raj792negi@gmail.com"


print()
print("========================================")
print("       ONLINE QUIZ - ADMIN SETUP")
print("========================================")
print()

password = getpass("Create Admin Password: ")
confirm_password = getpass("Confirm Admin Password: ")

if not password:
    print("\n❌ Password cannot be empty.")
    raise SystemExit

if password != confirm_password:
    print("\n❌ Passwords do not match.")
    raise SystemExit

if len(password) < 8:
    print("\n❌ Password must be at least 8 characters.")
    raise SystemExit


hashed_password = generate_password_hash(password)

connection = None
cursor = None

try:
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM admins
        WHERE email = %s
        LIMIT 1
        """,
        (ADMIN_EMAIL,)
    )

    existing_admin = cursor.fetchone()

    if existing_admin:
        print("\n⚠️ Admin account already exists.")
        print("No new account was created.")

    else:
        cursor.execute(
            """
            INSERT INTO admins (name, email, password)
            VALUES (%s, %s, %s)
            """,
            (
                "Raj Negi",
                ADMIN_EMAIL,
                hashed_password
            )
        )

        connection.commit()

        print()
        print("✅ ADMIN ACCOUNT CREATED SUCCESSFULLY!")
        print()
        print("Name  :", "Raj Negi")
        print("Email :", ADMIN_EMAIL)
        print("Password: Saved securely as a hash.")
        print()

except Exception as e:
    if connection:
        connection.rollback()

    print()
    print("❌ Admin setup error:")
    print(e)

finally:
    if cursor:
        cursor.close()

    if connection:
        connection.close()