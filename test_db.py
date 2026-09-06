import psycopg2
from getpass import getpass

password = getpass("Enter PostgreSQL password: ")

try:
    conn = psycopg2.connect(
        host="localhost",
        port="5432",
        database="online_quiz",
        user="postgres",
        password=password
    )

    print("PostgreSQL connection successful! ✅")
    conn.close()

except Exception as e:
    print("Connection failed ❌")
    print(e)