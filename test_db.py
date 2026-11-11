import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

try:
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

    if connection.is_connected():
        print("SUCCESS: Python connected to MariaDB!")
        print("Database:", connection.database)

    connection.close()

except mysql.connector.Error as error:
    print("Database connection failed:", error)
