from database.db import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(network_events)")

rows = cursor.fetchall()

for row in rows:
    print(dict(row))

conn.close()