import sqlite3

conn = sqlite3.connect("data/telemetry.db")
cursor = conn.cursor()

columns = [
    ("is_broadcast", "INTEGER"),
]

cursor.execute("PRAGMA table_info(network_events)")
existing = {row[1] for row in cursor.fetchall()}

for name, datatype in columns:
    if name not in existing:
        cursor.execute(f"ALTER TABLE network_events ADD COLUMN {name} {datatype}")
        print(f"Added {name}")
    else:
        print(f"{name} already exists")

conn.commit()
conn.close()