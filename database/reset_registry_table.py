import sqlite3

DB_PATH = "data/telemetry.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Delete old registry_events table
cursor.execute("DROP TABLE IF EXISTS registry_events")

print("Old registry_events table deleted.")

# Create new registry_events table
cursor.execute("""
CREATE TABLE registry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT NOT NULL,

    event_type TEXT NOT NULL,

    registry_path TEXT NOT NULL,

    hive TEXT,

    key_name TEXT,

    value_name TEXT,

    old_value TEXT,

    new_value TEXT,

    value_type INTEGER,

    process_id INTEGER,

    process_name TEXT,

    user_name TEXT,

    is_startup_location INTEGER DEFAULT 0,

    is_sensitive_key INTEGER DEFAULT 0,

    previous_exists INTEGER DEFAULT 0,

    operation_id TEXT,

    event_uuid TEXT
)
""")

print("New registry_events table created.")

conn.commit()
conn.close()

print("Registry table reset successfully.")