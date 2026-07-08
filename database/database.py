import sqlite3
import os

# Create the data folder if it doesn't exist
os.makedirs("data", exist_ok=True)

DB_PATH = "data/telemetry.db"

def create_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------
    # Process Events Table
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS process_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        pid INTEGER,
        parent_pid INTEGER,
        process_name TEXT,
        cpu_usage REAL,
        memory_usage REAL,
        command_line TEXT,
        start_time TEXT
    )
    """)

    # -------------------------
    # File Events Table
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        file_path TEXT
    )
    """)

    # -------------------------
    # Network Events Table
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        local_port INTEGER,
        remote_port INTEGER,
        process_id INTEGER
    )
    """)

    # -------------------------
    # Registry Events Table
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS registry_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        registry_key TEXT,
        event_type TEXT
    )
    """)

    conn.commit()
    conn.close()

    print("Database created successfully!")

if __name__ == "__main__":
    create_database()