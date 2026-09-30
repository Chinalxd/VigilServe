"""Add join_time/online_time/offline_time columns to existing SQLite database."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "monitor.db"


def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def main():
    if not DB_PATH.exists():
        print(f"Database not found: {DB_PATH}")
        return

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    columns = ["join_time", "online_time", "offline_time"]
    for col in columns:
        if not column_exists(cur, "servers", col):
            cur.execute(f"ALTER TABLE servers ADD COLUMN {col} DATETIME")
            print(f"Added column: {col}")
        else:
            print(f"Column already exists: {col}")

    conn.commit()
    conn.close()
    print("Migration completed.")


if __name__ == "__main__":
    main()
