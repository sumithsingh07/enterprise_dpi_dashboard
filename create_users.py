import sqlite3

conn = sqlite3.connect("dpi_database.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
)
""")

cur.execute("""
INSERT OR IGNORE INTO users(username,password,role)
VALUES('admin','admin123','Admin')
""")

cur.execute("""
INSERT OR IGNORE INTO users(username,password,role)
VALUES('analyst','analyst123','Analyst')
""")

conn.commit()
conn.close()

print("Users table created successfully.")