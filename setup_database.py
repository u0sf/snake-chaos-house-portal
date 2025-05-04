import sqlite3

# Connect to the database
conn = sqlite3.connect('club_database.db')
cursor = conn.cursor()

# Create Leaders table
cursor.execute('''
CREATE TABLE IF NOT EXISTS Leaders (
    leader_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    email TEXT
)
''')

# Create Requests table
cursor.execute('''
CREATE TABLE IF NOT EXISTS Requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER,
    submitted_by_leader_id INTEGER,
    description TEXT,
    assigned_to_leader_id INTEGER,
    created_at DATETIME,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (member_id) REFERENCES Members(member_id),
    FOREIGN KEY (submitted_by_leader_id) REFERENCES Leaders(leader_id),
    FOREIGN KEY (assigned_to_leader_id) REFERENCES Leaders(leader_id)
)
''')

# Insert some sample leaders
sample_leaders = [
    ('Ahmed', 'President', 'ahmed@example.com'),
    ('Sara', 'Vice President', 'sara@example.com'),
    ('Omar', 'Secretary', 'omar@example.com')
]

cursor.executemany('INSERT INTO Leaders (name, role, email) VALUES (?, ?, ?)', sample_leaders)

# Commit changes and close connection
conn.commit()
conn.close()

print("Database tables created successfully!") 