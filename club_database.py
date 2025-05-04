import pandas as pd
import sqlite3

# Read Excel file
excel_file = 'SnakeChaosHouse Members.xlsx'
df = pd.read_excel(excel_file)  # Will read the first sheet by default

# Create SQLite database
conn = sqlite3.connect('club_database.db')
cursor = conn.cursor()

# Create table automatically based on column names
table_name = 'Members'
df.to_sql(table_name, conn, if_exists='replace', index=False)

print(f"Data successfully imported to table '{table_name}' in the database.")

conn.close()
