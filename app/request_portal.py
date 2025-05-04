import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import os
import telegram
from telegram import Bot
import asyncio
import hashlib
import secrets

# Telegram Bot Token
TELEGRAM_BOT_TOKEN = "8086690351:AAGw6YPEFcguK-WH_IWp-dXM7sKl_M_1nf4"

# Get the absolute path to the database and Excel files
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(base_dir, 'data')
os.makedirs(data_dir, exist_ok=True)

db_path = os.path.join(data_dir, 'club_database.db')
requests_excel_path = os.path.join(data_dir, 'requests_history.xlsx')
leaders_excel_path = os.path.join(base_dir, 'dataleaders_data.xlsx')
members_excel_path = os.path.join(base_dir, 'SnakeChaosHouse Members.xlsx')

# Initialize database and tables
def init_database():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create Members table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Members (
        name TEXT,
        whatsapp TEXT,
        PRIMARY KEY (name)
    )
    ''')
    
    # Create Leaders table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Leaders (
        name TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        telegram_id INTEGER
    )
    ''')
    
    # Create RequestHistory table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS RequestHistory (
        member_name TEXT,
        member_whatsapp TEXT,
        submitted_by TEXT,
        description TEXT,
        assigned_to TEXT,
        created_at TIMESTAMP,
        status TEXT DEFAULT 'Pending'
    )
    ''')
    
    # Initialize Members table if empty
    cursor.execute("SELECT COUNT(*) FROM Members")
    if cursor.fetchone()[0] == 0:
        try:
            members_df = pd.read_excel(members_excel_path)
            for _, row in members_df.iterrows():
                cursor.execute("""
                    INSERT OR IGNORE INTO Members (name, whatsapp)
                    VALUES (?, ?)
                """, (row['Name '], row['Whatsapp Number ']))
            conn.commit()
        except Exception as e:
            st.error(f"Error initializing members: {str(e)}")
    
    # Initialize Leaders table if empty
    cursor.execute("SELECT COUNT(*) FROM Leaders")
    if cursor.fetchone()[0] == 0:
        try:
            leaders_df = pd.read_excel(leaders_excel_path)
            for _, leader in leaders_df.iterrows():
                password_hash = hash_password(leader['Name'].lower())
                cursor.execute("""
                    INSERT OR IGNORE INTO Leaders (name, password_hash, telegram_id)
                    VALUES (?, ?, ?)
                """, (leader['Name'], password_hash, 5440702961))
            conn.commit()
        except Exception as e:
            st.error(f"Error initializing leaders: {str(e)}")
    
    return conn

# Function to hash passwords
def hash_password(password):
    salt = secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt

# Function to verify password
def verify_password(stored_password, provided_password):
    password_hash, salt = stored_password.split(':')
    return password_hash == hashlib.sha256((provided_password + salt).encode()).hexdigest()

# Initialize database
conn = init_database()
cursor = conn.cursor()

# Load members data from Excel
try:
    members_df = pd.read_excel(members_excel_path)
except Exception as e:
    st.error(f"Error loading members: {str(e)}")
    members_df = pd.DataFrame(columns=['Name ', 'Whatsapp Number '])

# Load leaders data from Excel
try:
    leaders_df = pd.read_excel(leaders_excel_path)
except Exception as e:
    st.error(f"Error loading leaders: {str(e)}")
    leaders_df = pd.DataFrame(columns=['Name'])

# Function to save requests to Excel
def save_to_excel(requests_df):
    try:
        # Create a new Excel writer
        with pd.ExcelWriter(requests_excel_path, engine='openpyxl') as writer:
            # Save the current requests
            requests_df.to_excel(writer, sheet_name='Requests', index=False)
            
            # Save a summary sheet with status counts
            status_summary = requests_df['status'].value_counts().reset_index()
            status_summary.columns = ['Status', 'Count']
            status_summary.to_excel(writer, sheet_name='Summary', index=False)
    except Exception as e:
        st.error(f"Error saving to Excel: {str(e)}")

# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_leader' not in st.session_state:
    st.session_state.current_leader = None

# Initialize Telegram bot
bot = Bot(token=TELEGRAM_BOT_TOKEN)

# Login page
if not st.session_state.logged_in:
    st.title("🔐 Login")
    
    leader_name = st.selectbox("Select Your Name:", leaders_df['Name'])
    password = st.text_input("Password:", type="password")
    
    change_pw = st.checkbox("Change Password?")
    if change_pw:
        old_password = st.text_input("Old Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        if st.button("Update Password"):
            cursor.execute("SELECT password_hash FROM Leaders WHERE name = ?", (leader_name,))
            result = cursor.fetchone()
            if result and verify_password(result[0], old_password):
                if new_password == confirm_password and new_password.strip() != "":
                    new_hash = hash_password(new_password)
                    cursor.execute("UPDATE Leaders SET password_hash = ? WHERE name = ?", (new_hash, leader_name))
                    conn.commit()
                    st.success("✅ Password updated successfully! Please login with your new password.")
                else:
                    st.error("❌ New passwords do not match or are empty.")
            else:
                st.error("❌ Old password is incorrect.")
    else:
        if st.button("Login"):
            cursor.execute("SELECT password_hash FROM Leaders WHERE name = ?", (leader_name,))
            result = cursor.fetchone()
            
            if result and verify_password(result[0], password):
                st.session_state.logged_in = True
                st.session_state.current_leader = leader_name
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid password!")

# Main application
if st.session_state.logged_in:
    st.title("📋 Request Submission System - Snake Chaos House")
    
    # Logout button
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.current_leader = None
        st.rerun()
    
    # Select member
    st.subheader("Select Member")
    selected_member = st.selectbox("Select Member:", members_df['Name '])

    # Get member's WhatsApp number
    member_whatsapp = members_df[members_df['Name '] == selected_member]['Whatsapp Number '].values[0]

    # Write request description
    st.subheader("Write Request Description")
    description = st.text_area("Description:")

    # Select receiving leader
    st.subheader("Select who will receive the request")
    assigned_to = st.selectbox("Send to:", leaders_df['Name'])

    # Submit button
    if st.button("Submit Request") and selected_member:
        # Get IDs from names
        member_id = members_df[members_df['Name '] == selected_member].index[0]
        assigned_to_id = leaders_df[leaders_df['Name'] == assigned_to].index[0]

        # Insert into RequestHistory table with all details
        cursor.execute("""
            INSERT INTO RequestHistory (
                member_name, member_whatsapp, submitted_by,
                description, assigned_to, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            selected_member, member_whatsapp, st.session_state.current_leader,
            description, assigned_to, datetime.now()
        ))
        conn.commit()

        # Save to Excel
        history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
        save_to_excel(history_df)

        # Send message via Telegram
        message = f"""
📋 New Request Submitted

👤 Member: {selected_member}
📱 WhatsApp: {member_whatsapp}
📝 Description: {description}
👨‍💼 Submitted by: {st.session_state.current_leader}
🎯 Assigned to: {assigned_to}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        try:
            # Send message to the leader's Telegram ID
            asyncio.run(bot.send_message(chat_id=5440702961, text=message))
            st.success("✅ Request submitted and sent via Telegram successfully!")
        except Exception as e:
            st.error(f"❌ Request submitted but failed to send via Telegram: {str(e)}")

    # Show request history
    st.subheader("Request History")
    history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)

    # Add status update functionality for assigned leaders
    if not history_df.empty:
        st.subheader("Update Request Status")
        
        # Filter requests assigned to the current leader
        leader_requests = history_df[history_df['assigned_to'] == st.session_state.current_leader]
        
        if not leader_requests.empty:
            selected_request = st.selectbox(
                "Select Request to Update:",
                leader_requests['member_name'] + " - " + leader_requests['created_at'].astype(str)
            )
            
            # Get the selected request's index
            selected_index = leader_requests[leader_requests['member_name'] + " - " + leader_requests['created_at'].astype(str) == selected_request].index[0]
            
            # Status options
            status_options = ['Pending', 'In Progress', 'Completed', 'Rejected']
            new_status = st.selectbox("New Status:", status_options)
            
            if st.button("Update Status"):
                # Update the status in the database
                cursor.execute("""
                    UPDATE RequestHistory 
                    SET status = ? 
                    WHERE member_name = ? AND created_at = ?
                """, (new_status, 
                      leader_requests.iloc[selected_index]['member_name'],
                      leader_requests.iloc[selected_index]['created_at']))
                conn.commit()
                
                # Save to Excel after status update
                history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
                save_to_excel(history_df)
                
                st.success(f"✅ Status updated to {new_status} successfully!")
        else:
            st.info("You don't have any assigned requests to update.")

    # Display the history table
    st.dataframe(history_df)

    # Add download button for Excel file
    if os.path.exists(requests_excel_path):
        with open(requests_excel_path, 'rb') as f:
            st.download_button(
                label="Download Requests History",
                data=f,
                file_name="requests_history.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

conn.close()

