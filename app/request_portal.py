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
from whatsapp_api_client_python import API

# Telegram Bot Token
TELEGRAM_BOT_TOKEN = "8086690351:AAGw6YPEFcguK-WH_IWp-dXM7sKl_M_1nf4"

# WhatsApp API configuration
WHATSAPP_API_TOKEN = "dd62f35be0d847158901dc755381cf763277c9bd7115412d9c"
WHATSAPP_API_ID = "7105237464"

# Initialize WhatsApp API
whatsapp_api = API.GreenAPI(WHATSAPP_API_ID, WHATSAPP_API_TOKEN)

# WhatsApp configuration
SCH_CLUB_WHATSAPP = "201507466533"

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
    
    # Remove unwanted leaders
    cursor.execute("DELETE FROM Leaders WHERE LOWER(name) = 'uosf radwan'")
    conn.commit()
    
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
        telegram_id INTEGER,
        whatsapp TEXT,
        is_admin BOOLEAN DEFAULT FALSE
    )
    ''')
    
    # Add whatsapp column to Leaders table if it doesn't exist
    try:
        cursor.execute("SELECT whatsapp FROM Leaders LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE Leaders ADD COLUMN whatsapp TEXT")
    
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
    
    # Add SCH Club as a leader with WhatsApp notifications
    try:
        cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", ("SCH Club",))
        if cursor.fetchone()[0] == 0:
            password_hash = hash_password("schclub".lower())
            cursor.execute("""
                INSERT INTO Leaders (name, password_hash, telegram_id, whatsapp, is_admin)
                VALUES (?, ?, ?, ?, ?)
            """, ("SCH Club", password_hash, None, "201507466533", True))
            conn.commit()
    except Exception as e:
        st.error(f"Error adding SCH Club: {str(e)}")
    
    # Initialize Members table if empty
    cursor.execute("SELECT COUNT(*) FROM Members")
    if cursor.fetchone()[0] == 0:
        try:
            members_df = pd.read_excel(members_excel_path)
            # Clean the data
            members_df = members_df.dropna(subset=['Name '])  # Remove rows with empty names
            members_df['Name '] = members_df['Name '].astype(str).str.strip()  # Clean names
            members_df['Whatsapp Number '] = members_df['Whatsapp Number '].astype(str).str.strip()  # Clean numbers
            
            for _, row in members_df.iterrows():
                if row['Name '] and row['Name '] != 'nan':  # Only insert if name is not empty
                    cursor.execute("""
                        INSERT OR IGNORE INTO Members (name, whatsapp)
                        VALUES (?, ?)
                    """, (row['Name '], row['Whatsapp Number '] if pd.notna(row['Whatsapp Number ']) else ''))
            conn.commit()
        except Exception as e:
            st.error(f"Error initializing members: {str(e)}")
    
    # تحديث أو إضافة القادة من الإكسل كل مرة
    try:
        leaders_df = pd.read_excel(leaders_excel_path)
        # Print column names for debugging
        print("Leaders Excel columns:", leaders_df.columns.tolist())
        
        # Get the WhatsApp column name (case insensitive)
        whatsapp_col = next((col for col in leaders_df.columns if 'whatsapp' in col.lower()), None)
        
        for i, leader in leaders_df.iterrows():
            cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (leader['Name'],))
            if cursor.fetchone()[0] == 0:
                password_hash = hash_password(leader['Name'].lower())
                # Set first leader as admin, others as non-admin
                is_admin = True if i == 0 else False
                whatsapp_number = leader[whatsapp_col] if whatsapp_col and pd.notna(leader[whatsapp_col]) else ''
                cursor.execute("""
                    INSERT OR IGNORE INTO Leaders (name, password_hash, telegram_id, whatsapp, is_admin)
                    VALUES (?, ?, ?, ?, ?)
                """, (leader['Name'], password_hash, 5440702961, whatsapp_number, is_admin))
        conn.commit()
    except Exception as e:
        st.error(f"Error syncing leaders: {str(e)}")
        st.error(f"Available columns: {leaders_df.columns.tolist() if 'leaders_df' in locals() else 'Could not read Excel file'}")
    
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

# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_leader' not in st.session_state:
    st.session_state.current_leader = None

# Initialize Telegram bot
bot = Bot(token=TELEGRAM_BOT_TOKEN)

# Login page
if not st.session_state.logged_in:
    st.title("Login")
    
    # Load leaders data from database
    try:
        leaders_df = pd.read_sql_query("SELECT name FROM Leaders", conn)
        # Exclude SCH Club from login list
        leaders_df = leaders_df[leaders_df['name'] != 'SCH Club']
    except Exception as e:
        st.error(f"Error loading leaders: {str(e)}")
        leaders_df = pd.DataFrame(columns=['name'])
    
    leader_name = st.selectbox("Select Your Name:", leaders_df['name'])
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
                    st.success("Password updated successfully! Please login with your new password.")
                else:
                    st.error("New passwords do not match or are empty.")
            else:
                st.error("Old password is incorrect.")
    else:
        if st.button("Login"):
            cursor.execute("SELECT password_hash FROM Leaders WHERE name = ?", (leader_name,))
            result = cursor.fetchone()
            
            if result and verify_password(result[0], password):
                st.session_state.logged_in = True
                st.session_state.current_leader = leader_name
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid password!")

# Main application
async def main():
    if st.session_state.logged_in:
        # Load leaders data from database
        try:
            leaders_df = pd.read_sql_query("SELECT name FROM Leaders", conn)
            # Exclude SCH Club from send-to list
            leaders_df = leaders_df[leaders_df['name'] != 'SCH Club']
        except Exception as e:
            st.error(f"Error loading leaders: {str(e)}")
            leaders_df = pd.DataFrame(columns=['name'])
        
        st.title("Request Submission System - Snake Chaos House")
        
        # Logout button
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.current_leader = None
            st.rerun()
        
        # Add new leader section in sidebar (admin only)
        if st.session_state.current_leader:
            cursor.execute("SELECT is_admin FROM Leaders WHERE name = ?", (st.session_state.current_leader,))
            result = cursor.fetchone()
            is_admin = result[0] if result else False
            
            if is_admin:
                st.sidebar.title("Leader Management")
                
                # Add new leader section
                st.sidebar.subheader("Add New Leader")
                new_leader_name = st.sidebar.text_input("Leader Name")
                new_leader_telegram_id = st.sidebar.text_input("Telegram ID")
                
                if st.sidebar.button("Add Leader"):
                    if new_leader_name and new_leader_telegram_id:
                        try:
                            # Check if leader already exists
                            cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (new_leader_name,))
                            count = cursor.fetchone()[0]
                            
                            if count == 0:
                                # Hash the leader's name as initial password
                                password_hash = hash_password(new_leader_name.lower())
                                # Insert new leader
                                cursor.execute("""
                                    INSERT INTO Leaders (name, password_hash, telegram_id, whatsapp, is_admin)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (new_leader_name, password_hash, int(new_leader_telegram_id), None, False))
                                conn.commit()
                                st.sidebar.success(f"Leader {new_leader_name} added successfully!")
                                st.sidebar.info("Initial password is their name in lowercase")
                                # Refresh leaders list
                                leaders_df = pd.read_sql_query("SELECT name FROM Leaders", conn)
                                st.rerun()
                            else:
                                st.sidebar.error("Leader already exists!")
                        except Exception as e:
                            st.sidebar.error(f"Error adding leader: {str(e)}")
                    else:
                        st.sidebar.error("Please fill in all fields!")
                
                # Remove leader section
                st.sidebar.subheader("Remove Leader")
                remove_leader_name = st.sidebar.selectbox(
                    "Select Leader to Remove:",
                    leaders_df[leaders_df['name'] != st.session_state.current_leader]['name']
                )
                
                if st.sidebar.button("Remove Leader"):
                    if remove_leader_name:
                        try:
                            # Check if leader exists
                            cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (remove_leader_name,))
                            count = cursor.fetchone()[0]
                            
                            if count > 0:
                                # Delete leader
                                cursor.execute("DELETE FROM Leaders WHERE name = ?", (remove_leader_name,))
                                conn.commit()
                                st.sidebar.success(f"Leader {remove_leader_name} removed successfully!")
                                # Refresh leaders list
                                leaders_df = pd.read_sql_query("SELECT name FROM Leaders", conn)
                                st.rerun()
                            else:
                                st.sidebar.error("Leader not found!")
                        except Exception as e:
                            st.sidebar.error(f"Error removing leader: {str(e)}")
                    else:
                        st.sidebar.error("Please select a leader to remove!")
                
                # Make leader admin section
                st.sidebar.subheader("Make Leader Admin")
                admin_leader_name = st.sidebar.selectbox(
                    "Select Leader to Make Admin:",
                    leaders_df[leaders_df['name'] != st.session_state.current_leader]['name']
                )
                
                if st.sidebar.button("Make Admin"):
                    if admin_leader_name:
                        try:
                            # Check if leader exists
                            cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (admin_leader_name,))
                            count = cursor.fetchone()[0]
                            
                            if count > 0:
                                # Update leader to admin
                                cursor.execute("UPDATE Leaders SET is_admin = TRUE WHERE name = ?", (admin_leader_name,))
                                conn.commit()
                                st.sidebar.success(f"Leader {admin_leader_name} is now an admin!")
                                st.rerun()
                            else:
                                st.sidebar.error("Leader not found!")
                        except Exception as e:
                            st.sidebar.error(f"Error making leader admin: {str(e)}")
                    else:
                        st.sidebar.error("Please select a leader to make admin!")

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
        assigned_to = st.selectbox("Send to:", leaders_df['name'])
        
        # Submit button
        if st.button("Submit Request") and selected_member:
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

            # Prepare message
            message = f"""
📋 *New Request Submitted*

👤 *Member:* {selected_member}
📱 *WhatsApp:* {member_whatsapp}

📝 *Description:*
{description}

👨‍💼 *Submitted by:* {st.session_state.current_leader}
🎯 *Assigned to:* {assigned_to}

⏰ *Date & Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            try:
                # Send to Telegram
                cursor.execute("SELECT telegram_id FROM Leaders WHERE name = ?", (assigned_to,))
                result = cursor.fetchone()
                telegram_id = result[0] if result else None

                if telegram_id:
                    # Send message via Telegram
                    success = await send_message("Telegram", telegram_id, message)
                    if success:
                        st.success("Request submitted and sent via Telegram successfully!")
                    else:
                        st.warning("Request submitted but failed to send via Telegram.")
                else:
                    st.warning("Telegram ID not found for the assigned leader. Message not sent.")
                
                # Always send to SCH Club WhatsApp
                whatsapp_success = await send_message("WhatsApp", SCH_CLUB_WHATSAPP, message)
                if whatsapp_success:
                    st.success("Request also sent to SCH Club WhatsApp successfully!")
            except Exception as e:
                st.error(f"Request submitted but failed to send message: {str(e)}")

        # Show request history
        st.title("Request History")
        
        # Create two tabs
        tab1, tab2 = st.tabs(["All Requests", "My Assigned Requests"])
        
        with tab1:
            st.subheader("All Requests")
            all_requests_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
            st.dataframe(all_requests_df)
            
            # Add download button for all requests
            if os.path.exists(requests_excel_path):
                with open(requests_excel_path, 'rb') as f:
                    st.download_button(
                        label="Download All Requests History",
                        data=f,
                        file_name="all_requests_history.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
        
        with tab2:
            st.subheader("My Assigned Requests")
            # Filter requests assigned to the current leader
            my_requests_df = pd.read_sql_query("""
                SELECT * FROM RequestHistory 
                WHERE assigned_to = ? 
                ORDER BY created_at DESC
            """, conn, params=[st.session_state.current_leader])
            
            st.dataframe(my_requests_df)
            
            # Add status update functionality for assigned requests
            if not my_requests_df.empty:
                st.subheader("Update Request Status")
                
                selected_request = st.selectbox(
                    "Select Request to Update:",
                    my_requests_df['member_name'] + " - " + my_requests_df['created_at'].astype(str)
                )
                
                try:
                    selected_index = my_requests_df[my_requests_df['member_name'] + " - " + my_requests_df['created_at'].astype(str) == selected_request].index[0]
                    
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
                              my_requests_df.iloc[selected_index]['member_name'],
                              my_requests_df.iloc[selected_index]['created_at']))
                        conn.commit()
                        
                        # Save to Excel after status update
                        history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
                        save_to_excel(history_df)
                        st.success("Status updated successfully!")
                except IndexError:
                    st.error("No matching request found. Please select a valid request.")
                except Exception as e:
                    st.error(f"An error occurred while updating the status: {str(e)}")
            else:
                st.info("You don't have any assigned requests to update.")

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

# Function to format phone number for WhatsApp
def format_phone_number(phone):
    # Remove any non-digit characters
    phone = ''.join(filter(str.isdigit, str(phone)))
    # Add country code if not present
    if not phone.startswith('20'):
        phone = '20' + phone
    # Add the required @c.us suffix for GreenAPI
    return f"{phone}@c.us"

# Function to send message via selected platform
async def send_message(platform, recipient_id, message):
    if platform == "Telegram":
        try:
            await bot.send_message(chat_id=recipient_id, text=message)
            return True
        except Exception as e:
            st.error(f"Failed to send Telegram message: {str(e)}")
            return False
    elif platform == "WhatsApp":
        try:
            formatted_number = format_phone_number(SCH_CLUB_WHATSAPP)
            response = whatsapp_api.sending.sendMessage(formatted_number, message)
            # Print the response content for debugging
            st.error(f"WhatsApp API response: {getattr(response, 'data', str(response))}")
            # Try to check for success in the response data
            if hasattr(response, 'data') and isinstance(response.data, dict) and response.data.get('idMessage'):
                return True
            else:
                return False
        except Exception as e:
            st.error(f"Failed to send WhatsApp message: {str(e)}")
            return False

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())

conn.close()