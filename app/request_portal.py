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
import plotly.express as px

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
    
    # Create Members table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Members (
        name TEXT,
        whatsapp TEXT,
        email TEXT,
        password_hash TEXT,
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'Pending',
        comment TEXT,
        rating INTEGER,
        response_time_rating INTEGER,
        service_quality_rating INTEGER,
        communication_rating INTEGER,
        priority TEXT DEFAULT 'Medium'
    )
    ''')
    
    # Add missing columns if they don't exist
    try:
        cursor.execute("SELECT response_time_rating, service_quality_rating, communication_rating FROM RequestHistory LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE RequestHistory ADD COLUMN response_time_rating INTEGER")
        cursor.execute("ALTER TABLE RequestHistory ADD COLUMN service_quality_rating INTEGER")
        cursor.execute("ALTER TABLE RequestHistory ADD COLUMN communication_rating INTEGER")
        conn.commit()
    
    # Add priority column if it doesn't exist
    try:
        cursor.execute("SELECT priority FROM RequestHistory LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE RequestHistory ADD COLUMN priority TEXT DEFAULT 'Medium'")
        conn.commit()
    
    # Add Uosf Radwan as admin if not exists
    cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = 'Uosf Radwan'")
    if cursor.fetchone()[0] == 0:
        password_hash = hash_password('uosf radwan')  # Default password is name in lowercase
        cursor.execute("""
            INSERT INTO Leaders (name, password_hash, is_admin)
            VALUES (?, ?, ?)
        """, ('Uosf Radwan', password_hash, True))
        conn.commit()
    else:
        # Update existing Uosf Radwan to be admin
        cursor.execute("""
            UPDATE Leaders 
            SET is_admin = TRUE 
            WHERE name = 'Uosf Radwan'
        """)
        conn.commit()
    
    return conn

# Function to hash passwords
def hash_password(password):
    salt = secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt

# Function to verify password
def verify_password(stored_password, provided_password):
    password_hash, salt = stored_password.split(':')
    return password_hash == hashlib.sha256((provided_password + salt).encode()).hexdigest()

# Function to initialize members from Excel
def init_members_from_excel(conn):
    try:
        cursor = conn.cursor()
        # Read members data from Excel
        members_df = pd.read_excel(members_excel_path)
        
        # Clean the data
        members_df = members_df.dropna(subset=['Name '])  # Remove rows with empty names
        
        # Convert columns to string and handle NaN values
        members_df['Name '] = members_df['Name '].fillna('').astype(str).str.strip()
        members_df['Whatsapp Number '] = members_df['Whatsapp Number '].fillna('').astype(str).str.strip()
        members_df['Main Email'] = members_df['Main Email'].fillna('').astype(str).str.strip()
        
        print("\nDebug - Members data from Excel:")
        print(members_df[['Name ', 'Main Email']].head())
        
        # Read email and password data
        try:
            email_df = pd.read_excel("EmailDB_with_Passwords.xlsx")
            print("\nDebug - Email data loaded successfully")
            print("Columns in email file:", email_df.columns.tolist())
        except Exception as e:
            print(f"\nError loading email file: {str(e)}")
            email_df = pd.DataFrame()
        
        # Strip possible trailing/leading spaces from column names
        email_df.columns = email_df.columns.str.strip()
        
        # Attempt to identify relevant column names dynamically (case-insensitive)
        email_col = 'Main Email'
        password_col = next((c for c in email_df.columns if 'password' in c.lower()), None)
        
        print(f"\nDebug - Using columns: Email={email_col}, Password={password_col}")
        
        for _, row in members_df.iterrows():
            if row['Name '] and row['Name '] != 'nan':  # Only insert if name is not empty
                # Extract member's main email if present
                member_email = row.get('Main Email') if 'Main Email' in members_df.columns else None
                
                if member_email and member_email.lower() != 'nan':
                    member_email = member_email.strip()
                    print(f"\nProcessing member: {row['Name ']}")
                    print(f"Email: {member_email}")
                    
                    password_hash = None
                    if not email_df.empty and email_col and password_col:
                        # Find matching password for this email
                        match = email_df[email_df[email_col].astype(str).str.strip() == member_email]
                        if not match.empty:
                            raw_password = str(match.iloc[0][password_col])
                            print(f"Found password for {member_email}")
                            password_hash = hash_password(raw_password)
                        else:
                            print(f"No password found for {member_email}")
                            # Generate a random password if not found
                            raw_password = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
                            password_hash = hash_password(raw_password)
                            print(f"Generated new password for {member_email}")
                    else:
                        print(f"No email data available for {member_email}")
                        # Generate a random password
                        raw_password = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
                        password_hash = hash_password(raw_password)
                        print(f"Generated new password for {member_email}")
                    
                    try:
                        cursor.execute(
                            """
                            INSERT OR REPLACE INTO Members (name, whatsapp, email, password_hash)
                            VALUES (?, ?, ?, ?)
                            """,
                            (
                                row['Name '],
                                row['Whatsapp Number '] if pd.notna(row['Whatsapp Number ']) else '',
                                member_email,
                                password_hash,
                            ),
                        )
                        print(f"Successfully added/updated member: {row['Name ']}")
                    except Exception as e:
                        print(f"Error adding member {row['Name ']}: {str(e)}")
        
        conn.commit()
        print("\nDebug - Database initialization completed")
    except Exception as e:
        print(f"\nError in init_members_from_excel: {str(e)}")
        st.error(f"Error initializing members: {str(e)}")

# Initialize database
conn = init_database()
init_members_from_excel(conn)
cursor = conn.cursor()

# Load members data from Excel
def load_members_data():
    try:
        members_df = pd.read_excel(members_excel_path)
        print("Raw members data:")
        print(members_df[['Name ', 'Main Email']].head(10))  # Debug print
        
        # Clean the data
        members_df = members_df.dropna(subset=['Name '])  # Remove rows with empty names
        members_df['Name '] = members_df['Name '].astype(str).str.strip()  # Clean names
        members_df['Whatsapp Number '] = members_df['Whatsapp Number '].astype(str).str.strip()  # Clean numbers
        members_df['Main Email'] = members_df['Main Email'].astype(str).str.strip()  # Clean emails
        
        # Debug print for Aasem Ibrahim
        aasem_data = members_df[members_df['Name '].str.contains('Aasem', case=False, na=False)]
        print("\nAasem Ibrahim data:")
        print(aasem_data[['Name ', 'Main Email']])
        
        return members_df
    except Exception as e:
        st.error(f"Error loading members: {str(e)}")
        return pd.DataFrame(columns=['Name ', 'Whatsapp Number ', 'Main Email'])

# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_leader' not in st.session_state:
    st.session_state.current_leader = None
if 'members_df' not in st.session_state:
    st.session_state.members_df = load_members_data()

# Initialize Telegram bot
bot = Bot(token=TELEGRAM_BOT_TOKEN)

# Login page
if not st.session_state.logged_in:
    st.title("Login")
    
    # User type selection
    user_type = st.radio("Select User Type:", ["Leader", "Member"])
    
    if user_type == "Leader":
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
                    st.session_state.user_type = "leader"
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid password!")
    
    else:  # Member login
        email = st.text_input("Email:")
        password = st.text_input("Password:", type="password")
        
        if st.button("Login"):
            try:
                print(f"\nDebug - Login attempt for email: {email}")
                # Check if member exists and password is correct
                cursor.execute("SELECT * FROM Members WHERE email = ?", (email,))
                member = cursor.fetchone()
                
                if member:
                    print(f"Found member: {member[0]}")  # member[0] is the name
                    if member[3] and verify_password(member[3], password):  # password_hash is at index 3
                        st.session_state.logged_in = True
                        st.session_state.current_member = member[0]  # name is at index 0
                        st.session_state.user_type = "member"
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        print(f"Password verification failed for {email}")
                        st.error("Invalid email or password!")
                else:
                    print(f"No member found with email: {email}")
                    st.error("Invalid email or password!")
            except Exception as e:
                print(f"Error during login: {str(e)}")
                st.error(f"Error during login: {str(e)}")

# Main application
async def main():
    if st.session_state.logged_in:
        if st.session_state.user_type == "leader":
            # Leader interface
            st.title("Request Submission System - Snake Chaos House")
            
            # Load leaders data from database
            try:
                leaders_df = pd.read_sql_query("SELECT name FROM Leaders", conn)
                # Exclude SCH Club from send-to list
                leaders_df = leaders_df[leaders_df['name'] != 'SCH Club']
            except Exception as e:
                st.error(f"Error loading leaders: {str(e)}")
                leaders_df = pd.DataFrame(columns=['name'])
            
            # Logout button
            if st.sidebar.button("Logout"):
                st.session_state.logged_in = False
                st.session_state.current_leader = None
                st.session_state.user_type = None
                st.rerun()
            
            # Create tabs for different sections
            submit_tab, requests_tab, stats_tab, admin_tab = st.tabs([
                "Submit Request", 
                "My Requests", 
                "Statistics", 
                "Admin Panel"
            ])
            
            with submit_tab:
                st.header("Submit New Request")
                # Select member
                st.subheader("Select Member")
                selected_member = st.selectbox("Select Member:", st.session_state.members_df['Name '])

                # Get member's WhatsApp number
                member_whatsapp = st.session_state.members_df[st.session_state.members_df['Name '] == selected_member]['Whatsapp Number '].values[0]

                # Write request description
                st.subheader("Write Request Description")
                description = st.text_area("Description:")

                # Select receiving leader
                st.subheader("Select who will receive the request")
                assigned_to = st.selectbox("Send to:", leaders_df['name'])
                
                # Set priority
                st.subheader("Set Priority")
                priority = st.select_slider(
                    "Priority Level",
                    options=['Low', 'Medium', 'High'],
                    value='Medium'
                )
                
                # Submit button
                if st.button("Submit Request") and selected_member:
                    try:
                        # Get member's email
                        cursor.execute("SELECT email FROM Members WHERE name = ?", (selected_member,))
                        member_data = cursor.fetchone()
                        
                        if not member_data or not member_data[0]:
                            # Try to get email from Excel file
                            member_row = st.session_state.members_df[st.session_state.members_df['Name '] == selected_member]
                            if not member_row.empty and pd.notna(member_row['Main Email'].iloc[0]):
                                email = member_row['Main Email'].iloc[0].strip()
                                if email.lower() != 'nan':
                                    cursor.execute("UPDATE Members SET email = ? WHERE name = ?", (email, selected_member))
                                    conn.commit()
                                else:
                                    st.error(f"Invalid email found for {selected_member}!")
                                    return
                            else:
                                st.error(f"Member email not found for {selected_member}!")
                                return

                        # Insert into RequestHistory table with all details
                        cursor.execute("""
                            INSERT INTO RequestHistory (
                                member_name, member_whatsapp, submitted_by,
                                description, assigned_to, created_at, status, priority
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            selected_member, 
                            member_whatsapp, 
                            st.session_state.current_leader,
                            description, 
                            assigned_to, 
                            datetime.now(),
                            'Pending',
                            priority
                        ))
                        conn.commit()

                        # Save to Excel
                        history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
                        save_to_excel(history_df)
                        st.success("Request saved to database successfully!")

                        # Prepare message
                        message = f"""
📋 *New Request Submitted*

👤 *Member:* {selected_member}
📱 *WhatsApp:* {member_whatsapp}

📝 *Description:*
{description}

👨‍💼 *Submitted by:* {st.session_state.current_leader}
🎯 *Assigned to:* {assigned_to}
⚡ *Priority:* {priority}

⏰ *Date & Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        """
                        
                        try:
                            # Send to Telegram
                            cursor.execute("SELECT telegram_id FROM Leaders WHERE name = ?", (assigned_to,))
                            result = cursor.fetchone()
                            telegram_id = result[0] if result else None

                            if telegram_id:
                                telegram_success = await send_message("Telegram", telegram_id, message)
                                if telegram_success:
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
                    except Exception as e:
                        st.error(f"Error saving request to database: {str(e)}")
            
            with requests_tab:
                st.header("My Assigned Requests")
                
                # Get all requests assigned to current leader
                my_requests_df = pd.read_sql_query("""
                    SELECT * FROM RequestHistory 
                    WHERE assigned_to = ? 
                    ORDER BY 
                        CASE 
                            WHEN status = 'Pending' THEN 1
                            WHEN status = 'In Progress' THEN 2
                            ELSE 3
                        END,
                        CASE 
                            WHEN priority = 'High' THEN 1
                            WHEN priority = 'Medium' THEN 2
                            ELSE 3
                        END,
                        created_at DESC
                """, conn, params=[st.session_state.current_leader])
                
                if not my_requests_df.empty:
                    # Add filtering options
                    st.subheader("Filter Requests")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        status_filter = st.multiselect(
                            "Filter by Status",
                            options=my_requests_df['status'].unique(),
                            default=my_requests_df['status'].unique()
                        )
                    
                    with col2:
                        search_term = st.text_input("Search in requests", "")
                    
                    with col3:
                        priority_filter = st.multiselect(
                            "Filter by Priority",
                            options=['High', 'Medium', 'Low'],
                            default=['High', 'Medium', 'Low']
                        )
                    
                    # Apply filters
                    filtered_requests = my_requests_df
                    if status_filter:
                        filtered_requests = filtered_requests[filtered_requests['status'].isin(status_filter)]
                    if search_term:
                        filtered_requests = filtered_requests[
                            filtered_requests['description'].str.contains(search_term, case=False, na=False) |
                            filtered_requests['member_name'].str.contains(search_term, case=False, na=False)
                        ]
                    if priority_filter:
                        filtered_requests = filtered_requests[filtered_requests['priority'].isin(priority_filter)]
                    
                    # Display filtered requests
                    st.dataframe(filtered_requests, use_container_width=True)
                    
                    # Update request section
                    st.subheader("Update Request")
                    selected_request = st.selectbox(
                        "Select Request to Update:",
                        filtered_requests['member_name'] + " - " + filtered_requests['created_at'].astype(str)
                    )
                    
                    try:
                        selected_index = filtered_requests[filtered_requests['member_name'] + " - " + filtered_requests['created_at'].astype(str) == selected_request].index[0]
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            # Status options
                            status_options = ['Pending', 'In Progress', 'Completed', 'Rejected']
                            new_status = st.selectbox("New Status:", status_options)
                        
                        with col2:
                            # Priority options
                            priority_options = ['High', 'Medium', 'Low']
                            new_priority = st.selectbox("Priority:", priority_options, 
                                                     index=priority_options.index(filtered_requests.iloc[selected_index]['priority']))
                        
                        # Add comment
                        comment = st.text_area("Add a Comment:")
                        
                        if st.button("Update Request"):
                            # Update the request in the database
                            cursor.execute("""
                                UPDATE RequestHistory 
                                SET status = ?, priority = ?, comment = ? 
                                WHERE member_name = ? AND created_at = ?
                            """, (new_status, new_priority, comment,
                                  filtered_requests.iloc[selected_index]['member_name'],
                                  filtered_requests.iloc[selected_index]['created_at']))
                            conn.commit()
                            
                            # Save to Excel after update
                            history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
                            save_to_excel(history_df)
                            st.success("Request updated successfully!")
                            
                            # Send notification to member
                            try:
                                # Get member's WhatsApp
                                member_whatsapp = filtered_requests.iloc[selected_index]['member_whatsapp']
                                
                                # Prepare notification message
                                notification = f"""
📢 *Request Update*

👤 *Member:* {filtered_requests.iloc[selected_index]['member_name']}
📝 *Request:* {filtered_requests.iloc[selected_index]['description'][:100]}...

🔄 *New Status:* {new_status}
⚡ *Priority:* {new_priority}
💬 *Comment:* {comment if comment else 'No comment'}

👨‍💼 *Updated by:* {st.session_state.current_leader}
⏰ *Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                                """
                                
                                # Send WhatsApp notification
                                whatsapp_success = await send_message("WhatsApp", member_whatsapp, notification)
                                if whatsapp_success:
                                    st.success("Notification sent to member successfully!")
                            except Exception as e:
                                st.error(f"Failed to send notification: {str(e)}")
                    except IndexError:
                        st.error("No matching request found. Please select a valid request.")
                    except Exception as e:
                        st.error(f"An error occurred: {str(e)}")
                else:
                    st.info("You don't have any assigned requests.")
            
            with stats_tab:
                st.header("Request Statistics")
                
                # Get request statistics
                stats_df = pd.read_sql_query("""
                    SELECT 
                        status,
                        priority,
                        COUNT(*) as count,
                        assigned_to
                    FROM RequestHistory
                    WHERE assigned_to = ?
                    GROUP BY status, priority, assigned_to
                """, conn, params=[st.session_state.current_leader])
                
                if not stats_df.empty:
                    # Display statistics
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("Status Distribution")
                        status_counts = stats_df.groupby('status')['count'].sum().reset_index()
                        fig = px.pie(status_counts, values='count', names='status', title='Request Status Distribution')
                        st.plotly_chart(fig)
                    
                    with col2:
                        st.subheader("Priority Distribution")
                        priority_counts = stats_df.groupby('priority')['count'].sum().reset_index()
                        fig = px.pie(priority_counts, values='count', names='priority', title='Request Priority Distribution')
                        st.plotly_chart(fig)
                    
                    # Performance metrics
                    st.subheader("Performance Metrics")
                    cursor.execute("""
                        SELECT 
                            AVG(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completion_rate,
                            AVG(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) as pending_rate,
                            COUNT(*) as total_requests
                        FROM RequestHistory 
                        WHERE assigned_to = ?
                    """, (st.session_state.current_leader,))
                    
                    metrics = cursor.fetchone()
                    if metrics:
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Completion Rate", f"{metrics[0]*100:.1f}%")
                        with col2:
                            st.metric("Pending Rate", f"{metrics[1]*100:.1f}%")
                        with col3:
                            st.metric("Total Requests", metrics[2])
                else:
                    st.info("No statistics available yet.")
            
            with admin_tab:
                if st.session_state.current_leader:
                    cursor.execute("SELECT is_admin FROM Leaders WHERE name = ?", (st.session_state.current_leader,))
                    result = cursor.fetchone()
                    is_admin = result[0] if result else False
                    
                    if is_admin:
                        st.header("Admin Panel")
                        
                        # Add new leader section
                        st.subheader("Add New Leader")
                        new_leader_name = st.text_input("Leader Name")
                        new_leader_telegram_id = st.text_input("Telegram ID")
                        
                        if st.button("Add Leader"):
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
                                        st.success(f"Leader {new_leader_name} added successfully!")
                                        st.info("Initial password is their name in lowercase")
                                        st.rerun()
                                    else:
                                        st.error("Leader already exists!")
                                except Exception as e:
                                    st.error(f"Error adding leader: {str(e)}")
                            else:
                                st.error("Please fill in all fields!")
                        
                        # Remove leader section
                        st.subheader("Remove Leader")
                        remove_leader_name = st.selectbox(
                            "Select Leader to Remove:",
                            leaders_df[leaders_df['name'] != st.session_state.current_leader]['name']
                        )
                        
                        if st.button("Remove Leader"):
                            if remove_leader_name:
                                try:
                                    # Check if leader exists
                                    cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (remove_leader_name,))
                                    count = cursor.fetchone()[0]
                                    
                                    if count > 0:
                                        # Delete leader
                                        cursor.execute("DELETE FROM Leaders WHERE name = ?", (remove_leader_name,))
                                        conn.commit()
                                        st.success(f"Leader {remove_leader_name} removed successfully!")
                                        st.rerun()
                                    else:
                                        st.error("Leader not found!")
                                except Exception as e:
                                    st.error(f"Error removing leader: {str(e)}")
                            else:
                                st.error("Please select a leader to remove!")
                        
                        # Make leader admin section
                        st.subheader("Make Leader Admin")
                        admin_leader_name = st.selectbox(
                            "Select Leader to Make Admin:",
                            leaders_df[leaders_df['name'] != st.session_state.current_leader]['name']
                        )
                        
                        if st.button("Make Admin"):
                            if admin_leader_name:
                                try:
                                    # Check if leader exists
                                    cursor.execute("SELECT COUNT(*) FROM Leaders WHERE name = ?", (admin_leader_name,))
                                    count = cursor.fetchone()[0]
                                    
                                    if count > 0:
                                        # Update leader to admin
                                        cursor.execute("UPDATE Leaders SET is_admin = TRUE WHERE name = ?", (admin_leader_name,))
                                        conn.commit()
                                        st.success(f"Leader {admin_leader_name} is now an admin!")
                                        st.rerun()
                                    else:
                                        st.error("Leader not found!")
                                except Exception as e:
                                    st.error(f"Error making leader admin: {str(e)}")
                            else:
                                st.error("Please select a leader to make admin!")
                        
                        # Delete request section
                        st.subheader("Delete Request")
                        all_requests = pd.read_sql_query("""
                            SELECT member_name, created_at, description 
                            FROM RequestHistory 
                            ORDER BY created_at DESC
                        """, conn)
                        
                        if not all_requests.empty:
                            request_options = all_requests.apply(
                                lambda row: f"{row['member_name']} - {row['created_at']} - {row['description'][:30]}...", 
                                axis=1
                            )
                            request_to_delete = st.selectbox(
                                "Select Request to Delete:",
                                request_options
                            )
                            
                            if st.button("Delete Request"):
                                try:
                                    # Get the selected request details
                                    selected_request = all_requests.iloc[request_options[request_options == request_to_delete].index[0]]
                                    
                                    # Delete the request
                                    cursor.execute("""
                                        DELETE FROM RequestHistory 
                                        WHERE member_name = ? AND created_at = ?
                                    """, (selected_request['member_name'], selected_request['created_at']))
                                    conn.commit()
                                    
                                    # Save to Excel after deletion
                                    history_df = pd.read_sql_query("SELECT * FROM RequestHistory ORDER BY created_at DESC", conn)
                                    save_to_excel(history_df)
                                    
                                    st.success("Request deleted successfully!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error deleting request: {str(e)}")
                        else:
                            st.info("No requests available to delete.")
                        
                        # Edit Leader Data section
                        st.subheader("Edit Leader Data")
                        leader_to_edit = st.selectbox(
                            "Select Leader to Edit:",
                            leaders_df['name']
                        )
                        
                        if leader_to_edit:
                            # Get current leader data
                            cursor.execute("SELECT * FROM Leaders WHERE name = ?", (leader_to_edit,))
                            leader_data = cursor.fetchone()
                            
                            if leader_data:
                                new_telegram_id = st.text_input("New Telegram ID", value=str(leader_data[2] or ""))
                                
                                if st.button("Update Leader Data"):
                                    try:
                                        cursor.execute("""
                                            UPDATE Leaders 
                                            SET telegram_id = ? 
                                            WHERE name = ?
                                        """, (new_telegram_id if new_telegram_id else None, leader_to_edit))
                                        conn.commit()
                                        st.success("Leader data updated successfully!")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"Error updating leader data: {str(e)}")
                    else:
                        st.info("You don't have admin privileges.")
        else:
            # Member interface
            st.title("Member Portal - Snake Chaos House")
            
            # Logout button
            if st.sidebar.button("Logout"):
                st.session_state.logged_in = False
                st.session_state.current_member = None
                st.session_state.user_type = None
                st.rerun()
            
            # Add password change section for members
            st.sidebar.subheader("Change Password")
            old_password = st.sidebar.text_input("Old Password", type="password")
            new_password = st.sidebar.text_input("New Password", type="password")
            confirm_password = st.sidebar.text_input("Confirm New Password", type="password")
            
            if st.sidebar.button("Update Password"):
                try:
                    # Get current member's email
                    cursor.execute("SELECT email, password_hash FROM Members WHERE name = ?", (st.session_state.current_member,))
                    member_data = cursor.fetchone()
                    
                    if member_data and verify_password(member_data[1], old_password):
                        if new_password == confirm_password and new_password.strip() != "":
                            new_hash = hash_password(new_password)
                            cursor.execute("UPDATE Members SET password_hash = ? WHERE name = ?", (new_hash, st.session_state.current_member))
                            conn.commit()
                            st.sidebar.success("Password updated successfully!")
                        else:
                            st.sidebar.error("New passwords do not match or are empty.")
                    else:
                        st.sidebar.error("Old password is incorrect.")
                except Exception as e:
                    st.sidebar.error(f"Error updating password: {str(e)}")
            
            # Create tabs for different sections
            profile_tab, requests_tab, notifications_tab, reports_tab = st.tabs(["Profile", "My Requests", "Notifications", "Reports"])
            
            with profile_tab:
                st.subheader("My Profile")
                
                # Get member details
                cursor.execute("""
                    SELECT name, whatsapp, email 
                    FROM Members 
                    WHERE name = ?
                """, (st.session_state.current_member,))
                member_details = cursor.fetchone()
                
                if member_details:
                    # Display member information
                    st.write(f"**Name:** {member_details[0]}")
                    st.write(f"**WhatsApp:** {member_details[1]}")
                    st.write(f"**Email:** {member_details[2]}")
                    
                    # Update contact information
                    st.subheader("Update Contact Information")
                    new_whatsapp = st.text_input("New WhatsApp Number", value=member_details[1])
                    
                    if st.button("Update Contact Info"):
                        try:
                            cursor.execute("""
                                UPDATE Members 
                                SET whatsapp = ? 
                                WHERE name = ?
                            """, (new_whatsapp, st.session_state.current_member))
                            conn.commit()
                            st.success("Contact information updated successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error updating contact information: {str(e)}")
                    
                    # Display request statistics
                    st.subheader("Request Statistics")
                    cursor.execute("""
                        SELECT 
                            status,
                            COUNT(*) as count
                        FROM RequestHistory 
                        WHERE member_name = ?
                        GROUP BY status
                    """, (st.session_state.current_member,))
                    stats = cursor.fetchall()
                    
                    if stats:
                        stats_df = pd.DataFrame(stats, columns=['Status', 'Count'])
                        st.dataframe(stats_df)
                        
                        # Create a pie chart
                        fig = px.pie(stats_df, values='Count', names='Status', title='Request Status Distribution')
                        st.plotly_chart(fig)
                        
                        # Calculate average response time using created_at only
                        cursor.execute("""
                            SELECT 
                                AVG(julianday(CURRENT_TIMESTAMP) - julianday(created_at)) as avg_response_time
                            FROM RequestHistory 
                            WHERE member_name = ? AND status != 'Pending'
                        """, (st.session_state.current_member,))
                        avg_time = cursor.fetchone()[0]
                        if avg_time:
                            st.write(f"**Average Response Time:** {avg_time:.1f} days")
            
            with requests_tab:
                st.subheader("My Requests")
                try:
                    # Get all requests for the member
                    member_requests = pd.read_sql_query("""
                        SELECT 
                            member_name,
                            description,
                            assigned_to,
                            created_at,
                            status,
                            comment,
                            rating,
                            submitted_by,
                            COALESCE(priority, 'Medium') as priority
                        FROM RequestHistory 
                        WHERE member_name = ?
                        ORDER BY 
                            CASE 
                                WHEN status = 'Pending' THEN 1
                                WHEN status = 'In Progress' THEN 2
                                ELSE 3
                            END,
                            created_at DESC
                    """, conn, params=[st.session_state.current_member])
                    
                    if not member_requests.empty:
                        # Add filtering options
                        st.subheader("Filter Requests")
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            status_filter = st.multiselect(
                                "Filter by Status",
                                options=member_requests['status'].unique(),
                                default=member_requests['status'].unique()
                            )
                        
                        with col2:
                            search_term = st.text_input("Search in requests", "")
                        
                        with col3:
                            priority_filter = st.multiselect(
                                "Filter by Priority",
                                options=['High', 'Medium', 'Low'],
                                default=['High', 'Medium', 'Low']
                            )
                        
                        # Apply filters
                        filtered_requests = member_requests
                        if status_filter:
                            filtered_requests = filtered_requests[filtered_requests['status'].isin(status_filter)]
                        if search_term:
                            filtered_requests = filtered_requests[
                                filtered_requests['description'].str.contains(search_term, case=False, na=False) |
                                filtered_requests['assigned_to'].str.contains(search_term, case=False, na=False)
                            ]
                        if priority_filter:
                            filtered_requests = filtered_requests[filtered_requests['priority'].isin(priority_filter)]
                        
                        # Display filtered requests with priority colors
                        def color_priority(val):
                            color = 'red' if val == 'High' else 'orange' if val == 'Medium' else 'green'
                            return f'color: {color}'
                        
                        styled_requests = filtered_requests.style.applymap(color_priority, subset=['priority'])
                        st.dataframe(styled_requests, use_container_width=True)
                        
                        # Add comment and rating functionality
                        st.subheader("Comment and Rate")
                        selected_request = st.selectbox(
                            "Select Request to Comment/Rate:",
                            filtered_requests['member_name'] + " - " + filtered_requests['created_at'].astype(str)
                        )
                        
                        try:
                            selected_index = filtered_requests[filtered_requests['member_name'] + " - " + filtered_requests['created_at'].astype(str) == selected_request].index[0]
                            
                            # Advanced rating system
                            st.write("### Rate the Service")
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                response_time = st.slider("Response Time", 1, 5, 3)
                            with col2:
                                service_quality = st.slider("Service Quality", 1, 5, 3)
                            with col3:
                                communication = st.slider("Communication", 1, 5, 3)
                            
                            comment = st.text_area("Add a Comment:")
                            
                            if st.button("Submit Rating"):
                                try:
                                    member_name = filtered_requests.iloc[selected_index]['member_name']
                                    created_at_str = filtered_requests.iloc[selected_index]['created_at']
                                    
                                    # Calculate average rating
                                    avg_rating = (response_time + service_quality + communication) / 3
                                    
                                    # Update the request with detailed ratings
                                    cursor.execute("""
                                        UPDATE RequestHistory 
                                        SET 
                                            comment = ?,
                                            rating = ?,
                                            response_time_rating = ?,
                                            service_quality_rating = ?,
                                            communication_rating = ?
                                        WHERE member_name = ? AND datetime(created_at) = datetime(?)
                                    """, (
                                        comment if comment else None,
                                        avg_rating,
                                        response_time,
                                        service_quality,
                                        communication,
                                        member_name,
                                        created_at_str
                                    ))
                                    
                                    if cursor.rowcount > 0:
                                        conn.commit()
                                        st.success("Rating submitted successfully!")
                                        st.rerun()
                                    else:
                                        st.error("Request not found in database!")
                                except Exception as e:
                                    st.error(f"Error updating rating: {str(e)}")
                        except IndexError:
                            st.error("No matching request found. Please select a valid request.")
                        except Exception as e:
                            st.error(f"An error occurred: {str(e)}")
                    else:
                        st.info("You haven't submitted any requests yet.")
                except Exception as e:
                    st.error(f"Error loading requests: {str(e)}")
            
            with notifications_tab:
                st.subheader("Notifications")
                
                # Get recent updates
                cursor.execute("""
                    SELECT 
                        created_at,
                        status,
                        comment,
                        assigned_to,
                        priority
                    FROM RequestHistory 
                    WHERE member_name = ?
                    ORDER BY created_at DESC
                    LIMIT 5
                """, (st.session_state.current_member,))
                
                recent_updates = cursor.fetchall()
                
                if recent_updates:
                    for update in recent_updates:
                        with st.container():
                            # Color code based on priority
                            priority_color = 'red' if update[4] == 'High' else 'orange' if update[4] == 'Medium' else 'green'
                            st.markdown(f"<h4 style='color: {priority_color};'>{update[4]} Priority</h4>", unsafe_allow_html=True)
                            st.write(f"**Date:** {update[0]}")
                            st.write(f"**Status:** {update[1]}")
                            if update[2]:  # If there's a comment
                                st.write(f"**Comment:** {update[2]}")
                            st.write(f"**Assigned to:** {update[3]}")
                            st.divider()
                else:
                    st.info("No recent updates.")
            
            with reports_tab:
                st.subheader("Performance Reports")
                
                # Get leader performance data
                cursor.execute("""
                    SELECT 
                        assigned_to,
                        AVG(COALESCE(rating, 0)) as avg_rating,
                        AVG(COALESCE(response_time_rating, 0)) as avg_response_time,
                        AVG(COALESCE(service_quality_rating, 0)) as avg_service_quality,
                        AVG(COALESCE(communication_rating, 0)) as avg_communication,
                        COUNT(*) as total_requests
                    FROM RequestHistory 
                    WHERE member_name = ? AND rating IS NOT NULL
                    GROUP BY assigned_to
                """, (st.session_state.current_member,))
                
                leader_stats = cursor.fetchall()
                
                if leader_stats:
                    # Create performance dataframe
                    perf_df = pd.DataFrame(leader_stats, columns=[
                        'Leader', 'Overall Rating', 'Response Time', 
                        'Service Quality', 'Communication', 'Total Requests'
                    ])
                    
                    # Display leader performance
                    st.write("### Leader Performance")
                    st.dataframe(perf_df)
                    
                    # Create performance chart
                    fig = px.bar(perf_df, 
                                x='Leader', 
                                y=['Response Time', 'Service Quality', 'Communication'],
                                title='Leader Performance Metrics',
                                barmode='group')
                    st.plotly_chart(fig)
                    
                    # Request timeline
                    st.write("### Request Timeline")
                    cursor.execute("""
                        SELECT 
                            created_at,
                            status,
                            assigned_to
                        FROM RequestHistory 
                        WHERE member_name = ?
                        ORDER BY created_at
                    """, (st.session_state.current_member,))
                    
                    timeline_data = cursor.fetchall()
                    if timeline_data:
                        timeline_df = pd.DataFrame(timeline_data, columns=['Date', 'Status', 'Leader'])
                        fig = px.scatter(timeline_df, 
                                       x='Date', 
                                       y='Status',
                                       color='Leader',
                                       title='Request Timeline')
                        st.plotly_chart(fig)
                else:
                    st.info("No performance data available yet.")

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
            # Create a new bot instance for each message
            bot = Bot(token=TELEGRAM_BOT_TOKEN)
            # Use the synchronous send_message method
            bot.send_message(chat_id=recipient_id, text=message, parse_mode='Markdown')
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