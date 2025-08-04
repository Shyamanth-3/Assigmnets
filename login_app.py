import streamlit as st
import hashlib
import re
import sqlite3
import os
from datetime import datetime, timedelta

# Page configuration for the login app
st.set_page_config(
    page_title="Event Safety Login",
    page_icon="🛡",
    layout="centered", # Centered layout for login page
    initial_sidebar_state="collapsed" # No sidebar on login page
)

# --- Database Setup and Authentication Functions ---
def init_database():
    """Initialize SQLite database for user management"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')

    # Create default admin user if doesn't exist
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone()[0] == 0:
        salt = os.urandom(32).hex()
        password_hash = hash_password_with_salt('Admin123!', salt)
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, role)
            VALUES (?, ?, ?, ?)
        ''', ('admin', password_hash, salt, 'admin'))

    conn.commit()
    conn.close()

def hash_password_with_salt(password, salt):
    """Hash password with salt using SHA-256"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def validate_password_strength(password):
    """Validate password strength and return feedback"""
    issues = []

    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")

    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        issues.append("Password must contain at least one number")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password must contain at least one special character (!@#$%^&*, .?\":{}|<>)")

    # Check for common weak patterns
    common_patterns = ['123456', 'password', 'qwerty', 'admin', 'user']
    if any(pattern in password.lower() for pattern in common_patterns):
        issues.append("Password should not contain common patterns")

    return issues

def get_password_strength_score(password):
    """Calculate password strength score (0-100)"""
    score = 0

    # Length bonus
    score += min(25, len(password) * 2)

    # Character variety bonus
    if re.search(r'[a-z]', password): score += 15
    if re.search(r'[A-Z]', password): score += 15
    if re.search(r'\d', password): score += 15
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 15

    # Additional complexity bonus
    if len(password) >= 12: score += 10
    if len(set(password)) / len(password) > 0.7: score += 5  # Character diversity

    return min(100, score)

def authenticate_user(username, password):
    """Authenticate user with enhanced security"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Check if account is locked
    cursor.execute('''
        SELECT password_hash, salt, failed_attempts, locked_until
        FROM users WHERE username = ?
    ''', (username,))

    result = cursor.fetchone()
    if not result:
        conn.close()
        return False, "Invalid username or password"

    password_hash, salt, failed_attempts, locked_until = result

    # Check if account is locked
    if locked_until:
        locked_until_dt = datetime.fromisoformat(locked_until)
        if datetime.now() < locked_until_dt:
            conn.close()
            return False, f"Account locked until {locked_until_dt.strftime('%Y-%m-%d %H:%M:%S')}"

    # Verify password
    if hash_password_with_salt(password, salt) == password_hash:
        # Reset failed attempts on successful login
        cursor.execute('''
            UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE username = ?
        ''', (datetime.now().isoformat(), username))
        conn.commit()
        conn.close()
        return True, "Login successful"
    else:
        # Increment failed attempts
        new_failed_attempts = failed_attempts + 1
        locked_until = None

        # Lock account after 5 failed attempts for 15 minutes
        if new_failed_attempts >= 5:
            locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()

        cursor.execute('''
            UPDATE users SET failed_attempts = ?, locked_until = ?
            WHERE username = ?
        ''', (new_failed_attempts, locked_until, username))
        conn.commit()
        conn.close()

        if new_failed_attempts >= 5:
            return False, "Account locked due to too many failed attempts. Try again in 15 minutes."
        else:
            return False, f"Invalid username or password. {5 - new_failed_attempts} attempts remaining."

def register_user(username, password, role='operator'):
    """Register new user with password validation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        salt = os.urandom(32).hex()
        password_hash = hash_password_with_salt(password, salt)

        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, role)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, salt, role))

        conn.commit()
        conn.close()
        return True, "User registered successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"

# --- Session State Initialization (for authentication) ---
# These are specific to the login process and will be cleared/set upon successful login
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'show_register' not in st.session_state:
    st.session_state.show_register = False

# --- Initialize database ---
init_database()

# --- UI Helper Functions ---
def show_password_requirements():
    """Display password requirements in sidebar"""
    with st.sidebar.expander("📋 Password Requirements"):
        st.write("*Strong passwords must have:*")
        st.write("• At least 8 characters")
        st.write("• At least one uppercase letter (A-Z)")
        st.write("• At least one lowercase letter (a-z)")
        st.write("• At least one number (0-9)")
        st.write("• At least one special character (!@#$%^&*)")
        st.write("• No common patterns (123456, password, etc.)")

def password_strength_indicator(password):
    """Display password strength indicator"""
    if not password:
        return

    score = get_password_strength_score(password)

    if score < 30:
        strength = "Very Weak"
        # color = "red" # Streamlit progress bar handles color based on value
    elif score < 50:
        strength = "Weak"
        # color = "orange"
    elif score < 70:
        strength = "Fair"
        # color = "yellow"
    elif score < 90:
        strength = "Strong"
        # color = "lightgreen"
    else:
        strength = "Very Strong"
        # color = "green"

    st.write(f"Password Strength: *{strength}* ({score}/100)")
    st.progress(score / 100)

# --- Main Login/Register Page ---
def show_login_register_page():
    st.title("🛡 Event Safety System")

    # Toggle between login and register
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

    with tab1:
        st.subheader("Secure Login")

        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                remember_me = st.checkbox("Remember me") # This would require more advanced session management
                login_button = st.form_submit_button("🚀 Login", use_container_width=True)

                if login_button:
                    if username and password:
                        success, message = authenticate_user(username, password)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.username = username
                            # Redirect to the main dashboard page, now in pages/
                            st.switch_page("pages/main_dashboard.py")
                        else:
                            st.error(f"❌ {message}")
                    else:
                        st.warning("⚠ Please enter both username and password")

    with tab2:
        st.subheader("Create New Account")

        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            with st.form("register_form"):
                new_username = st.text_input("Choose Username", placeholder="Enter desired username")
                new_password = st.text_input("Create Password", type="password", placeholder="Create a strong password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")

                # Show password strength in real-time
                if new_password:
                    password_strength_indicator(new_password)

                    # Show password validation issues
                    issues = validate_password_strength(new_password)
                    if issues:
                        st.error("*Password Requirements Not Met:*")
                        for issue in issues:
                            st.write(f"• {issue}")

                role = st.selectbox("Role", ["operator", "security", "admin"], index=0)
                register_button = st.form_submit_button("📝 Create Account", use_container_width=True)

                if register_button:
                    if not all([new_username, new_password, confirm_password]):
                        st.warning("⚠ Please fill in all fields")
                    elif new_password != confirm_password:
                        st.error("❌ Passwords do not match")
                    elif validate_password_strength(new_password): # Check if there are any issues
                        st.error("❌ Password does not meet requirements. Please check above.")
                    else:
                        success, message = register_user(new_username, new_password, role)
                        if success:
                            st.success(f"✅ {message}")
                            st.info("You can now login with your new account!")
                        else:
                            st.error(f"❌ {message}")

    # Show password requirements
    show_password_requirements()

    # Demo account info
    with st.expander("🔑 Demo Account"):
        st.write("*Default admin account:*")
        st.code("Username: admin")
        st.code("Password: Admin123!")
        st.warning("⚠ Please create your own account for security")

# --- Main execution for login_app.py ---
if __name__ == "__main__":
    # If not authenticated, show the login/register page
    if not st.session_state.authenticated:
        show_login_register_page()
    else:
        # If already authenticated (e.g., after a rerun), redirect to dashboard
        st.switch_page("pages/main_dashboard.py")
