import sqlite3
from flask import Flask, render_template, redirect, url_for, request, g, flash, jsonify, session
from flask_socketio import SocketIO, send, emit, join_room, disconnect
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import validate_csrf
from wtforms import StringField, PasswordField, validators
from wtforms.validators import DataRequired, Length, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import os
import logging
from functools import wraps
import bleach
import secrets
from threading import Lock

app = Flask(__name__)

# Security configurations
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 2 hour session timeout
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = os.environ.get('DATABASE_PATH', 'chat.db')

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('chat_app.log'),
        logging.StreamHandler()
    ]
)

# Initialize security extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Thread-safe lock for database operations
db_lock = Lock()

# Connected users tracking
connected_users = set()

# Initialize Flask extensions
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.session_protection = "strong"
login_manager.init_app(app)

def get_db():
    if "db" not in g:
        try:
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            raise
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    try:
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL CHECK(length(username) <= 50),
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL CHECK(length(message) <= 500),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(from_user, to_user)
        );
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            friend TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user, friend)
        );
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            message TEXT NOT NULL CHECK(length(message) <= 500),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        db.commit()
        logging.info("Database initialized successfully")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_db()
        user = db.execute("SELECT username FROM users WHERE username = ?", (user_id,)).fetchone()
        return User(user_id) if user else None
    except sqlite3.Error as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None

# Security utility functions
def sanitize_message(message):
    """Sanitize user input to prevent XSS attacks"""
    allowed_tags = []  # No HTML tags allowed in messages
    return bleach.clean(message, tags=allowed_tags, strip=True)

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, "Password is strong."

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if len(username) > 50:
        return False, "Username must be 50 characters or less."
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, hyphens, and underscores."
    return True, "Username is valid."

# Form classes for CSRF protection
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=50),
        Regexp(r'^[a-zA-Z0-9_-]+$', message="Username can only contain letters, numbers, hyphens, and underscores.")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

# SocketIO authentication decorator
def socketio_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return False
        return f(*args, **kwargs)
    return decorated_function

# Enhanced database operations with proper error handling
def safe_db_execute(query, params=(), fetch_one=False, fetch_all=False):
    """Execute database queries safely with proper error handling"""
    try:
        with db_lock:
            db = get_db()
            cursor = db.execute(query, params)
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                result = cursor
            db.commit()
            return result
    except sqlite3.Error as e:
        logging.error(f"Database error: {e} - Query: {query} - Params: {params}")
        db.rollback()
        raise

@app.route("/")
def index():
    return redirect(url_for("chat"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        
        # Validate username format
        is_valid, msg = validate_username(username)
        if not is_valid:
            flash(msg, 'error')
            return render_template("login.html", form=form)
        
        try:
            user = safe_db_execute(
                "SELECT * FROM users WHERE username = ?", 
                (username,), 
                fetch_one=True
            )
            if user and check_password_hash(user["password"], password):
                user_obj = User(username)
                login_user(user_obj, remember=False)
                session.permanent = True
                logging.info(f"User {username} logged in successfully")
                return redirect(url_for("chat"))
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                flash("Invalid credentials.", 'error')
        except Exception as e:
            logging.error(f"Login error: {e}")
            flash("Login failed. Please try again.", 'error')
    
    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        
        # Validate username
        is_valid, msg = validate_username(username)
        if not is_valid:
            flash(msg, 'error')
            return render_template("register.html", form=form)
        
        # Validate password strength
        is_strong, pwd_msg = validate_password_strength(password)
        if not is_strong:
            flash(pwd_msg, 'error')
            return render_template("register.html", form=form)
        
        try:
            # Check if username already exists
            existing_user = safe_db_execute(
                "SELECT id FROM users WHERE username = ?", 
                (username,), 
                fetch_one=True
            )
            if existing_user:
                flash("Username already exists.", 'error')
                return render_template("register.html", form=form)
            
            # Create new user
            hashed = generate_password_hash(password, method='pbkdf2:sha256')
            safe_db_execute(
                "INSERT INTO users (username, password) VALUES (?, ?)", 
                (username, hashed)
            )
            
            logging.info(f"New user registered: {username}")
            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for("login"))
            
        except Exception as e:
            logging.error(f"Registration error: {e}")
            flash("Registration failed. Please try again.", 'error')
    
    return render_template("register.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/chat")
@login_required
def chat():
    try:
        db = get_db()
        # Limit messages to last 100 for performance
        messages = db.execute(
            "SELECT username, message, timestamp FROM messages ORDER BY id DESC LIMIT 100"
        ).fetchall()
        messages = list(reversed(messages))  # Show oldest first
        
        # Get friends from both directions (user->friend and friend->user)
        friends = db.execute("""
            SELECT DISTINCT 
                CASE 
                    WHEN user = ? THEN friend 
                    ELSE user 
                END as friend_name
            FROM friendships 
            WHERE user = ? OR friend = ?
        """, (current_user.id, current_user.id, current_user.id)).fetchall()
        return render_template("chat.html", username=current_user.id, messages=messages, friends=[f["friend_name"] for f in friends])
    except sqlite3.Error as e:
        logging.error(f"Chat page database error: {e}")
        flash("Error loading chat. Please try again.")
        return redirect(url_for("login"))

@app.route("/friends")
@login_required
def friends():
    try:
        db = get_db()
        # Get friends from both directions
        friends = db.execute("""
            SELECT DISTINCT 
                CASE 
                    WHEN user = ? THEN friend 
                    ELSE user 
                END as friend_name
            FROM friendships 
            WHERE user = ? OR friend = ?
        """, (current_user.id, current_user.id, current_user.id)).fetchall()
        pending = db.execute("SELECT * FROM friend_requests WHERE to_user=? AND status='pending'", (current_user.id,)).fetchall()
        return render_template("friends.html", friends=friends, pending=pending)
    except sqlite3.Error as e:
        logging.error(f"Friends page database error: {e}")
        flash("Error loading friends. Please try again.")
        return redirect(url_for("chat"))

@app.route("/send_friend_request/<to_user>")
@login_required
def send_friend_request(to_user):
    try:
        db = get_db()
        if to_user == current_user.id:
            flash("Cannot add yourself.")
        else:
            # Check if user exists
            user_exists = db.execute("SELECT username FROM users WHERE username = ?", (to_user,)).fetchone()
            if not user_exists:
                flash("User not found.")
                return redirect(url_for("friends"))
            
            existing = db.execute(
                "SELECT id FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'",
                (current_user.id, to_user)).fetchone()
            already = db.execute(
                "SELECT id FROM friendships WHERE (user=? AND friend=?) OR (user=? AND friend=?)",
                (current_user.id, to_user, to_user, current_user.id)).fetchone()
            if not existing and not already:
                db.execute("INSERT INTO friend_requests (from_user, to_user) VALUES (?, ?)", (current_user.id, to_user))
                db.commit()
                # Send real-time notification
                socketio.emit('new_friend_request', {
                    'from_user': current_user.id
                }, room=to_user)
                flash("Friend request sent.")
            else:
                flash("Request already sent or you're already friends.")
    except sqlite3.Error as e:
        logging.error(f"Send friend request error: {e}")
        flash("Error sending friend request.")
    return jsonify({'status': 'success'})

@app.route("/respond_friend_request/<int:req_id>/<action>")
@login_required
def respond_friend_request(req_id, action):
    db = get_db()
    req = db.execute("SELECT * FROM friend_requests WHERE id=?", (req_id,)).fetchone()
    if req and req["to_user"] == current_user.id:
        if action == "accept":
            db.execute("UPDATE friend_requests SET status='accepted' WHERE id=?", (req_id,))
            # Only insert one friendship record per pair
            db.execute("INSERT INTO friendships (user, friend) VALUES (?, ?)",
                       (req["from_user"], req["to_user"]))
            db.commit()
            # Emit real-time notification
            socketio.emit('friend_request_accepted', {
                'from_user': current_user.id,
                'to_user': req["from_user"]
            }, room=req["from_user"])
        else:
            db.execute("UPDATE friend_requests SET status='rejected' WHERE id=?", (req_id,))
            db.commit()
    return redirect(url_for("friends"))

@app.route('/private_chat/<friend_username>')
@login_required
def private_chat(friend_username):
    try:
        db = get_db()
        # Check if users are friends
        friendship = db.execute(
            "SELECT id FROM friendships WHERE (user=? AND friend=?) OR (user=? AND friend=?)",
            (current_user.id, friend_username, friend_username, current_user.id)
        ).fetchone()
        
        if not friendship:
            flash("You can only chat with friends.")
            return redirect(url_for("friends"))
        
        # Get private message history (last 100 messages)
        messages = db.execute("""
            SELECT from_user, to_user, message, timestamp 
            FROM private_messages 
            WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) 
            ORDER BY id DESC LIMIT 100
        """, (current_user.id, friend_username, friend_username, current_user.id)).fetchall()
        
        messages = list(reversed(messages))  # Show oldest first
        
        # Get all friends for sidebar
        friends = db.execute("""
            SELECT DISTINCT 
                CASE 
                    WHEN user = ? THEN friend 
                    ELSE user 
                END as friend_name
            FROM friendships 
            WHERE user = ? OR friend = ?
        """, (current_user.id, current_user.id, current_user.id)).fetchall()
        
        return render_template("private_chat.html", 
                             username=current_user.id, 
                             friend=friend_username,
                             messages=messages, 
                             friends=[f["friend_name"] for f in friends])
    except sqlite3.Error as e:
        logging.error(f"Private chat page database error: {e}")
        flash("Error loading chat. Please try again.")
        return redirect(url_for("friends"))

@app.route('/search_users')
@login_required
@limiter.limit("10 per minute")
def search_users():
    query = request.args.get('query', '').strip()
    if not query or len(query) < 2:
        return jsonify(users=[])
    
    # Sanitize search query
    query = bleach.clean(query, tags=[], strip=True)
    
    try:
        # Use parameterized query to prevent SQL injection
        search_pattern = f"%{query}%"
        users = safe_db_execute("""
            SELECT DISTINCT u.username, 
                   CASE WHEN f.user IS NOT NULL OR f.friend IS NOT NULL THEN 1 ELSE 0 END as is_friend,
                   CASE WHEN fr.id IS NOT NULL THEN 1 ELSE 0 END as has_pending_request
            FROM users u
            LEFT JOIN friendships f ON (f.user = ? AND f.friend = u.username) OR (f.friend = ? AND f.user = u.username)
            LEFT JOIN friend_requests fr ON (fr.from_user = ? AND fr.to_user = u.username AND fr.status = 'pending')
            WHERE u.username LIKE ? AND u.username != ? AND u.username != 'admin'
            LIMIT 10
        """, (current_user.id, current_user.id, current_user.id, search_pattern, current_user.id), fetch_all=True)
        
        # Filter and return results with status
        result = []
        for user in users:
            status = 'available'
            if user['is_friend']:
                status = 'friend'
            elif user['has_pending_request']:
                status = 'pending'
            
            result.append({
                'username': sanitize_message(user['username']),
                'status': status
            })
        
        return jsonify(users=result)
    except Exception as e:
        logging.error(f"Search users error: {e}")
        return jsonify(users=[], error="Search failed"), 500

@socketio.on("message")
@socketio_login_required
def handle_public_message(data):
    if not current_user.is_authenticated:
        return False
    
    try:
        db = get_db()
        username = current_user.id
        msg = data.get("msg", "").strip()
        
        # Validate message
        if not msg or len(msg) > 500:
            return False
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
                   (username, msg, timestamp))
        db.commit()
        send({"msg": msg, "user": username, "time": timestamp}, broadcast=True)
    except sqlite3.Error as e:
        logging.error(f"Message handling error: {e}")
        return False

@socketio.on("connect")
def on_connect():
    if current_user.is_authenticated:
        join_room(current_user.id)

@socketio.on("private_message")
@socketio_login_required
def handle_private(data):
    if not current_user.is_authenticated:
        return False
    
    try:
        db = get_db()
        to_user = data.get("to", "").strip()
        msg = data.get("msg", "").strip()
        
        # Validate message and recipient
        if not msg or not to_user or len(msg) > 500:
            return False
        
        # Check if users are friends
        friendship = db.execute(
            "SELECT id FROM friendships WHERE (user=? AND friend=?) OR (user=? AND friend=?)",
            (current_user.id, to_user, to_user, current_user.id)
        ).fetchone()
        
        if not friendship:
            return False  # Only allow messages between friends
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO private_messages (from_user, to_user, message, timestamp) VALUES (?, ?, ?, ?)",
                   (current_user.id, to_user, msg, timestamp))
        db.commit()
        
        emit("private_message", {
            "msg": msg,
            "from": current_user.id,
            "time": timestamp
        }, room=to_user)
        emit("private_message", {
            "msg": msg,
            "from": "You",
            "time": timestamp
        }, room=current_user.id)
    except sqlite3.Error as e:
        logging.error(f"Private message handling error: {e}")
        return False

if __name__ == "__main__":
    with app.app_context():
        init_db()
    socketio.run(app, debug=True)
