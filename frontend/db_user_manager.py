import hashlib
import uuid
import threading
import time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple
import psycopg2
from psycopg2 import extras
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('db_user_manager')

# Import User and UserSession classes from models_and_managers.py
from models_and_managers import User, UserSession

class PostgreSQLUserManager:
    """
    PostgreSQL implementation of the UserManager class.
    Provides the same interface as the in-memory UserManager but uses PostgreSQL for storage.
    """
    def __init__(self, session_timeout_hours=24, fallback_to_memory=True):
        """
        Initialize the PostgreSQL user manager.

        Args:
            session_timeout_hours: Number of hours before a session expires
            fallback_to_memory: Whether to fall back to in-memory storage if PostgreSQL is unavailable
        """
        self.session_timeout = timedelta(hours=session_timeout_hours)
        self.lock = threading.Lock()
        self.fallback_to_memory = fallback_to_memory

        # In-memory fallback storage
        self.users: Dict[str, User] = {}
        self.usernames: Dict[str, str] = {}
        self.sessions: Dict[str, UserSession] = {}

        # PostgreSQL connection parameters
        self.database_url = os.environ.get('DATABASE_URL', 'postgresql://user:password@network_db:5432/networkdb')

        # Initialize the database and create default admin if needed
        try:
            self._create_default_admin()
        except Exception as e:
            logger.error(f"Error initializing PostgreSQL user manager: {e}")
            if not self.fallback_to_memory:
                raise
            logger.warning("Falling back to in-memory storage")
            # Initialize in-memory storage with default admin
            self._create_default_admin_memory()

    def get_db_connection(self):
        """Get a connection to the PostgreSQL database"""
        try:
            conn = psycopg2.connect(self.database_url)
            return conn
        except Exception as e:
            logger.error(f"Error connecting to PostgreSQL: {e}")
            if not self.fallback_to_memory:
                raise
            return None

    def _create_default_admin(self):
        """Create a default admin user if it doesn't exist"""
        conn = self.get_db_connection()
        if conn is None and self.fallback_to_memory:
            return self._create_default_admin_memory()

        try:
            cursor = conn.cursor()

            # Ensure tables exist
            self._ensure_tables_exist(cursor)

            # Check if admin user exists
            cursor.execute("SELECT user_id FROM users WHERE username = %s", ("admin",))
            admin = cursor.fetchone()

            if admin is None:
                admin_id = str(uuid.uuid4())
                password_hash = hashlib.sha256("admin123".encode()).hexdigest()
                now = datetime.now()

                cursor.execute("""
                INSERT INTO users (user_id, username, email, password_hash, created_at, role)
                VALUES (%s, %s, %s, %s, %s, %s)
                """, (admin_id, "admin", "admin@localhost", password_hash, now, "admin"))

                conn.commit()
                logger.info("👑 Admin créé - Username: admin, Password: admin123")

            conn.close()
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
            if conn:
                conn.close()
            if self.fallback_to_memory:
                return self._create_default_admin_memory()
            raise

    def _create_default_admin_memory(self):
        """Create a default admin user in memory (fallback)"""
        with self.lock:
            if "admin" in self.usernames:
                return

            admin_id = str(uuid.uuid4())
            password_hash = hashlib.sha256("admin123".encode()).hexdigest()

            admin = User(
                user_id=admin_id,
                username="admin",
                email="admin@localhost",
                password_hash=password_hash,
                created_at=datetime.now(),
                role="admin"
            )

            self.users[admin_id] = admin
            self.usernames["admin"] = admin_id
            logger.info("👑 Admin créé en mémoire (fallback) - Username: admin, Password: admin123")

    def authenticate(self, username: str, password: str, ip_address: str = "unknown") -> Optional[str]:
        """
        Authenticate a user and create a session.

        Args:
            username: The username
            password: The password
            ip_address: The IP address of the client

        Returns:
            The session ID if authentication is successful, None otherwise
        """
        conn = self.get_db_connection()
        if conn is None and self.fallback_to_memory:
            return self._authenticate_memory(username, password, ip_address)

        try:
            cursor = conn.cursor(cursor_factory=extras.DictCursor)

            # Ensure tables exist
            self._ensure_tables_exist(cursor)

            # Check if user exists and password is correct
            cursor.execute("""
            SELECT * FROM users 
            WHERE username = %s AND is_active = TRUE
            """, (username,))

            user_data = cursor.fetchone()
            if not user_data:
                conn.close()
                return None

            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user_data['password_hash'] != password_hash:
                conn.close()
                return None

            # Create a new session
            session_id = str(uuid.uuid4())
            now = datetime.now()
            expires_at = now + self.session_timeout

            cursor.execute("""
            INSERT INTO user_sessions 
            (session_id, user_id, username, created_at, last_activity, ip_address, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (session_id, user_data['user_id'], username, now, now, ip_address, expires_at))

            # Update last login time
            cursor.execute("""
            UPDATE users SET last_login = %s WHERE user_id = %s
            """, (now, user_data['user_id']))

            conn.commit()
            conn.close()
            return session_id
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            if conn:
                conn.close()
            if self.fallback_to_memory:
                return self._authenticate_memory(username, password, ip_address)
            return None

    def _authenticate_memory(self, username: str, password: str, ip_address: str = "unknown") -> Optional[str]:
        """In-memory fallback for authentication"""
        with self.lock:
            if username not in self.usernames:
                return None

            user_id = self.usernames[username]
            user = self.users[user_id]

            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user.password_hash != password_hash or not user.is_active:
                return None

            session_id = str(uuid.uuid4())
            now = datetime.now()

            session = UserSession(
                session_id=session_id,
                user_id=user_id,
                username=username,
                created_at=now,
                last_activity=now,
                ip_address=ip_address,
                expires_at=now + self.session_timeout
            )

            self.sessions[session_id] = session
            user.last_login = now
            return session_id

    def get_user_by_session(self, session_id: str) -> Optional[User]:
        """
        Get a user by session ID.

        Args:
            session_id: The session ID

        Returns:
            The user if the session is valid, None otherwise
        """
        conn = self.get_db_connection()
        if conn is None and self.fallback_to_memory:
            return self._get_user_by_session_memory(session_id)

        try:
            cursor = conn.cursor(cursor_factory=extras.DictCursor)

            # Ensure tables exist
            self._ensure_tables_exist(cursor)

            # Get the session
            cursor.execute("""
            SELECT * FROM user_sessions WHERE session_id = %s
            """, (session_id,))

            session_data = cursor.fetchone()
            if not session_data:
                conn.close()
                return None

            now = datetime.now()

            # Check if session has expired
            if now > session_data['expires_at']:
                cursor.execute("""
                DELETE FROM user_sessions WHERE session_id = %s
                """, (session_id,))
                conn.commit()
                conn.close()
                return None

            # Update last activity
            cursor.execute("""
            UPDATE user_sessions SET last_activity = %s WHERE session_id = %s
            """, (now, session_id))

            # Get the user
            cursor.execute("""
            SELECT * FROM users WHERE user_id = %s
            """, (session_data['user_id'],))

            user_data = cursor.fetchone()
            if not user_data:
                conn.close()
                return None

            conn.commit()
            conn.close()

            # Convert to User object
            return User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                password_hash=user_data['password_hash'],
                created_at=user_data['created_at'],
                last_login=user_data['last_login'],
                is_active=user_data['is_active'],
                role=user_data['role']
            )
        except Exception as e:
            logger.error(f"Error getting user by session: {e}")
            if conn:
                conn.close()
            if self.fallback_to_memory:
                return self._get_user_by_session_memory(session_id)
            return None

    def _get_user_by_session_memory(self, session_id: str) -> Optional[User]:
        """In-memory fallback for getting user by session"""
        with self.lock:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]
            now = datetime.now()

            if now > session.expires_at:
                del self.sessions[session_id]
                return None

            session.last_activity = now
            return self.users.get(session.user_id)

    def register_user(self, username: str, email: str, password: str, role: str = "user") -> bool:
        """
        Register a new user.

        Args:
            username: The username
            email: The email
            password: The password
            role: The role (default: "user")

        Returns:
            True if registration is successful, False otherwise
        """
        conn = self.get_db_connection()
        if conn is None and self.fallback_to_memory:
            return self._register_user_memory(username, email, password, role)

        try:
            cursor = conn.cursor()

            # Ensure tables exist
            self._ensure_tables_exist(cursor)

            # Check if username already exists
            cursor.execute("""
            SELECT user_id FROM users WHERE username = %s
            """, (username,))

            if cursor.fetchone():
                conn.close()
                return False

            # Create new user
            user_id = str(uuid.uuid4())
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            now = datetime.now()

            cursor.execute("""
            INSERT INTO users 
            (user_id, username, email, password_hash, created_at, role)
            VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, username, email, password_hash, now, role))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            if conn:
                conn.close()
            if self.fallback_to_memory:
                return self._register_user_memory(username, email, password, role)
            return False

    def _register_user_memory(self, username: str, email: str, password: str, role: str = "user") -> bool:
        """In-memory fallback for registering a user"""
        with self.lock:
            if username in self.usernames:
                return False

            user_id = str(uuid.uuid4())
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                created_at=datetime.now(),
                role=role
            )

            self.users[user_id] = user
            self.usernames[username] = user_id
            return True

    def logout(self, session_id: str) -> bool:
        """
        Log out a user by deleting their session.

        Args:
            session_id: The session ID

        Returns:
            True if logout is successful, False otherwise
        """
        conn = self.get_db_connection()
        if conn is None and self.fallback_to_memory:
            return self._logout_memory(session_id)

        try:
            cursor = conn.cursor()

            # Delete the session
            cursor.execute("""
            DELETE FROM user_sessions WHERE session_id = %s
            """, (session_id,))

            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return success
        except Exception as e:
            logger.error(f"Error logging out: {e}")
            if conn:
                conn.close()
            if self.fallback_to_memory:
                return self._logout_memory(session_id)
            return False

    def _logout_memory(self, session_id: str) -> bool:
        """In-memory fallback for logging out"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            return False

    def cleanup_expired_sessions(self):
        """Clean up expired sessions from the database"""
        conn = self.get_db_connection()
        if conn is None:
            return

        try:
            cursor = conn.cursor()

            now = datetime.now()
            cursor.execute("""
            DELETE FROM user_sessions WHERE expires_at < %s
            """, (now,))

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            if conn:
                conn.close()

    def _ensure_tables_exist(self, cursor):
        """Ensure that the required tables exist in the database"""
        try:
            # Create users table if it doesn't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                role TEXT DEFAULT 'user'
            )
            """)

            # Create user_sessions table if it doesn't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_activity TIMESTAMP NOT NULL,
                ip_address TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """)

            # Create indexes if they don't exist
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)
            """)

            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at)
            """)

            logger.info("Database tables and indexes created or verified")
        except Exception as e:
            logger.error(f"Error ensuring tables exist: {e}")
            raise

    def sync_to_database(self):
        """
        Synchronize in-memory data to the database.
        This is useful when falling back to in-memory storage and then reconnecting to the database.
        """
        if not self.users:
            return

        conn = self.get_db_connection()
        if conn is None:
            return

        try:
            cursor = conn.cursor()

            # Sync users
            for user_id, user in self.users.items():
                cursor.execute("""
                INSERT INTO users 
                (user_id, username, email, password_hash, created_at, last_login, is_active, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                username = EXCLUDED.username,
                email = EXCLUDED.email,
                password_hash = EXCLUDED.password_hash,
                created_at = EXCLUDED.created_at,
                last_login = EXCLUDED.last_login,
                is_active = EXCLUDED.is_active,
                role = EXCLUDED.role
                """, (
                    user.user_id, user.username, user.email, user.password_hash,
                    user.created_at, user.last_login, user.is_active, user.role
                ))

            # Sync sessions
            for session_id, session in self.sessions.items():
                cursor.execute("""
                INSERT INTO user_sessions 
                (session_id, user_id, username, created_at, last_activity, ip_address, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (session_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                username = EXCLUDED.username,
                created_at = EXCLUDED.created_at,
                last_activity = EXCLUDED.last_activity,
                ip_address = EXCLUDED.ip_address,
                expires_at = EXCLUDED.expires_at
                """, (
                    session.session_id, session.user_id, session.username,
                    session.created_at, session.last_activity, session.ip_address, session.expires_at
                ))

            conn.commit()
            conn.close()

            # Clear in-memory storage
            self.users = {}
            self.usernames = {}
            self.sessions = {}
        except Exception as e:
            logger.error(f"Error syncing to database: {e}")
            if conn:
                conn.close()
