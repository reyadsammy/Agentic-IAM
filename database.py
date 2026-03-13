"""
Database Management Module for Agentic-IAM

Handles SQLite database operations for logging events and storing agent data.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import os

# Optional secret manager integration
try:
    from secrets.key_vault import secret_manager
except Exception:
    secret_manager = None
import logging
import bcrypt

logger = logging.getLogger(__name__)

class Database:
    """SQLite database manager for Agentic-IAM"""
    
    def __init__(self, db_path: str = "data/agentic_iam.db"):
        """Initialize database connection"""
        self.db_path = db_path
        self._ensure_db_path()
        self.init_tables()
    
    def _ensure_db_path(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def init_tables(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table for dashboard authentication
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT DEFAULT 'user',
                    full_name TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            
            # Agents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Events/Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'success',
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            
            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    metadata TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            
            # Agent permissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    permission TEXT NOT NULL,
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    granted_by INTEGER,
                    FOREIGN KEY (agent_id) REFERENCES agents(id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (granted_by) REFERENCES users(id)
                )
            """)
            
            # Agent capabilities tracking table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_capabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                )
            """)
            
            # Login history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    ip_address TEXT DEFAULT '127.0.0.1',
                    user_agent TEXT DEFAULT '',
                    reason TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Security test results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    passed BOOLEAN NOT NULL,
                    details TEXT,
                    recommendation TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create default admin and user if not exists
            # Ensure schema migrations for older DBs: add missing columns
            cursor.execute("PRAGMA table_info(users)")
            existing_cols = [r[1] for r in cursor.fetchall()]
            if 'full_name' not in existing_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
            if 'status' not in existing_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")

            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role, full_name, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ("admin", sqlite3.Binary(admin_password), "admin@agentic-iam.com", "admin", "Administrator", "active"))

                user_password = bcrypt.hashpw("user123".encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role, full_name, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ("user", sqlite3.Binary(user_password), "user@agentic-iam.com", "user", "Default User", "active"))
                
                # Create operator user
                operator_password = bcrypt.hashpw("operator123".encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role, full_name, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, ("operator", sqlite3.Binary(operator_password), "operator@agentic-iam.com", "operator", "System Operator", "active"))
            
            conn.commit()
            logger.info("Database tables initialized successfully")
    
    # Agent operations
    def add_agent(self, agent_id: str, name: str, agent_type: str = "standard", metadata: Dict = None) -> bool:
        """Add new agent to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO agents (id, name, type, metadata)
                    VALUES (?, ?, ?, ?)
                """, (agent_id, name, agent_type, json.dumps(metadata or {})))
                conn.commit()
                
                # Log event
                self.log_event("agent_created", agent_id, "create", f"Agent {name} created")
                logger.info(f"Agent {agent_id} added to database")
                return True
        except sqlite3.IntegrityError:
            logger.error(f"Agent {agent_id} already exists")
            return False
        except Exception as e:
            logger.error(f"Error adding agent: {e}")
            return False
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent details"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'status': row[3],
                        'created_at': row[4],
                        'updated_at': row[5],
                        'metadata': json.loads(row[6]) if row[6] else {}
                    }
        except Exception as e:
            logger.error(f"Error getting agent: {e}")
        return None
    
    def list_agents(self) -> List[Dict]:
        """List all agents"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agents ORDER BY created_at DESC")
                rows = cursor.fetchall()
                agents = []
                for row in rows:
                    agents.append({
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'status': row[3],
                        'created_at': row[4],
                        'updated_at': row[5],
                        'metadata': json.loads(row[6]) if row[6] else {}
                    })
                return agents
        except Exception as e:
            logger.error(f"Error listing agents: {e}")
        return []
    
    def update_agent(self, agent_id: str, **kwargs) -> bool:
        """Update agent information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                updates = []
                values = []
                
                for key, value in kwargs.items():
                    if key in ['name', 'type', 'status']:
                        updates.append(f"{key} = ?")
                        values.append(value)
                
                if not updates:
                    return False
                
                updates.append("updated_at = ?")
                values.append(datetime.now().isoformat())
                values.append(agent_id)
                
                query = f"UPDATE agents SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, values)
                conn.commit()
                
                self.log_event("agent_updated", agent_id, "update", f"Agent {agent_id} updated")
                return True
        except Exception as e:
            logger.error(f"Error updating agent: {e}")
            return False
    
    # Event logging operations
    def log_event(self, event_type: str, agent_id: Optional[str] = None, 
                  action: Optional[str] = None, details: Optional[str] = None, 
                  status: str = "success") -> bool:
        """Log an event to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO events (event_type, agent_id, action, details, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (event_type, agent_id, action, details, status))
                conn.commit()
                logger.info(f"Event logged: {event_type} for agent {agent_id}")
                return True
        except Exception as e:
            logger.error(f"Error logging event: {e}")
            return False
    
    def get_events(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get events from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if agent_id:
                    cursor.execute("""
                        SELECT * FROM events 
                        WHERE agent_id = ? 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    """, (agent_id, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM events 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    """, (limit,))
                
                rows = cursor.fetchall()
                events = []
                for row in rows:
                    events.append({
                        'id': row[0],
                        'event_type': row[1],
                        'agent_id': row[2],
                        'action': row[3],
                        'details': row[4],
                        'created_at': row[5],
                        'status': row[6]
                    })
                return events
        except Exception as e:
            logger.error(f"Error getting events: {e}")
        return []
    
    # Session operations
    def create_session(self, session_id: str, agent_id: str, metadata: Dict = None) -> bool:
        """Create a session for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO sessions (id, agent_id, metadata)
                    VALUES (?, ?, ?)
                """, (session_id, agent_id, json.dumps(metadata or {})))
                conn.commit()
                self.log_event("session_created", agent_id, "session_start", f"Session {session_id} started")
                return True
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False
    
    def end_session(self, session_id: str) -> bool:
        """End a session"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE sessions 
                    SET status = 'ended', ended_at = ? 
                    WHERE id = ?
                """, (datetime.now().isoformat(), session_id))
                conn.commit()
                
                # Get agent_id for logging
                cursor.execute("SELECT agent_id FROM sessions WHERE id = ?", (session_id,))
                result = cursor.fetchone()
                if result:
                    self.log_event("session_ended", result[0], "session_end", f"Session {session_id} ended")
                
                return True
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False
    
    def get_agent_sessions(self, agent_id: str) -> List[Dict]:
        """Get all sessions for an agent"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM sessions 
                    WHERE agent_id = ? 
                    ORDER BY started_at DESC
                """, (agent_id,))
                
                rows = cursor.fetchall()
                sessions = []
                for row in rows:
                    sessions.append({
                        'id': row[0],
                        'agent_id': row[1],
                        'started_at': row[2],
                        'ended_at': row[3],
                        'status': row[4],
                        'metadata': json.loads(row[5]) if row[5] else {}
                    })
                return sessions
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
        return []

    def list_users(self) -> list:
        """List all users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, username, email, role, full_name, status, created_at, last_login FROM users")
                rows = cursor.fetchall()
                users = []
                for row in rows:
                    users.append({
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'role': row[3],
                        'full_name': row[4],
                        'status': row[5],
                        'created_at': row[6],
                        'last_login': row[7]
                    })
                return users
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return []

    def authenticate_user(self, username: str, password: str) -> dict:
        """Authenticate a user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, username, email, role, password_hash, full_name, status,
                           created_at, last_login
                    FROM users WHERE username = ?
                """, (username,))
                row = cursor.fetchone()
                if row:
                    stored_hash = row[4]
                    # Ensure stored_hash is bytes
                    if isinstance(stored_hash, memoryview):
                        stored_hash = stored_hash.tobytes()
                    if isinstance(stored_hash, str):
                        stored_hash = stored_hash.encode('utf-8')
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                        # Update last login
                        cursor.execute("""
                            UPDATE users SET last_login = datetime('now') WHERE id = ?
                        """, (row[0],))
                        conn.commit()
                        return {
                            'id': row[0],
                            'username': row[1],
                            'email': row[2],
                            'role': row[3],
                            'full_name': row[5],
                            'status': row[6],
                            'created_at': row[7],
                            'last_login': row[8],
                        }
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
        return None

    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> bool:
        """Create a new user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (username, password_hash, email, role, full_name, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """, (username, sqlite3.Binary(password_hash), email, role, '', 'active'))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            logger.error(f"User {username} already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
        return False

    def change_password(self, user_id: int, new_password: str) -> bool:
        """Change user password"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("""
                    UPDATE users SET password_hash = ? WHERE id = ?
                """, (sqlite3.Binary(password_hash), user_id))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error changing password: {e}")
        return False

    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, username, email, role, full_name, status, created_at, last_login 
                    FROM users WHERE id = ?
                """, (user_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'role': row[3],
                        'full_name': row[4],
                        'status': row[5],
                        'created_at': row[6],
                        'last_login': row[7]
                    }
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
        return None

    def update_user_role(self, user_id: int, new_role: str) -> bool:
        """Update user role"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET role = ? WHERE id = ?
                """, (new_role, user_id))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating user role: {e}")
        return False

    def update_user_status(self, user_id: int, new_status: str) -> bool:
        """Update user status (active/suspended)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET status = ? WHERE id = ?
                """, (new_status, user_id))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating user status: {e}")
        return False

    def delete_user(self, user_id: int) -> bool:
        """Delete a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
        return False

    # Login history operations
    def record_login(self, username: str, success: bool, ip_address: str = "127.0.0.1",
                     user_agent: str = "", reason: str = "") -> bool:
        """Record a login attempt in history."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO login_history (username, success, ip_address, user_agent, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, success, ip_address, user_agent, reason))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error recording login: {e}")
            return False

    def get_login_history(self, username: str = None, limit: int = 50) -> List[Dict]:
        """Get login history, optionally filtered by username."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if username:
                    cursor.execute("""
                        SELECT id, username, success, ip_address, user_agent, reason, created_at
                        FROM login_history WHERE username = ?
                        ORDER BY created_at DESC LIMIT ?
                    """, (username, limit))
                else:
                    cursor.execute("""
                        SELECT id, username, success, ip_address, user_agent, reason, created_at
                        FROM login_history ORDER BY created_at DESC LIMIT ?
                    """, (limit,))
                rows = cursor.fetchall()
                return [{
                    'id': r[0], 'username': r[1], 'success': bool(r[2]),
                    'ip_address': r[3], 'user_agent': r[4], 'reason': r[5],
                    'created_at': r[6]
                } for r in rows]
        except Exception as e:
            logger.error(f"Error getting login history: {e}")
            return []

    def create_task(self, agent_id: str, task_type: str = "general", details: str = "") -> bool:
        """Create a remediation or general task linked to an agent.

        Tasks are stored as events with event_type 'task_created' so they
        appear in the audit trail alongside other events.
        """
        return self.log_event(
            event_type="task_created",
            agent_id=agent_id,
            action=task_type,
            details=details,
            status="pending"
        )

    # Security test results operations
    def save_test_results(self, run_id: str, results: list) -> bool:
        """Save a batch of security test results for a given run_id."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                for r in results:
                    cursor.execute("""
                        INSERT INTO security_test_results
                            (run_id, test_id, category, name, severity, passed, details, recommendation)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        run_id,
                        r.get('test_id', ''),
                        r.get('category', ''),
                        r.get('name', ''),
                        r.get('severity', 'info'),
                        r.get('passed', False),
                        r.get('details', ''),
                        r.get('recommendation', ''),
                    ))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving test results: {e}")
            return False

    def get_test_results(self, run_id: str) -> List[Dict]:
        """Get all results for a specific run_id."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT run_id, test_id, category, name, severity, passed,
                           details, recommendation, created_at
                    FROM security_test_results
                    WHERE run_id = ?
                    ORDER BY id
                """, (run_id,))
                rows = cursor.fetchall()
                return [{
                    'run_id': r[0], 'test_id': r[1], 'category': r[2],
                    'name': r[3], 'severity': r[4], 'passed': bool(r[5]),
                    'details': r[6], 'recommendation': r[7], 'created_at': r[8],
                } for r in rows]
        except Exception as e:
            logger.error(f"Error getting test results: {e}")
            return []

    def get_test_runs(self, limit: int = 10) -> List[Dict]:
        """Get distinct run_ids with aggregated counts."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT run_id,
                           COUNT(*) as total,
                           SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                           SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as failed,
                           SUM(CASE WHEN passed = 0 AND severity = 'critical' THEN 1 ELSE 0 END) as critical,
                           MIN(created_at) as created_at
                    FROM security_test_results
                    GROUP BY run_id
                    ORDER BY MIN(created_at) DESC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [{
                    'run_id': r[0], 'total': r[1], 'passed': r[2],
                    'failed': r[3], 'critical': r[4], 'created_at': r[5],
                } for r in rows]
        except Exception as e:
            logger.error(f"Error getting test runs: {e}")
            return []

    def get_latest_test_run(self) -> Optional[str]:
        """Get the most recent run_id."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT run_id FROM security_test_results
                    ORDER BY created_at DESC LIMIT 1
                """)
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Error getting latest test run: {e}")
            return None

    def get_test_summary(self, run_id: str) -> Optional[Dict]:
        """Get aggregated summary for a specific run."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                           SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as failed,
                           SUM(CASE WHEN passed = 0 AND severity = 'critical' THEN 1 ELSE 0 END) as critical,
                           MIN(created_at) as created_at
                    FROM security_test_results
                    WHERE run_id = ?
                """, (run_id,))
                row = cursor.fetchone()
                if row and row[0] > 0:
                    return {
                        'run_id': run_id, 'total': row[0], 'passed': row[1],
                        'failed': row[2], 'critical': row[3], 'created_at': row[4],
                    }
        except Exception as e:
            logger.error(f"Error getting test summary: {e}")
        return None


# Global database instance
_db_instance = None

def get_database(db_path: str = "data/agentic_iam.db") -> Database:
    """Get or create global database instance"""
    global _db_instance
    if _db_instance is None:
        # Allow DB path override from environment or secret manager
        resolved_path = os.getenv("DB_PATH")
        if not resolved_path and secret_manager:
            try:
                resolved_path = secret_manager.get_secret("DB_PATH")
            except Exception:
                resolved_path = None

        if not resolved_path:
            resolved_path = db_path

        _db_instance = Database(resolved_path)
    return _db_instance
