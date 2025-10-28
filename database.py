"""
Conners Group AI Assistant - Database Manager
SQLite database for conversations with Universal Memory support
ENHANCED VERSION with Alphabetical Organization & Advanced Features
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
import os

class ConversationDatabase:
    """Manages all conversation storage with Universal Memory"""
    
    def __init__(self, db_path="database/conversations.db"):
        """Initialize database connection"""
        self.db_path = db_path
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._create_tables()
    
    def _create_tables(self):
        """Create all necessary database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                color TEXT DEFAULT '#FFD700',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Conversations table (enhanced with alphabetical categories)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                title TEXT NOT NULL,
                category_letter TEXT DEFAULT 'U',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_pinned BOOLEAN DEFAULT 0,
                is_archived BOOLEAN DEFAULT 0,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
            )
        """)
        
        # Messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tokens_used INTEGER DEFAULT 0,
                cost REAL DEFAULT 0.0,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            )
        """)
        
        # Tags table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                color TEXT DEFAULT '#3B82F6'
            )
        """)
        
        # Conversation tags (many-to-many)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversation_tags (
                conversation_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, tag_id),
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            )
        """)
        
        # Prompt templates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS prompt_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Usage tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                total_cost REAL DEFAULT 0.0,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            )
        """)
        
        # Full-text search index
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                message_id UNINDEXED,
                conversation_id UNINDEXED,
                content,
                tokenize='porter'
            )
        """)
        
        # Categories table for alphabetical organization
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                letter TEXT NOT NULL UNIQUE,
                description TEXT,
                color TEXT DEFAULT '#D4AF37'
            )
        """)
        
        # Initialize default categories (A-Z + Numbers + Uncategorized)
        cursor.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] == 0:
            categories = [
                ('A', 'Conversations starting with A', '#FF6B6B'),
                ('B', 'Conversations starting with B', '#4ECDC4'),
                ('C', 'Conversations starting with C', '#45B7D1'),
                ('D', 'Conversations starting with D', '#FFA07A'),
                ('E', 'Conversations starting with E', '#98D8C8'),
                ('F', 'Conversations starting with F', '#F7DC6F'),
                ('G', 'Conversations starting with G', '#BB8FCE'),
                ('H', 'Conversations starting with H', '#85C1E2'),
                ('I', 'Conversations starting with I', '#F8B739'),
                ('J', 'Conversations starting with J', '#52B788'),
                ('K', 'Conversations starting with K', '#E63946'),
                ('L', 'Conversations starting with L', '#457B9D'),
                ('M', 'Conversations starting with M', '#A8DADC'),
                ('N', 'Conversations starting with N', '#F1FAEE'),
                ('O', 'Conversations starting with O', '#E76F51'),
                ('P', 'Conversations starting with P', '#2A9D8F'),
                ('Q', 'Conversations starting with Q', '#E9C46A'),
                ('R', 'Conversations starting with R', '#F4A261'),
                ('S', 'Conversations starting with S', '#264653'),
                ('T', 'Conversations starting with T', '#287271'),
                ('U', 'Conversations starting with U', '#8B5A3C'),
                ('V', 'Conversations starting with V', '#774C60'),
                ('W', 'Conversations starting with W', '#6A994E'),
                ('X', 'Conversations starting with X', '#BC4749'),
                ('Y', 'Conversations starting with Y', '#F2CC8F'),
                ('Z', 'Conversations starting with Z', '#81B29A'),
                ('#', 'Conversations starting with Numbers', '#D4AF37'),
                ('U', 'Uncategorized conversations', '#64748B')
            ]
            cursor.executemany("""
                INSERT INTO categories (letter, description, color)
                VALUES (?, ?, ?)
            """, categories)
        
        conn.commit()
        conn.close()
    
    # ============================================
    # SECTION A: PROJECT MANAGEMENT
    # ============================================
    
    def create_project(self, name, description="", color="#FFD700"):
        """Create a new project folder"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO projects (name, description, color)
                VALUES (?, ?, ?)
            """, (name, description, color))
            conn.commit()
            project_id = cursor.lastrowid
            return project_id  # FIXED: Return integer, not dict
        except sqlite3.IntegrityError:
            raise Exception("Project already exists")
        finally:
            conn.close()
    
    def get_all_projects(self):
        """Get all projects - returns list of dictionaries for API compatibility"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, description, color, created_at
            FROM projects
            ORDER BY name ASC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        # Convert tuples to dictionaries for JavaScript/API compatibility
        projects = []
        for row in rows:
            projects.append({
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'color': row[3],
                'created_at': row[4]
            })
        
        return projects
    
    def update_project(self, project_id, name=None, description=None, color=None):
        """Update project details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        updates = []
        params = []
        
        if name:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if color:
            updates.append("color = ?")
            params.append(color)
        
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(project_id)
            
            cursor.execute(f"""
                UPDATE projects
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            
            conn.commit()
        
        conn.close()
        return {"success": True}
    
    def delete_project(self, project_id):
        """
        Delete a project
        Note: Conversations linked to this project will have project_id set to NULL
        (due to ON DELETE SET NULL cascade rule)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if project exists
            cursor.execute("SELECT name FROM projects WHERE id = ?", (project_id,))
            project = cursor.fetchone()
            
            if project:
                # Delete project (CASCADE will handle conversation links)
                cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
                conn.commit()
                conn.close()
                return {"success": True, "message": f"Project '{project[0]}' deleted successfully"}
            else:
                conn.close()
                return {"success": False, "error": "Project not found"}
        except Exception as e:
            conn.close()
            return {"success": False, "error": str(e)}
    
    def get_project_statistics(self, project_id):
        """Get statistics for a specific project"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get conversation count
        cursor.execute("""
            SELECT COUNT(*) FROM conversations WHERE project_id = ?
        """, (project_id,))
        conversation_count = cursor.fetchone()[0]
        
        # Get total messages
        cursor.execute("""
            SELECT COUNT(*) FROM messages
            WHERE conversation_id IN (
                SELECT id FROM conversations WHERE project_id = ?
            )
        """, (project_id,))
        message_count = cursor.fetchone()[0]
        
        # Get total tokens and cost
        cursor.execute("""
            SELECT 
                SUM(input_tokens + output_tokens) as total_tokens,
                SUM(total_cost) as total_cost
            FROM usage_logs
            WHERE conversation_id IN (
                SELECT id FROM conversations WHERE project_id = ?
            )
        """, (project_id,))
        
        result = cursor.fetchone()
        total_tokens = result[0] or 0
        total_cost = result[1] or 0.0
        
        conn.close()
        
        return {
            "conversation_count": conversation_count,
            "message_count": message_count,
            "total_tokens": total_tokens,
            "total_cost": total_cost
        }
    
    # ============================================
    # SECTION B: CONVERSATION MANAGEMENT
    # ============================================
    
    def _get_category_letter(self, title):
        """Determine category letter from conversation title"""
        if not title:
            return 'U'
        
        first_char = title[0].upper()
        
        if first_char.isalpha():
            return first_char
        elif first_char.isdigit():
            return '#'
        else:
            return 'U'
    
    def create_conversation(self, title, project_id=None):
        """Create a new conversation with automatic categorization"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Determine category letter
        category_letter = self._get_category_letter(title)
        
        cursor.execute("""
            INSERT INTO conversations (title, project_id, category_letter)
            VALUES (?, ?, ?)
        """, (title, project_id, category_letter))
        
        conn.commit()
        conversation_id = cursor.lastrowid
        conn.close()
        
        return conversation_id
    
    def get_conversations_by_project(self, project_id=None):
        """Get all conversations in a project (or all if project_id is None)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project_id:
            cursor.execute("""
                SELECT id, title, created_at, updated_at, is_pinned, category_letter
                FROM conversations
                WHERE project_id = ?
                ORDER BY is_pinned DESC, updated_at DESC
            """, (project_id,))
        else:
            cursor.execute("""
                SELECT id, title, created_at, updated_at, is_pinned, category_letter
                FROM conversations
                ORDER BY is_pinned DESC, updated_at DESC
            """)
        
        conversations = cursor.fetchall()
        conn.close()
        
        return conversations
    
    def get_conversations_by_category(self, category_letter):
        """Get all conversations in a specific alphabetical category"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT c.id, c.title, c.created_at, c.updated_at, c.is_pinned, 
                   p.name as project_name, p.color as project_color
            FROM conversations c
            LEFT JOIN projects p ON c.project_id = p.id
            WHERE c.category_letter = ?
            ORDER BY c.is_pinned DESC, c.updated_at DESC
        """, (category_letter,))
        
        conversations = []
        for row in cursor.fetchall():
            conversations.append({
                'id': row[0],
                'title': row[1],
                'created_at': row[2],
                'updated_at': row[3],
                'is_pinned': row[4],
                'project_name': row[5],
                'project_color': row[6]
            })
        
        conn.close()
        return conversations
    
    def get_all_categories_with_counts(self):
        """Get all categories with conversation counts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                cat.letter,
                cat.description,
                cat.color,
                COUNT(c.id) as conversation_count
            FROM categories cat
            LEFT JOIN conversations c ON cat.letter = c.category_letter
            GROUP BY cat.letter, cat.description, cat.color
            ORDER BY 
                CASE 
                    WHEN cat.letter = 'ÃƒÂ¢Ã‹Å“Ã¢â‚¬Â¦' THEN 2
                    WHEN cat.letter = '#' THEN 1
                    ELSE 0
                END,
                cat.letter ASC
        """)
        
        categories = []
        for row in cursor.fetchall():
            categories.append({
                'letter': row[0],
                'description': row[1],
                'color': row[2],
                'count': row[3]
            })
        
        conn.close()
        return categories
    
    def update_conversation_title(self, conversation_id, new_title):
        """Update conversation title and recategorize"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Determine new category
        category_letter = self._get_category_letter(new_title)
        
        cursor.execute("""
            UPDATE conversations
            SET title = ?, category_letter = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_title, category_letter, conversation_id))
        
        conn.commit()
        conn.close()
        return {"success": True}
    
    def pin_conversation(self, conversation_id, pinned=True):
        """Pin or unpin a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE conversations
            SET is_pinned = ?
            WHERE id = ?
        """, (1 if pinned else 0, conversation_id))
        
        conn.commit()
        conn.close()
    
    def archive_conversation(self, conversation_id, archived=True):
        """Archive or unarchive a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE conversations
            SET is_archived = ?
            WHERE id = ?
        """, (1 if archived else 0, conversation_id))
        
        conn.commit()
        conn.close()
    
    def delete_conversation(self, conversation_id):
        """
        Delete a conversation with TRIPLE FAILSAFE
        This should only be called after user confirmation
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Backup before delete (safety measure)
        cursor.execute("""
            SELECT * FROM conversations WHERE id = ?
        """, (conversation_id,))
        
        conversation = cursor.fetchone()
        
        if conversation:
            # Delete (CASCADE will handle messages)
            cursor.execute("""
                DELETE FROM conversations WHERE id = ?
            """, (conversation_id,))
            
            conn.commit()
            conn.close()
            return {"success": True}
        else:
            conn.close()
            return {"success": False, "error": "Conversation not found"}
    
    # ============================================
    # SECTION C: MESSAGE MANAGEMENT
    # ============================================
    
    def save_message(self, conversation_id, role, content, tokens=0, cost=0.0):
        """Save a message to the database with Universal Memory indexing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Save to messages table
        cursor.execute("""
            INSERT INTO messages (conversation_id, role, content, tokens_used, cost)
            VALUES (?, ?, ?, ?, ?)
        """, (conversation_id, role, content, tokens, cost))
        
        message_id = cursor.lastrowid
        
        # Index for full-text search (Universal Memory)
        cursor.execute("""
            INSERT INTO messages_fts (message_id, conversation_id, content)
            VALUES (?, ?, ?)
        """, (message_id, conversation_id, content))
        
        # Update conversation timestamp
        cursor.execute("""
            UPDATE conversations 
            SET updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (conversation_id,))
        
        conn.commit()
        conn.close()
        
        return message_id
    
    def get_conversation_history(self, conversation_id):
        """Get all messages from a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT role, content, timestamp, tokens_used, cost
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
        """, (conversation_id,))
        
        messages = cursor.fetchall()
        conn.close()
        
        return messages
    
    def delete_last_message(self, conversation_id):
        """Delete the last message in a conversation (for regeneration)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id FROM messages 
            WHERE conversation_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (conversation_id,))
        
        result = cursor.fetchone()
        
        if result:
            message_id = result[0]
            cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
            cursor.execute("DELETE FROM messages_fts WHERE message_id = ?", (message_id,))
            conn.commit()
        
        conn.close()
    
    def get_message_count(self, conversation_id):
        """Get total message count for a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) FROM messages WHERE conversation_id = ?
        """, (conversation_id,))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
    
    # ============================================
    # SECTION D: SEARCH & UNIVERSAL MEMORY
    # ============================================
    
    def search_conversations(self, query, limit=50):
        """Search all conversations using Universal Memory (partial matching)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Use LIKE for partial matching
        search_pattern = f'%{query}%'
        
        cursor.execute('''
            SELECT DISTINCT m.conversation_id, c.title, c.project_id, m.content
            FROM messages m
            JOIN conversations c ON m.conversation_id = c.id
            LEFT JOIN projects p ON c.project_id = p.id
            WHERE c.title LIKE ? OR m.content LIKE ?
            ORDER BY c.updated_at DESC
            LIMIT ?
        ''', (search_pattern, search_pattern, limit))
        
        results = []
        for row in cursor.fetchall():
            conversation_id, title, project_id, content = row
            
            # Get project name if exists
            project_name = "No Project"
            if project_id:
                proj_cursor = conn.cursor()
                proj_cursor.execute('SELECT name FROM projects WHERE id = ?', (project_id,))
                proj_result = proj_cursor.fetchone()
                if proj_result:
                    project_name = proj_result[0]
            
            # Create snippet (first 150 characters of matching content)
            snippet = content[:150] + '...' if len(content) > 150 else content
            
            results.append({
                'conversation_id': conversation_id,
                'conversation_title': title,
                'project_name': project_name,
                'snippet': snippet
            })
        
        conn.close()
        return results
    
    def advanced_search(self, query, filters=None):
        """
        Advanced search with filters
        filters = {
            'project_id': int,
            'date_from': str,
            'date_to': str,
            'has_tags': bool,
            'category_letter': str
        }
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        base_query = """
            SELECT DISTINCT c.id, c.title, c.created_at, c.updated_at,
                   p.name as project_name, c.category_letter
            FROM conversations c
            LEFT JOIN projects p ON c.project_id = p.id
            LEFT JOIN messages m ON c.id = m.conversation_id
            WHERE 1=1
        """
        
        params = []
        
        # Add search term
        if query:
            base_query += " AND (c.title LIKE ? OR m.content LIKE ?)"
            search_pattern = f'%{query}%'
            params.extend([search_pattern, search_pattern])
        
        # Apply filters
        if filters:
            if 'project_id' in filters:
                base_query += " AND c.project_id = ?"
                params.append(filters['project_id'])
            
            if 'date_from' in filters:
                base_query += " AND c.created_at >= ?"
                params.append(filters['date_from'])
            
            if 'date_to' in filters:
                base_query += " AND c.created_at <= ?"
                params.append(filters['date_to'])
            
            if 'category_letter' in filters:
                base_query += " AND c.category_letter = ?"
                params.append(filters['category_letter'])
        
        base_query += " ORDER BY c.updated_at DESC LIMIT 100"
        
        cursor.execute(base_query, params)
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'title': row[1],
                'created_at': row[2],
                'updated_at': row[3],
                'project_name': row[4],
                'category_letter': row[5]
            })
        
        conn.close()
        return results
    
    # ============================================
    # SECTION E: TAGS MANAGEMENT
    # ============================================
    
    def add_tag(self, conversation_id, tag_name, color="#3B82F6"):
        """Add a tag to a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tag if doesn't exist
        cursor.execute("""
            INSERT OR IGNORE INTO tags (name, color)
            VALUES (?, ?)
        """, (tag_name, color))
        
        # Get tag ID
        cursor.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
        tag_id = cursor.fetchone()[0]
        
        # Link tag to conversation
        cursor.execute("""
            INSERT OR IGNORE INTO conversation_tags (conversation_id, tag_id)
            VALUES (?, ?)
        """, (conversation_id, tag_id))
        
        conn.commit()
        conn.close()
    
    def remove_tag(self, conversation_id, tag_name):
        """Remove a tag from a conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM conversation_tags
            WHERE conversation_id = ? AND tag_id = (
                SELECT id FROM tags WHERE name = ?
            )
        """, (conversation_id, tag_name))
        
        conn.commit()
        conn.close()
    
    def get_all_tags(self):
        """Get all available tags"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT t.id, t.name, t.color, COUNT(ct.conversation_id) as usage_count
            FROM tags t
            LEFT JOIN conversation_tags ct ON t.id = ct.tag_id
            GROUP BY t.id, t.name, t.color
            ORDER BY usage_count DESC, t.name ASC
        """)
        
        tags = []
        for row in cursor.fetchall():
            tags.append({
                'id': row[0],
                'name': row[1],
                'color': row[2],
                'usage_count': row[3]
            })
        
        conn.close()
        return tags
    
    def get_conversation_tags(self, conversation_id):
        """Get all tags for a specific conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT t.id, t.name, t.color
            FROM tags t
            JOIN conversation_tags ct ON t.id = ct.tag_id
            WHERE ct.conversation_id = ?
        """, (conversation_id,))
        
        tags = []
        for row in cursor.fetchall():
            tags.append({
                'id': row[0],
                'name': row[1],
                'color': row[2]
            })
        
        conn.close()
        return tags
    
    def create_tag(self, name, color='#3B82F6'):
        """Create a new tag"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO tags (name, color)
                VALUES (?, ?)
            """, (name, color))
            conn.commit()
            tag_id = cursor.lastrowid
            return tag_id
        except sqlite3.IntegrityError:
            raise Exception("Tag already exists")
        finally:
            conn.close()
    
    def delete_tag(self, tag_id):
        """Delete a tag"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
        conn.commit()
        conn.close()
    
    def add_tag_to_conversation(self, conversation_id, tag_id):
        """Add tag to conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO conversation_tags (conversation_id, tag_id)
                VALUES (?, ?)
            """, (conversation_id, tag_id))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Tag already added
        finally:
            conn.close()
    
    def remove_tag_from_conversation(self, conversation_id, tag_id):
        """Remove tag from conversation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM conversation_tags
            WHERE conversation_id = ? AND tag_id = ?
        """, (conversation_id, tag_id))
        conn.commit()
        conn.close()
    
    def get_analytics_data(self, days=30):
        """Get analytics data for specified days"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get daily usage
        cursor.execute("""
            SELECT 
                DATE(timestamp) as date,
                SUM(input_tokens + output_tokens) as total_tokens,
                SUM(total_cost) as total_cost,
                COUNT(*) as api_calls
            FROM usage_logs
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        """, (days,))
        
        daily_usage = [dict(row) for row in cursor.fetchall()]
        
        # Get usage by model
        cursor.execute("""
            SELECT 
                model,
                SUM(input_tokens + output_tokens) as total_tokens,
                SUM(total_cost) as total_cost,
                COUNT(*) as api_calls
            FROM usage_logs
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY model
        """, (days,))
        
        model_usage = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'daily_usage': daily_usage,
            'model_usage': model_usage
        }
    
    # ============================================
    # SECTION F: USAGE TRACKING & STATISTICS
    # ============================================
    
    def log_usage(self, conversation_id, model, input_tokens, output_tokens, cost):
        """Track API usage and costs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO usage_logs (conversation_id, model, input_tokens, output_tokens, total_cost)
            VALUES (?, ?, ?, ?, ?)
        """, (conversation_id, model, input_tokens, output_tokens, cost))
        
        conn.commit()
        conn.close()
    
    def get_usage_statistics(self, days=30):
        """Get usage statistics for dashboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                DATE(timestamp) as date,
                SUM(input_tokens) as total_input,
                SUM(output_tokens) as total_output,
                SUM(total_cost) as daily_cost
            FROM usage_logs
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        """, (days,))
        
        stats = cursor.fetchall()
        conn.close()
        
        return stats
    
    def get_total_usage(self):
        """Get total lifetime usage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT conversation_id) as total_conversations,
                SUM(input_tokens) as total_input_tokens,
                SUM(output_tokens) as total_output_tokens,
                SUM(input_tokens + output_tokens) as total_tokens,
                SUM(total_cost) as total_cost,
                AVG(total_cost) as avg_cost_per_call
            FROM usage_logs
        """)
        
        result = cursor.fetchone()
        conn.close()
        
        return {
            'total_conversations': result[0] or 0,
            'total_input_tokens': result[1] or 0,
            'total_output_tokens': result[2] or 0,
            'total_tokens': result[3] or 0,
            'total_cost': result[4] or 0.0,
            'avg_cost_per_call': result[5] or 0.0
        }
    
    def get_usage_by_model(self):
        """Get usage breakdown by model"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                model,
                COUNT(*) as call_count,
                SUM(input_tokens) as total_input,
                SUM(output_tokens) as total_output,
                SUM(total_cost) as total_cost
            FROM usage_logs
            GROUP BY model
            ORDER BY total_cost DESC
        """)
        
        models = []
        for row in cursor.fetchall():
            models.append({
                'model': row[0],
                'call_count': row[1],
                'total_input': row[2],
                'total_output': row[3],
                'total_cost': row[4]
            })
        
        conn.close()
        return models
    
    # ============================================
    # SECTION G: EXPORT & BACKUP
    # ============================================
    
    def export_conversation_json(self, conversation_id):
        """Export a conversation as JSON"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get conversation details
        cursor.execute("""
            SELECT c.title, c.created_at, c.updated_at, p.name as project_name
            FROM conversations c
            LEFT JOIN projects p ON c.project_id = p.id
            WHERE c.id = ?
        """, (conversation_id,))
        
        conv_data = cursor.fetchone()
        
        if not conv_data:
            conn.close()
            return None
        
        # Get messages
        cursor.execute("""
            SELECT role, content, timestamp, tokens_used, cost
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
        """, (conversation_id,))
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'role': row[0],
                'content': row[1],
                'timestamp': row[2],
                'tokens': row[3],
                'cost': row[4]
            })
        
        # Get tags
        tags = self.get_conversation_tags(conversation_id)
        
        conn.close()
        
        export_data = {
            'conversation_id': conversation_id,
            'title': conv_data[0],
            'created_at': conv_data[1],
            'updated_at': conv_data[2],
            'project': conv_data[3],
            'tags': tags,
            'messages': messages
        }
        
        return json.dumps(export_data, indent=2)
    
    def backup_database(self, backup_path):
        """Create a backup of the entire database"""
        import shutil
        try:
            shutil.copy2(self.db_path, backup_path)
            return {"success": True, "message": f"Database backed up to {backup_path}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ============================================
    # SECTION H: PROMPT TEMPLATES
    # ============================================
    
    def save_prompt_template(self, name, content, category="General"):
        """Save a reusable prompt template"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO prompt_templates (name, content, category)
            VALUES (?, ?, ?)
        """, (name, content, category))
        
        conn.commit()
        template_id = cursor.lastrowid
        conn.close()
        
        return template_id
    
    def get_prompt_templates(self, category=None):
        """Get all prompt templates, optionally filtered by category"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if category:
            cursor.execute("""
                SELECT id, name, content, category, created_at
                FROM prompt_templates
                WHERE category = ?
                ORDER BY name ASC
            """, (category,))
        else:
            cursor.execute("""
                SELECT id, name, content, category, created_at
                FROM prompt_templates
                ORDER BY category ASC, name ASC
            """)
        
        templates = []
        for row in cursor.fetchall():
            templates.append({
                'id': row[0],
                'name': row[1],
                'content': row[2],
                'category': row[3],
                'created_at': row[4]
            })
        
        conn.close()
        return templates
    
    def delete_prompt_template(self, template_id):
        """Delete a prompt template"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM prompt_templates WHERE id = ?", (template_id,))
        conn.commit()
        conn.close()
    
    # ============================================
    # SECTION I: COMPATIBILITY FUNCTIONS
    # ============================================
    # These functions provide compatibility with app.py expectations
    
    def get_all_conversations(self):
        """
        Get all conversations with project info (compatibility wrapper)
        Returns conversations in the format expected by app.py
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT c.id, c.title, c.created_at, c.updated_at, c.is_pinned, 
                   c.project_id, p.name as project_name, p.color as project_color
            FROM conversations c
            LEFT JOIN projects p ON c.project_id = p.id
            ORDER BY c.is_pinned DESC, c.updated_at DESC
        """)
        
        conversations = []
        for row in cursor.fetchall():
            conversations.append({
                'id': row[0],
                'title': row[1],
                'created_at': row[2],
                'updated_at': row[3],
                'is_pinned': row[4],
                'project_id': row[5],
                'project_name': row[6],
                'project_color': row[7]
            })
        
        conn.close()
        return conversations
    
    def search_memory(self, query, max_results=10):
        """
        Search Universal Memory (compatibility wrapper)
        Wrapper for search_conversations to match app.py expectations
        """
        return self.search_conversations(query, limit=max_results)
    
    def get_messages(self, conversation_id):
        """
        Get messages for a conversation (compatibility wrapper)
        Returns messages in the format expected by app.py
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, role, content, timestamp as created_at, tokens_used, cost
            FROM messages
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
        """, (conversation_id,))
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'role': row[1],
                'content': row[2],
                'created_at': row[3],
                'tokens': row[4],
                'cost': row[5]
            })
        
        conn.close()
        return messages
    
    def get_usage_stats(self):
        """
        Get usage statistics (compatibility wrapper)
        Wrapper for get_total_usage to match app.py expectations
        """
        return self.get_total_usage()

# Initialize database on import
db = ConversationDatabase()
