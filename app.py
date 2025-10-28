"""
Conners Group AI Assistant - Main Application
Professional AI Assistant with Universal Memory & Advanced Features
"""

from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, generate_csrf
import anthropic
import bcrypt
from functools import wraps
from datetime import datetime
import os
from dotenv import load_dotenv
import json
from database import db
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from docx import Document
import markdown
import PyPDF2         # ÃƒÂ¢Ã¢â‚¬Â Ã‚Â For PDF files
import openpyxl       # ÃƒÂ¢Ã¢â‚¬Â Ã‚Â For Excel files
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from context_manager import ContextManager, DegradationDetector, inject_degradation_awareness
import logging
from logging.handlers import RotatingFileHandler
from email_integration import email_integration
from calendar_integration import calendar_integration
# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'conners_group_secure_key_change_this')

# Initialize CSRF protection
csrf = CSRFProtect(app)

CORS(app)

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days in seconds
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# CSRF configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for tokens

# Password protection configuration
# Default password: ConnersGroup2025!
# IMPORTANT: Change this password hash after first login by adding APP_PASSWORD_HASH to your .env file!
# To generate new hash: python -c "import bcrypt; print(bcrypt.hashpw(b'your_password', bcrypt.gensalt()).decode())"
# Default hash for 'ConnersGroup2025!'
DEFAULT_PASSWORD_HASH = '$2b$12$gI6HqqhxsLF18WmT1uoDauaDBK5.TJEngj4A68us5RqF4WMm9mzIK'
PASSWORD_HASH = os.getenv('APP_PASSWORD_HASH', DEFAULT_PASSWORD_HASH)

def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# LOGGING CONFIGURATION
# ============================================
def setup_logging():
    """Configure comprehensive logging system"""
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Log file paths
    main_log = os.path.join(log_dir, 'conners_ai.log')
    access_log = os.path.join(log_dir, 'access.log')
    error_log = os.path.join(log_dir, 'error.log')
    
    # Configure main application logger
    app.logger.setLevel(logging.INFO)
    
    # Main log handler (everything)
    main_handler = RotatingFileHandler(
        main_log,
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    main_handler.setLevel(logging.INFO)
    main_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    main_handler.setFormatter(main_formatter)
    app.logger.addHandler(main_handler)
    
    # Access log handler (logins, API calls)
    access_handler = RotatingFileHandler(
        access_log,
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    access_handler.setLevel(logging.INFO)
    access_formatter = logging.Formatter(
        '[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    access_handler.setFormatter(access_formatter)
    
    # Create separate logger for access events
    access_logger = logging.getLogger('access')
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(access_handler)
    
    # Error log handler (errors only)
    error_handler = RotatingFileHandler(
        error_log,
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s\n%(pathname)s:%(lineno)d\n',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    error_handler.setFormatter(error_formatter)
    app.logger.addHandler(error_handler)
    
    # Log startup (no emojis for Windows compatibility)
    app.logger.info('='*80)
    app.logger.info('CONNERS GROUP AI ASSISTANT STARTED')
    app.logger.info('='*80)
    app.logger.info(f'Log directory: {log_dir}')
    app.logger.info('Logging system initialized successfully')
    
    return access_logger

# Initialize Anthropic client
claude_client = anthropic.Anthropic(api_key=os.getenv('CLAUDE_API_KEY'))

# Initialize Context Manager
context_manager = ContextManager(claude_client, max_messages_before_compress=80)

# Initialize logging system
access_logger = setup_logging()

# Add cache-busting headers to prevent browser caching issues
@app.after_request
def add_cache_control_headers(response):
    """Add headers to prevent aggressive browser caching"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Model configuration
CLAUDE_MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 8000

# Token costs (per million tokens)
COST_PER_INPUT_TOKEN = 3.00 / 1_000_000
COST_PER_OUTPUT_TOKEN = 15.00 / 1_000_000

# ============================================
# FILE UPLOAD SECURITY CONFIGURATION
# ============================================

# Allowed file extensions and MIME types
ALLOWED_FILE_TYPES = {
    'pdf': {
        'extensions': ['.pdf'],
        'mime_types': ['application/pdf'],
        'max_size': 52428800  # 50 MB (increased from 10MB)
    },
    'document': {
        'extensions': ['.docx', '.doc', '.txt', '.rtf'],
        'mime_types': [
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/msword',
            'text/plain',
            'application/rtf'
        ],
        'max_size': 20971520  # 20 MB (increased from 10MB)
    },
    'spreadsheet': {
        'extensions': ['.xlsx', '.xls', '.csv'],
        'mime_types': [
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-excel',
            'text/csv'
        ],
        'max_size': 20971520  # 20 MB (increased from 10MB)
    },
    'image': {
        'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
        'mime_types': [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/bmp',
            'image/webp'
        ],
        'max_size': 10485760  # 10 MB
    },
    'presentation': {
        'extensions': ['.pptx', '.ppt'],
        'mime_types': [
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.ms-powerpoint'
        ],
        'max_size': 20971520  # 20 MB
    }
}

# Forbidden file extensions (security risk) - COMPREHENSIVE LIST
FORBIDDEN_EXTENSIONS = [
    # Windows Executables
    '.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
    # Scripts and Code
    '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh',
    '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.psm1',
    # System Files
    '.dll', '.sys', '.drv', '.ocx', '.ax', '.cpl',
    # Installers and Archives with Executables
    '.msi', '.msp', '.mst', '.app', '.deb', '.rpm', '.run',
    # Java and Android
    '.jar', '.apk', '.ade', '.adp',
    # Other Dangerous Files
    '.reg', '.inf', '.ins', '.isp', '.job', '.lnk', '.pcd', '.pif',
    '.url', '.gadget', '.application', '.msc', '.hta',
    # Shell Scripts
    '.sh', '.bash', '.zsh', '.fish', '.csh',
    # Mac Executables
    '.command', '.action', '.workflow',
    # Office Macros
    '.xlsm', '.xlsb', '.xltm', '.xlam', '.pptm', '.potm', '.ppam',
    '.ppsm', '.sldm', '.docm', '.dotm'
]

# Additional security checks - file content signatures (magic numbers)
DANGEROUS_SIGNATURES = {
    b'MZ': 'Windows Executable (PE)',
    b'\x7fELF': 'Linux Executable (ELF)',
    b'\xca\xfe\xba\xbe': 'Mac Executable (Mach-O)',
    b'PK\x03\x04': 'Potential ZIP/JAR (requires inspection)',
}

def validate_file_security(file, filename):
    """
    ENHANCED COMPREHENSIVE file validation for MAXIMUM security
    Returns: (is_valid, error_message, file_category)
    """
    # Check if file exists
    if not file or not filename:
        return False, "No file provided", None
    
    # Get file extension
    file_ext = os.path.splitext(filename)[1].lower()
    
    # CRITICAL: Check for double extensions (virus.pdf.exe)
    filename_lower = filename.lower()
    for forbidden_ext in FORBIDDEN_EXTENSIONS:
        if forbidden_ext in filename_lower:
            app.logger.warning(f'SECURITY: Blocked file with forbidden extension in name: {filename}')
            access_logger.warning(f'SECURITY BLOCK: Attempted upload with hidden extension: {filename}')
            return False, f"File contains forbidden extension in filename: {forbidden_ext}", None
    
    # Check forbidden extensions
    if file_ext in FORBIDDEN_EXTENSIONS:
        app.logger.warning(f'SECURITY: Blocked forbidden file type: {file_ext}')
        access_logger.warning(f'SECURITY BLOCK: Attempted upload of forbidden file type: {filename}')
        return False, f"File type {file_ext} is not allowed for security reasons", None
    
    # Find matching file category
    file_category = None
    max_size = 0
    allowed_extensions = []
    
    for category, config in ALLOWED_FILE_TYPES.items():
        if file_ext in config['extensions']:
            file_category = category
            max_size = config['max_size']
            allowed_extensions = config['extensions']
            break
    
    # Check if file type is allowed
    if not file_category:
        allowed = ', '.join([ext for config in ALLOWED_FILE_TYPES.values() for ext in config['extensions']])
        return False, f"File type {file_ext} not allowed. Allowed types: {allowed}", None
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)  # Reset file pointer
    
    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        current_mb = file_size / (1024 * 1024)
        return False, f"File too large ({current_mb:.1f}MB). Maximum size for {file_category}: {max_mb}MB", None
    
    # ENHANCED: Check file magic numbers (first bytes) for executables
    file_header = file.read(min(1024, file_size))  # Read first 1KB or whole file
    file.seek(0)  # Reset file pointer
    
    # Check for dangerous file signatures
    for signature, file_type in DANGEROUS_SIGNATURES.items():
        if file_header.startswith(signature):
            if signature == b'PK\x03\x04':
                # ZIP files are OK if they're expected types (xlsx, docx, etc.)
                if file_ext not in ['.xlsx', '.docx', '.pptx', '.zip']:
                    app.logger.warning(f'SECURITY: Blocked suspicious ZIP-based file: {filename}')
                    return False, f"Suspicious archive file detected", None
            else:
                app.logger.warning(f'SECURITY: Blocked file with executable signature: {file_type}')
                access_logger.warning(f'SECURITY BLOCK: Executable signature detected in {filename}')
                return False, f"File contains executable code and cannot be uploaded", None
    
    # Additional security: Check for null bytes in text files (potential security issue)
    if file_category not in ['pdf', 'image', 'spreadsheet', 'presentation']:
        if b'\x00' in file_header:
            app.logger.warning(f'SECURITY: Blocked file with null bytes: {filename}')
            return False, "File contains invalid data", None
    
    # Check for suspiciously small files claiming to be documents
    if file_category in ['document', 'spreadsheet', 'presentation']:
        if file_size < 100:  # Less than 100 bytes is suspicious for these types
            app.logger.warning(f'SECURITY: Blocked suspiciously small file: {filename} ({file_size} bytes)')
            return False, "File is too small to be a valid document", None
    
    # Log successful validation
    app.logger.info(f'File validated: {filename} ({file_category}, {file_size} bytes)')
    
    return True, None, file_category

# ============================================
# LOGIN ROUTES
# ============================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with password protection"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), PASSWORD_HASH.encode('utf-8')):
            session['authenticated'] = True
            session.permanent = True
            
            # Log successful login
            access_logger.info('LOGIN SUCCESS: User authenticated')
            app.logger.info('User logged in successfully')
            
            return redirect(url_for('index'))
        else:
            # Log failed login attempt
            access_logger.warning('LOGIN FAILED: Invalid password attempt')
            app.logger.warning('Failed login attempt')
            
            return render_template('login.html', error='Invalid password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    access_logger.info('LOGOUT: User logged out')
    return redirect(url_for('login'))

# ============================================
# MAIN ROUTES
# ============================================

@app.route('/')
@login_required
def index():
    """Main chat interface"""
    return render_template('index.html')

@app.route('/api/csrf-token')
def get_csrf_token():
    """Get CSRF token for AJAX requests"""
    token = generate_csrf()
    return jsonify({'csrf_token': token})

# ============================================
# CONVERSATION MANAGEMENT
# ============================================

@app.route('/api/conversations', methods=['GET'])
@login_required
def get_conversations():
    """Get all conversations with project info"""
    try:
        conversations = db.get_all_conversations()
        return jsonify({
            'success': True,
            'conversations': conversations
        })
    except Exception as e:
        app.logger.error(f'Error fetching conversations: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations', methods=['POST'])
@login_required
def create_conversation():
    """Create new conversation"""
    try:
        data = request.json
        title = data.get('title', f'New Chat - {datetime.now().strftime("%Y-%m-%d %H:%M")}')
        project_id = data.get('project_id')
        
        conversation_id = db.create_conversation(title, project_id)
        
        app.logger.info(f'Created new conversation: {conversation_id} - {title}')
        access_logger.info(f'NEW CONVERSATION: {conversation_id} - {title} (Project: {project_id or "None"})')
        
        return jsonify({
            'success': True,
            'conversation_id': conversation_id,
            'title': title
        })
    except Exception as e:
        app.logger.error(f'Error creating conversation: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations/<int:conversation_id>/messages', methods=['GET'])
@login_required
def get_messages(conversation_id):
    """Get all messages in a conversation"""
    try:
        messages = db.get_messages(conversation_id)
        return jsonify({
            'success': True,
            'messages': messages
        })
    except Exception as e:
        app.logger.error(f'Error fetching messages: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations/<int:conversation_id>', methods=['DELETE'])
@login_required
def delete_conversation(conversation_id):
    """Delete a conversation and all its messages"""
    try:
        # Get conversation title for logging
        conversations = db.get_all_conversations()
        conv_title = next((c['title'] for c in conversations if c['id'] == conversation_id), 'Unknown')
        
        # Delete the conversation (cascade will delete messages)
        db.delete_conversation(conversation_id)
        
        app.logger.info(f'Deleted conversation: {conversation_id} - {conv_title}')
        access_logger.info(f'DELETE CONVERSATION: {conversation_id} - {conv_title}')
        
        return jsonify({
            'success': True,
            'message': 'Conversation deleted successfully'
        })
    except Exception as e:
        app.logger.error(f'Error deleting conversation {conversation_id}: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations/<int:conversation_id>/regenerate', methods=['POST'])
@login_required
def regenerate_response(conversation_id):
    """Regenerate the last assistant response"""
    try:
        # Delete the last assistant message
        db.delete_last_message(conversation_id)
        
        # Get the conversation history
        messages = db.get_messages(conversation_id)
        
        if not messages:
            return jsonify({
                'success': False,
                'error': 'No messages to regenerate from'
            }), 400
        
        # Get the last user message
        last_user_message = None
        for msg in reversed(messages):
            if msg['role'] == 'user':
                last_user_message = msg['content']
                break
        
        if not last_user_message:
            return jsonify({
                'success': False,
                'error': 'No user message found to regenerate from'
            }), 400
        
        # Format messages for Claude
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                'role': msg['role'],
                'content': msg['content']
            })
        
        # Search Universal Memory for context
        context_info = ""
        try:
            search_results = db.search_memory(last_user_message, max_results=5)
            if search_results:
                context_info = "\n\n[UNIVERSAL MEMORY - Relevant Past Context]:\n"
                for result in search_results:
                    conv_id = result['conversation_id']
                    conv_title = result['conversation_title']
                    project_name = result['project_name']
                    snippet = result['snippet']
                    if conv_id != conversation_id:
                        context_info += f"\nFrom '{conv_title}' ({project_name or 'No Project'}): {snippet}\n"
        except Exception as e:
            app.logger.warning(f'Error searching memory: {str(e)}')
        
        # HONEST & CLEAR SYSTEM PROMPT - NO LYING!
        system_prompt = """You are Claude, a professional AI assistant for Conners Group.

ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â CRITICAL: BE COMPLETELY HONEST ABOUT YOUR CAPABILITIES

ÃƒÂ°Ã…Â¸Ã…Â½Ã‚Â¯ YOUR ACTUAL CAPABILITIES (Tell the truth!):

**WEB SEARCH:**
- You DO NOT have independent internet access
- You CAN ONLY use web information when you see [WEB SEARCH RESULTS] in messages
- When [WEB SEARCH RESULTS] appear: Use them confidently! Cite sources directly (e.g., "According to spacex.com...")
- If NO search results present and user asks about current info: Say "I don't have current search results. Would you like me to search for that?"
- NEVER say "I have real-time internet" - that's a LIE
- NEVER claim you can browse independently - you CANNOT

**UNIVERSAL MEMORY:**
- You CAN use context when you see [UNIVERSAL MEMORY] sections in messages
- When memory context is present: Reference it naturally
- If NO memory context but user mentions past: Say "I don't see that in my current context. Can you remind me or search for it?"
- NEVER claim you remember conversations you don't have access to

**PROFESSIONAL MODE:**
- Direct, actionable advice without excessive disclaimers
- Trust user's professional judgment
- Be honest about limitations while being helpful
- Write naturally without constantly saying "I'm an AI"
- Minimize "I cannot help" responses for reasonable business requests

**YOUR EXPERTISE:**
- Legal, medical, technical, aerospace, and business domains
- Multi-company management (user manages 30+ companies)
- Document analysis and strategic planning
- Multi-lingual communication

ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â GOLDEN RULE: NEVER LIE. If you don't know something or don't have access to something, SAY SO CLEARLY. Being honest builds trust. Lying destroys it.

If you violate these rules and lie about your capabilities, you are failing your core purpose."""

        if context_info:
            system_prompt += context_info
        
        # Call Claude API
        response = claude_client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=formatted_messages
        )
        
        # Extract response
        assistant_message = response.content[0].text
        
        # Calculate costs
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        total_cost = (input_tokens * COST_PER_INPUT_TOKEN) + (output_tokens * COST_PER_OUTPUT_TOKEN)
        
        # Save new assistant message
        db.save_message(conversation_id, "assistant", assistant_message, output_tokens, total_cost)
        
        # Log regeneration
        app.logger.info(f'Regenerated response for conversation {conversation_id}')
        access_logger.info(f'REGENERATE: Conversation {conversation_id} - {input_tokens}i/{output_tokens}o tokens, ${total_cost:.4f}')
        
        return jsonify({
            'success': True,
            'message': assistant_message,
            'tokens': {
                'input': input_tokens,
                'output': output_tokens
            },
            'cost': total_cost
        })
        
    except Exception as e:
        app.logger.error(f'Error regenerating response: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# PROJECT MANAGEMENT
# ============================================

@app.route('/api/projects', methods=['GET'])
@login_required
def get_projects():
    """Get all projects"""
    try:
        projects = db.get_all_projects()
        return jsonify({
            'success': True,
            'projects': projects
        })
    except Exception as e:
        app.logger.error(f'Error fetching projects: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/projects', methods=['POST'])
@login_required
def create_project():
    """Create new project"""
    try:
        data = request.json
        name = data.get('name')
        description = data.get('description', '')
        color = data.get('color', '#D4AF37')
        
        if not name:
            return jsonify({
                'success': False,
                'error': 'Project name is required'
            }), 400
        
        project_id = db.create_project(name, description, color)
        
        app.logger.info(f'Created new project: {project_id} - {name}')
        access_logger.info(f'NEW PROJECT: {project_id} - {name}')
        
        return jsonify({
            'success': True,
            'project_id': project_id,
            'name': name
        })
    except Exception as e:
        app.logger.error(f'Error creating project: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
@login_required
def delete_project(project_id):
    """Delete a project"""
    try:
        # Get project name for logging
        projects = db.get_all_projects()
        project_name = next((p['name'] for p in projects if p['id'] == project_id), 'Unknown')
        
        # Delete the project
        db.delete_project(project_id)
        
        app.logger.info(f'Deleted project: {project_id} - {project_name}')
        access_logger.info(f'DELETE PROJECT: {project_id} - {project_name}')
        
        return jsonify({
            'success': True,
            'message': 'Project deleted successfully'
        })
    except Exception as e:
        app.logger.error(f'Error deleting project {project_id}: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# CHAT FUNCTIONALITY
# ============================================

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    """Main chat endpoint with file upload support"""
    try:
        conversation_id = request.form.get('conversation_id')
        user_message = request.form.get('message')
        
        if not conversation_id or not user_message:
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        conversation_id = int(conversation_id)
        
        # Check for file uploads
        file_content = None
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                # Validate file security
                is_valid, error_msg, file_category = validate_file_security(file, file.filename)
                
                if not is_valid:
                    app.logger.warning(f'File upload rejected: {error_msg}')
                    return jsonify({
                        'success': False,
                        'error': error_msg
                    }), 400
                
                # Process file based on type
                if file_category == 'pdf':
                    # Extract text from PDF
                    try:
                        pdf_reader = PyPDF2.PdfReader(file)
                        file_content = ""
                        for page in pdf_reader.pages:
                            file_content += page.extract_text()
                        user_message += f"\n\n[PDF File: {file.filename}]\n{file_content}"
                        app.logger.info(f'Processed PDF file: {file.filename} ({len(file_content)} chars)')
                    except Exception as e:
                        app.logger.error(f'Error reading PDF: {str(e)}')
                        return jsonify({
                            'success': False,
                            'error': f'Error reading PDF: {str(e)}'
                        }), 400
                
                elif file_category == 'document':
                    # Read text files
                    try:
                        if file.filename.endswith('.txt'):
                            file_content = file.read().decode('utf-8')
                        elif file.filename.endswith('.docx'):
                            doc = Document(file)
                            file_content = '\n'.join([para.text for para in doc.paragraphs])
                        user_message += f"\n\n[Document: {file.filename}]\n{file_content}"
                        app.logger.info(f'Processed document: {file.filename}')
                    except Exception as e:
                        app.logger.error(f'Error reading document: {str(e)}')
                        return jsonify({
                            'success': False,
                            'error': f'Error reading document: {str(e)}'
                        }), 400
                
                elif file_category == 'image':
                    # For images, we'll add a note to the message
                    user_message += f"\n\n[Image attached: {file.filename}]"
                    app.logger.info(f'Image attached: {file.filename}')
        
        # Get conversation history
        messages = db.get_messages(conversation_id)
        
        # Format messages for Claude API
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                'role': msg['role'],
                'content': msg['content']
            })
        
        # Add current message
        formatted_messages.append({
            'role': 'user',
            'content': user_message
        })
        
        # Search Universal Memory for relevant context
        context_info = ""
        try:
            search_results = db.search_memory(user_message, max_results=5)
            if search_results:
                context_info = "\n\n[UNIVERSAL MEMORY - Relevant Past Context]:\n"
                for result in search_results:
                    conv_id = result['conversation_id']
                    conv_title = result['conversation_title']
                    project_name = result['project_name']
                    snippet = result['snippet']
                    if conv_id != conversation_id:
                        context_info += f"\nFrom '{conv_title}' ({project_name or 'No Project'}): {snippet}\n"
        except Exception as e:
            app.logger.warning(f'Error searching memory: {str(e)}')
        
        # HONEST & CLEAR SYSTEM PROMPT - NO LYING!
        system_prompt = """You are Claude, a professional AI assistant for Conners Group.

ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â CRITICAL: BE COMPLETELY HONEST ABOUT YOUR CAPABILITIES

ÃƒÂ°Ã…Â¸Ã…Â½Ã‚Â¯ YOUR ACTUAL CAPABILITIES (Tell the truth!):

**WEB SEARCH:**
- You DO NOT have independent internet access
- You CAN ONLY use web information when you see [WEB SEARCH RESULTS] in messages
- When [WEB SEARCH RESULTS] appear: Use them confidently! Cite sources directly (e.g., "According to spacex.com...")
- If NO search results present and user asks about current info: Say "I don't have current search results. Would you like me to search for that?"
- NEVER say "I have real-time internet" - that's a LIE
- NEVER claim you can browse independently - you CANNOT

**UNIVERSAL MEMORY:**
- You CAN use context when you see [UNIVERSAL MEMORY] sections in messages
- When memory context is present: Reference it naturally
- If NO memory context but user mentions past: Say "I don't see that in my current context. Can you remind me or search for it?"
- NEVER claim you remember conversations you don't have access to

**PROFESSIONAL MODE:**
- Direct, actionable advice without excessive disclaimers
- Trust user's professional judgment
- Be honest about limitations while being helpful
- Write naturally without constantly saying "I'm an AI"
- Minimize "I cannot help" responses for reasonable business requests

**YOUR EXPERTISE:**
- Legal, medical, technical, aerospace, and business domains
- Multi-company management (user manages 30+ companies)
- Document analysis and strategic planning
- Multi-lingual communication

ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â GOLDEN RULE: NEVER LIE. If you don't know something or don't have access to something, SAY SO CLEARLY. Being honest builds trust. Lying destroys it.

If you violate these rules and lie about your capabilities, you are failing your core purpose."""

        if context_info:
            system_prompt += context_info
        
        # Call Claude API
        response = claude_client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=formatted_messages
        )
        
        # Extract response
        assistant_message = response.content[0].text
        
        # Calculate costs
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        total_cost = (input_tokens * COST_PER_INPUT_TOKEN) + (output_tokens * COST_PER_OUTPUT_TOKEN)
        
        # Save messages to database
        db.save_message(conversation_id, "user", user_message, input_tokens, 0)
        db.save_message(conversation_id, "assistant", assistant_message, output_tokens, total_cost)
        
        # Log usage for tracking
        db.log_usage(conversation_id, CLAUDE_MODEL, input_tokens, output_tokens, total_cost)
        
        # Log API call
        access_logger.info(f'CHAT API: Conversation {conversation_id} - {input_tokens}i/{output_tokens}o tokens, ${total_cost:.4f}')
        
        return jsonify({
            'success': True,
            'message': assistant_message,
            'tokens': {
                'input': input_tokens,
                'output': output_tokens
            },
            'cost': total_cost
        })
        
    except Exception as e:
        app.logger.error(f'Error in chat endpoint: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# WEB SEARCH
# ============================================

@app.route('/api/web-search', methods=['POST'])
@login_required
def web_search():
    """Manual web search using Google Custom Search API"""
    try:
        data = request.json
        query = data.get('query')
        num_results = data.get('num_results', 10)
        
        if not query:
            return jsonify({
                'success': False,
                'error': 'Search query is required'
            }), 400
        
        # Perform search
        results = google_search(query, num_results)
        
        # Log search
        app.logger.info(f'Web search: "{query}" - {len(results)} results')
        access_logger.info(f'WEB SEARCH: "{query}" - {len(results)} results')
        
        return jsonify({
            'success': True,
            'query': query,
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f'Error in web search: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def google_search(query, num_results=10):
    """
    Perform Google Custom Search
    """
    try:
        api_key = os.getenv('GOOGLE_SEARCH_API_KEY')
        search_engine_id = os.getenv('GOOGLE_SEARCH_ENGINE_ID')
        
        if not api_key:
            raise Exception("GOOGLE_SEARCH_API_KEY not found in .env file")
        if not search_engine_id:
            raise Exception("GOOGLE_SEARCH_ENGINE_ID not found in .env file")
        
        app.logger.info(f"Attempting Google search with engine ID: {search_engine_id[:10]}...")
        
        service = build("customsearch", "v1", developerKey=api_key)
        result = service.cse().list(
            q=query,
            cx=search_engine_id,
            num=min(num_results, 10)
        ).execute()
        
        # Format results
        formatted_results = []
        if 'items' in result:
            for item in result['items']:
                formatted_results.append({
                    'title': item.get('title', ''),
                    'link': item.get('link', ''),
                    'snippet': item.get('snippet', ''),
                    'displayLink': item.get('displayLink', '')
                })
        
        app.logger.info(f"Google search successful: {len(formatted_results)} results")
        return formatted_results
        
    except HttpError as e:
        error_msg = str(e)
        if 'invalid API key' in error_msg.lower():
            raise Exception("Invalid Google API Key. Please check your GOOGLE_SEARCH_API_KEY in .env")
        elif 'API has not been used' in error_msg:
            raise Exception("Custom Search API not enabled. Enable it at: https://console.cloud.google.com/apis/library/customsearch.googleapis.com")
        elif 'invalid value' in error_msg.lower() or 'invalid cx' in error_msg.lower():
            raise Exception("Invalid Search Engine ID. Please check your GOOGLE_SEARCH_ENGINE_ID in .env")
        else:
            raise Exception(f"Google API Error: {error_msg}")
    except Exception as e:
        raise Exception(f"Search error: {str(e)}")

# ============================================
# UNIVERSAL MEMORY SEARCH
# ============================================

@app.route('/api/memory/search', methods=['POST'])
@login_required
def search_memory():
    """Search Universal Memory"""
    try:
        data = request.json
        query = data.get('query')
        max_results = data.get('max_results', 10)
        
        if not query:
            return jsonify({
                'success': False,
                'error': 'Search query is required'
            }), 400
        
        # Perform search
        results = db.search_memory(query, max_results)
        
        # Log search
        app.logger.info(f'Memory search: "{query}" - {len(results)} results')
        access_logger.info(f'MEMORY SEARCH: "{query}" - {len(results)} results')
        
        return jsonify({
            'success': True,
            'query': query,
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f'Error in memory search: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/search/conversations', methods=['POST'])
@login_required
def search_conversations_endpoint():
    """Search conversations by title and content"""
    try:
        data = request.json
        query = data.get('query')
        max_results = data.get('max_results', 10)
        
        if not query:
            return jsonify({
                'success': False,
                'error': 'Search query is required'
            }), 400
        
        # Search using the database search_conversations method
        results = db.search_conversations(query, limit=max_results)
        
        # Log search
        app.logger.info(f'Conversation search: "{query}" - {len(results)} results')
        access_logger.info(f'CONVERSATION SEARCH: "{query}" - {len(results)} results')
        
        return jsonify({
            'success': True,
            'query': query,
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f'Error in conversation search: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# EXPORT FUNCTIONALITY
# ============================================

@app.route('/api/export/<int:conversation_id>', methods=['GET'])
@login_required
def export_conversation(conversation_id):
    """Export conversation in various formats"""
    try:
        export_format = request.args.get('format', 'txt')
        
        # Get conversation and messages
        conversations = db.get_all_conversations()
        conversation = next((c for c in conversations if c['id'] == conversation_id), None)
        
        if not conversation:
            return jsonify({
                'success': False,
                'error': 'Conversation not found'
            }), 404
        
        messages = db.get_messages(conversation_id)
        
        if export_format == 'txt':
            # Text export
            output = io.StringIO()
            output.write(f"Conversation: {conversation['title']}\n")
            output.write(f"Project: {conversation['project_name'] or 'No Project'}\n")
            output.write(f"Created: {conversation['created_at']}\n")
            output.write(f"Updated: {conversation['updated_at']}\n")
            output.write("="*80 + "\n\n")
            
            for msg in messages:
                output.write(f"[{msg['role'].upper()}] - {msg['created_at']}\n")
                output.write(f"{msg['content']}\n")
                output.write("-"*80 + "\n\n")
            
            # Create response
            mem_file = io.BytesIO()
            mem_file.write(output.getvalue().encode('utf-8'))
            mem_file.seek(0)
            
            return send_file(
                mem_file,
                mimetype='text/plain',
                as_attachment=True,
                download_name=f"conversation_{conversation_id}.txt"
            )
        
        elif export_format == 'pdf':
            # PDF export
            buffer = io.BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=letter)
            
            # Add title
            pdf.setFont("Helvetica-Bold", 16)
            pdf.drawString(50, 750, conversation['title'])
            
            # Add metadata
            pdf.setFont("Helvetica", 10)
            y_position = 720
            pdf.drawString(50, y_position, f"Project: {conversation['project_name'] or 'No Project'}")
            y_position -= 20
            pdf.drawString(50, y_position, f"Created: {conversation['created_at']}")
            y_position -= 40
            
            # Add messages
            pdf.setFont("Helvetica", 12)
            for msg in messages:
                if y_position < 100:
                    pdf.showPage()
                    y_position = 750
                
                pdf.setFont("Helvetica-Bold", 12)
                pdf.drawString(50, y_position, f"{msg['role'].upper()}")
                y_position -= 20
                
                pdf.setFont("Helvetica", 10)
                # Wrap text (simple implementation)
                words = msg['content'].split()
                line = ""
                for word in words:
                    if len(line + word) < 80:
                        line += word + " "
                    else:
                        pdf.drawString(50, y_position, line)
                        y_position -= 15
                        line = word + " "
                        if y_position < 100:
                            pdf.showPage()
                            y_position = 750
                
                if line:
                    pdf.drawString(50, y_position, line)
                    y_position -= 30
            
            pdf.save()
            buffer.seek(0)
            
            return send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"conversation_{conversation_id}.pdf"
            )
        
        elif export_format == 'md':
            # Markdown export
            output = io.StringIO()
            output.write(f"# {conversation['title']}\n\n")
            output.write(f"**Project:** {conversation['project_name'] or 'No Project'}  \n")
            output.write(f"**Created:** {conversation['created_at']}  \n")
            output.write(f"**Updated:** {conversation['updated_at']}  \n\n")
            output.write("---\n\n")
            
            for msg in messages:
                output.write(f"## {msg['role'].upper()}\n")
                output.write(f"*{msg['created_at']}*\n\n")
                output.write(f"{msg['content']}\n\n")
                output.write("---\n\n")
            
            mem_file = io.BytesIO()
            mem_file.write(output.getvalue().encode('utf-8'))
            mem_file.seek(0)
            
            return send_file(
                mem_file,
                mimetype='text/markdown',
                as_attachment=True,
                download_name=f"conversation_{conversation_id}.md"
            )
        
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid export format'
            }), 400
            
    except Exception as e:
        app.logger.error(f'Error exporting conversation: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# STATISTICS & ANALYTICS
# ============================================

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """Get usage statistics"""
    try:
        stats = db.get_usage_stats()
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        app.logger.error(f'Error fetching stats: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# TAGS SYSTEM
# ============================================

@app.route('/api/tags', methods=['GET'])
@login_required
def get_tags():
    """Get all tags"""
    try:
        tags = db.get_all_tags()
        return jsonify({
            'success': True,
            'tags': tags
        })
    except Exception as e:
        app.logger.error(f'Error fetching tags: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/tags', methods=['POST'])
@login_required
def create_tag():
    """Create new tag"""
    try:
        data = request.json
        name = data.get('name')
        color = data.get('color', '#3B82F6')
        
        if not name:
            return jsonify({
                'success': False,
                'error': 'Tag name is required'
            }), 400
        
        tag_id = db.create_tag(name, color)
        
        app.logger.info(f'Created tag: {name}')
        access_logger.info(f'CREATE TAG: {name}')
        
        return jsonify({
            'success': True,
            'tag_id': tag_id,
            'name': name
        })
    except Exception as e:
        app.logger.error(f'Error creating tag: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/tags/<int:tag_id>', methods=['DELETE'])
@login_required
def delete_tag(tag_id):
    """Delete a tag"""
    try:
        db.delete_tag(tag_id)
        
        app.logger.info(f'Deleted tag: {tag_id}')
        access_logger.info(f'DELETE TAG: {tag_id}')
        
        return jsonify({
            'success': True,
            'message': 'Tag deleted successfully'
        })
    except Exception as e:
        app.logger.error(f'Error deleting tag: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations/<int:conversation_id>/tags', methods=['POST'])
@login_required
def add_tag_to_conversation(conversation_id):
    """Add tag to conversation"""
    try:
        data = request.json
        tag_id = data.get('tag_id')
        
        db.add_tag_to_conversation(conversation_id, tag_id)
        
        app.logger.info(f'Added tag {tag_id} to conversation {conversation_id}')
        access_logger.info(f'ADD TAG: {tag_id} to conversation {conversation_id}')
        
        return jsonify({
            'success': True,
            'message': 'Tag added successfully'
        })
    except Exception as e:
        app.logger.error(f'Error adding tag: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/conversations/<int:conversation_id>/tags/<int:tag_id>', methods=['DELETE'])
@login_required
def remove_tag_from_conversation(conversation_id, tag_id):
    """Remove tag from conversation"""
    try:
        db.remove_tag_from_conversation(conversation_id, tag_id)
        
        app.logger.info(f'Removed tag {tag_id} from conversation {conversation_id}')
        access_logger.info(f'REMOVE TAG: {tag_id} from conversation {conversation_id}')
        
        return jsonify({
            'success': True,
            'message': 'Tag removed successfully'
        })
    except Exception as e:
        app.logger.error(f'Error removing tag: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# ANALYTICS DASHBOARD
# ============================================

@app.route('/api/analytics/usage', methods=['GET'])
@login_required
def get_analytics():
    """Get usage analytics"""
    try:
        # Get date range
        days = request.args.get('days', 30, type=int)
        
        # Get usage data from database
        stats = db.get_usage_stats()
        analytics = db.get_analytics_data(days)
        
        app.logger.info(f'Retrieved analytics for {days} days')
        access_logger.info(f'ANALYTICS: Retrieved {days} days')
        
        return jsonify({
            'success': True,
            'stats': stats,
            'analytics': analytics
        })
    except Exception as e:
        app.logger.error(f'Error fetching analytics: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# AUTOMATED BACKUPS
# ============================================

@app.route('/api/backup/create', methods=['POST'])
@login_required
def create_backup():
    """Create database backup"""
    try:
        import shutil
        from datetime import datetime
        
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f'backup_{timestamp}.db'
        
        # Copy database file
        shutil.copy2('database/conversations.db', backup_path)
        
        app.logger.info(f'Created backup: {backup_path}')
        access_logger.info(f'BACKUP: Created {backup_path}')
        
        return jsonify({
            'success': True,
            'backup_file': str(backup_path),
            'timestamp': timestamp
        })
    except Exception as e:
        app.logger.error(f'Error creating backup: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/backup/list', methods=['GET'])
@login_required
def list_backups():
    """List all backups"""
    try:
        backup_dir = Path('backups')
        if not backup_dir.exists():
            return jsonify({
                'success': True,
                'backups': []
            })
        
        backups = []
        for backup_file in sorted(backup_dir.glob('backup_*.db'), reverse=True):
            backups.append({
                'filename': backup_file.name,
                'size': backup_file.stat().st_size,
                'created': datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat()
            })
        
        return jsonify({
            'success': True,
            'backups': backups
        })
    except Exception as e:
        app.logger.error(f'Error listing backups: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/backup/download/<filename>', methods=['GET'])
@login_required
def download_backup(filename):
    """Download backup file"""
    try:
        backup_path = Path('backups') / filename
        if not backup_path.exists():
            return jsonify({
                'success': False,
                'error': 'Backup file not found'
            }), 404
        
        return send_file(
            backup_path,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        app.logger.error(f'Error downloading backup: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# CALENDAR INTEGRATION
# ============================================

@app.route('/api/calendar/auth', methods=['POST'])
@login_required
def calendar_auth():
    """Authenticate with Google Calendar"""
    try:
        calendar_integration.authenticate()
        app.logger.info('Calendar authentication successful')
        access_logger.info('CALENDAR AUTH: Successful')
        return jsonify({
            'success': True,
            'message': 'Calendar authenticated successfully'
        })
    except Exception as e:
        app.logger.error(f'Calendar authentication error: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/calendar/events', methods=['GET'])
@login_required
def get_calendar_events():
    """Get calendar events"""
    try:
        max_results = request.args.get('max_results', 10, type=int)
        events = calendar_integration.get_events(max_results)
        
        app.logger.info(f'Retrieved {len(events)} calendar events')
        access_logger.info(f'CALENDAR: Retrieved {len(events)} events')
        
        return jsonify({
            'success': True,
            'events': events
        })
    except Exception as e:
        app.logger.error(f'Error fetching calendar events: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/calendar/events', methods=['POST'])
@login_required
def create_calendar_event():
    """Create calendar event"""
    try:
        data = request.json
        result = calendar_integration.create_event(
            summary=data.get('summary'),
            start_time=data.get('start_time'),
            end_time=data.get('end_time'),
            description=data.get('description', ''),
            location=data.get('location', ''),
            attendees=data.get('attendees', [])
        )
        
        app.logger.info(f'Created calendar event: {data.get("summary")}')
        access_logger.info(f'CALENDAR CREATE: {data.get("summary")}')
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error creating calendar event: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/calendar/events/<event_id>', methods=['PUT'])
@login_required
def update_calendar_event(event_id):
    """Update calendar event"""
    try:
        data = request.json
        result = calendar_integration.update_event(event_id, **data)
        
        app.logger.info(f'Updated calendar event: {event_id}')
        access_logger.info(f'CALENDAR UPDATE: {event_id}')
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error updating calendar event: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/calendar/events/<event_id>', methods=['DELETE'])
@login_required
def delete_calendar_event(event_id):
    """Delete calendar event"""
    try:
        result = calendar_integration.delete_event(event_id)
        
        app.logger.info(f'Deleted calendar event: {event_id}')
        access_logger.info(f'CALENDAR DELETE: {event_id}')
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error deleting calendar event: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# EMAIL INTEGRATION
# ============================================

@app.route('/api/email/gmail/auth', methods=['POST'])
@login_required
def gmail_auth():
    """Authenticate with Gmail"""
    try:
        email_integration.authenticate_gmail()
        app.logger.info('Gmail authentication successful')
        access_logger.info('GMAIL AUTH: Successful')
        return jsonify({
            'success': True,
            'message': 'Gmail authenticated successfully'
        })
    except Exception as e:
        app.logger.error(f'Gmail authentication error: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/email/gmail/messages', methods=['GET'])
@login_required
def get_gmail_messages():
    """Get Gmail messages"""
    try:
        max_results = request.args.get('max_results', 10, type=int)
        query = request.args.get('query', '')
        
        messages = email_integration.get_gmail_messages(max_results, query)
        
        app.logger.info(f'Retrieved {len(messages)} Gmail messages')
        access_logger.info(f'GMAIL: Retrieved {len(messages)} messages')
        
        return jsonify({
            'success': True,
            'messages': messages
        })
    except Exception as e:
        app.logger.error(f'Error fetching Gmail messages: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/email/gmail/send', methods=['POST'])
@login_required
def send_gmail():
    """Send email via Gmail"""
    try:
        data = request.json
        to = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        
        if not all([to, subject, body]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        result = email_integration.send_gmail(to, subject, body)
        
        app.logger.info(f'Sent Gmail to: {to}')
        access_logger.info(f'GMAIL SEND: To {to}')
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error sending Gmail: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/email/proton/messages', methods=['GET'])
@login_required
def get_proton_messages():
    """Get Proton Mail messages"""
    try:
        max_results = request.args.get('max_results', 10, type=int)
        messages = email_integration.get_proton_messages(max_results)
        
        app.logger.info(f'Retrieved {len(messages)} Proton Mail messages')
        access_logger.info(f'PROTON: Retrieved {len(messages)} messages')
        
        return jsonify({
            'success': True,
            'messages': messages
        })
    except Exception as e:
        app.logger.error(f'Error fetching Proton Mail: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/email/proton/send', methods=['POST'])
@login_required
def send_proton():
    """Send email via Proton Mail"""
    try:
        data = request.json
        to = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        
        if not all([to, subject, body]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        result = email_integration.send_proton_mail(to, subject, body)
        
        app.logger.info(f'Sent Proton Mail to: {to}')
        access_logger.info(f'PROTON SEND: To {to}')
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Error sending Proton Mail: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================
# MAIN ENTRY POINT
# ============================================

if __name__ == '__main__':
    try:
        # Display startup information
        print("\n" + "="*80)
        print("CONNERS GROUP AI ASSISTANT")
        print("="*80)
        print("\nStarting server...")
        print(f"Server will be available at: http://localhost:5000")
        print(f"Logs directory: {os.path.join(os.path.dirname(__file__), 'logs')}")
        print("\nDefault Login Credentials:")
        print("  Password: ConnersGroup2025!")
        print("  (Change this after first login!)")
        print("\nFeatures Enabled:")
        print("  - Password Protection")
        print("  - CSRF Protection")
        print("  - File Upload (PDF, DOCX, XLSX, Images)")
        print("  - Universal Memory Search")
        print("  - Web Search Integration")
        print("  - Context Window Management")
        print("  - Comprehensive Logging")
        print("  - Export Functionality")
        print("\nPress CTRL+C to stop the server\n")
        
        app.run(host='0.0.0.0', port=5000, debug=False)
        
    except Exception as e:
        print("\n" + "="*80)
        print("ERROR STARTING SERVER")
        print("="*80)
        print(f"Error: {str(e)}")
        print("\nFull error details:")
        import traceback
        traceback.print_exc()
        print("="*80 + "\n")
        input("Press Enter to exit...")
