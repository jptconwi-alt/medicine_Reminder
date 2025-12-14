import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
import atexit
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Get database URL from environment (Render provides DATABASE_URL)
database_url = os.environ.get('DATABASE_URL')

# Fix for Render: Replace postgres:// with postgresql:// if needed
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///medicine.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    medicines = db.relationship('Medicine', backref='user', lazy=True, cascade='all, delete-orphan')

class Medicine(db.Model):
    __tablename__ = 'medicines'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50))
    time = db.Column(db.Time, nullable=False)
    days = db.Column(db.String(100))  # Comma-separated days (e.g., "Mon,Tue,Wed")
    status = db.Column(db.String(20), default='pending')  # pending, taken, missed
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_notified = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            logger.info("✅ Database tables checked/created successfully")
            
            # Add missing columns without dropping tables
            from sqlalchemy import inspect, text
            
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('medicines')]
            
            # Define required columns with their types
            required_columns = {
                'name': 'VARCHAR(100)',
                'dosage': 'VARCHAR(50)',
                'time': 'TIME',
                'days': 'VARCHAR(100)',
                'status': 'VARCHAR(20)',
                'user_id': 'INTEGER',
                'created_at': 'TIMESTAMP',
                'last_notified': 'TIMESTAMP'
            }
            
            for column_name, column_type in required_columns.items():
                if column_name not in columns:
                    try:
                        logger.info(f"Adding missing column '{column_name}'...")
                        db.session.execute(text(f"""
                            ALTER TABLE medicines 
                            ADD COLUMN {column_name} {column_type}
                        """))
                        db.session.commit()
                        logger.info(f"✅ Added column '{column_name}'")
                    except Exception as e:
                        logger.error(f"Error adding column {column_name}: {e}")
                        db.session.rollback()
                        
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please enter both email and password')
            return redirect(url_for('login'))
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password, password):
                login_user(user, remember=True)
                flash('Logged in successfully!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not email or not password:
            flash('Please fill in all fields')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters')
            return redirect(url_for('signup'))
        
        try:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered')
                return redirect(url_for('signup'))
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(email=email, password=hashed_password)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please login.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Signup error: {e}")
            flash('An error occurred. Please try again.')
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        medicines = Medicine.query.filter_by(user_id=current_user.id)\
            .order_by(Medicine.time).all()
        
        # Group medicines by status
        pending_medicines = [m for m in medicines if m.status == 'pending']
        taken_medicines = [m for m in medicines if m.status == 'taken']
        missed_medicines = [m for m in medicines if m.status == 'missed']
        
        return render_template('dashboard.html', 
                             medicines=medicines,
                             pending_medicines=pending_medicines,
                             taken_medicines=taken_medicines,
                             missed_medicines=missed_medicines)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('An error occurred while loading dashboard')
        return render_template('dashboard.html', medicines=[])

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        name = request.form.get('name')
        dosage = request.form.get('dosage')
        time_str = request.form.get('time')
        days = request.form.getlist('days')
        
        if not name or not time_str or not days:
            flash('Please fill in all required fields')
            return redirect(url_for('add_medicine'))
        
        try:
            time_obj = datetime.strptime(time_str, '%H:%M').time()
            days_str = ','.join(days)
            
            medicine = Medicine(
                name=name,
                dosage=dosage,
                time=time_obj,
                days=days_str,
                user_id=current_user.id
            )
            
            db.session.add(medicine)
            db.session.commit()
            
            flash('Medicine added successfully!')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid time format. Please use HH:MM format')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Add medicine error: {e}")
            flash('An error occurred. Please try again.')
    
    days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    return render_template('add_medicine.html', days=days_of_week)

@app.route('/update_status/<int:medicine_id>', methods=['POST'])
@login_required
def update_status(medicine_id):
    try:
        medicine = Medicine.query.get_or_404(medicine_id)
        
        if medicine.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        new_status = request.json.get('status')
        if new_status not in ['pending', 'taken', 'missed']:
            return jsonify({'error': 'Invalid status'}), 400
        
        medicine.status = new_status
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Status updated'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update status error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/delete_medicine/<int:medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    try:
        medicine = Medicine.query.get_or_404(medicine_id)
        
        if medicine.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(medicine)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Medicine deleted'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete medicine error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Try to query database
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500

# Email notification function (Basic implementation)
def send_email_notification(user_email, medicine_name, dosage, time_str):
    """Simple email notification - you can integrate EmailJS here"""
    logger.info(f"Reminder: {medicine_name} at {time_str} for {user_email}")
    # Implement EmailJS integration here
    return True

# Check reminders function
def check_due_medicines():
    """Check and send notifications for due medicines"""
    with app.app_context():
        try:
            now = datetime.now()
            current_time = now.time()
            current_day = now.strftime('%A')  # Full day name
            
            # Get medicines due in the next 5 minutes
            five_minutes_later = (datetime.combine(now.date(), current_time) + timedelta(minutes=5)).time()
            
            medicines = Medicine.query.filter(
                Medicine.time.between(current_time, five_minutes_later),
                Medicine.days.like(f'%{current_day}%'),
                Medicine.status == 'pending'
            ).all()
            
            for medicine in medicines:
                # Only send if not notified in the last hour
                if (medicine.last_notified is None or 
                    (now - medicine.last_notified) > timedelta(hours=1)):
                    
                    success = send_email_notification(
                        medicine.user.email,
                        medicine.name,
                        medicine.dosage or "As prescribed",
                        medicine.time.strftime('%I:%M %p')
                    )
                    
                    if success:
                        medicine.last_notified = now
                        db.session.commit()
                        logger.info(f"Sent reminder for {medicine.name} to {medicine.user.email}")
                        
        except Exception as e:
            logger.error(f"Error checking reminders: {e}")

# Initialize scheduler (only if not in debug mode)
if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    scheduler = BackgroundScheduler()
    # Check every minute
    scheduler.add_job(func=check_due_medicines, trigger='interval', minutes=1)
    scheduler.start()
    
    # Shut down scheduler on exit
    atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Get port from environment (Render sets PORT)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
