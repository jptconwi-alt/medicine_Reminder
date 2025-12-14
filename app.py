import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import logging
import requests
import json

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Brevo Configuration
BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', 'jpconwi2005@gmail.com')
BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'medicine')

# Get database URL
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
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
    time = db.Column(db.Time, nullable=False)  # Stored as Philippine Time
    days = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_notified = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database tables checked/created")
            
            # Check Brevo configuration
            if BREVO_API_KEY:
                logger.info("✅ Brevo is configured")
            else:
                logger.warning("⚠️ Brevo API key not set - emails will be logged only")
                
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")

init_db()

# Brevo Email Function (Works on Render Free Tier)
def send_email_via_brevo(user_email, medicine_name, dosage, time_str):
    """Send email using Brevo API"""
    try:
        if not BREVO_API_KEY:
            logger.error("❌ Brevo API key not configured")
            return False
        
        # Get current PH time
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_day = now_ph.strftime('%A')
        
        # HTML content for email
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                .header {{ background: linear-gradient(to right, #4b6cb7, #182848); padding: 20px; border-radius: 10px 10px 0 0; color: white; text-align: center; }}
                .content {{ padding: 30px; background: #f9f9f9; }}
                .medicine-box {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4b6cb7; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #666; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1 style="margin: 0;">💊 Medicine Reminder</h1>
            </div>
            
            <div class="content">
                <h2>Time to take your medicine!</h2>
                
                <div class="medicine-box">
                    <h3 style="margin-top: 0; color: #2c3e50;">{medicine_name}</h3>
                    <p><strong>Dosage:</strong> {dosage or 'As prescribed'}</p>
                    <p><strong>Time:</strong> {time_str} (Philippine Time)</p>
                    <p><strong>Day:</strong> {current_day}</p>
                </div>
                
                <p>Please don't forget to take your medicine on time. Your health is important! 💙</p>
                
                <div class="footer">
                    <p>This is an automated reminder from your Medicine Reminder app.<br>
                    You can manage your reminders at <a href="https://medicine-reminder-85qu.onrender.com">Medicine Reminder App</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Text content (for plain text email clients)
        text_content = f"""
💊 Medicine Reminder

Time to take your medicine!

Medicine: {medicine_name}
Dosage: {dosage or 'As prescribed'}
Time: {time_str} (Philippine Time)
Day: {current_day}

Please don't forget to take your medicine on time. Your health is important!

This is an automated reminder from your Medicine Reminder app.
Manage your reminders at https://medicine-reminder-85qu.onrender.com
        """
        
        # Brevo API request
        brevo_url = "https://api.brevo.com/v3/smtp/email"
        
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY
        }
        
        payload = {
            "sender": {
                "name": BREVO_SENDER_NAME,
                "email": BREVO_SENDER_EMAIL
            },
            "to": [
                {
                    "email": user_email,
                    "name": user_email.split('@')[0]
                }
            ],
            "subject": f"💊 Medicine Reminder: {medicine_name}",
            "htmlContent": html_content,
            "textContent": text_content,
            "replyTo": {
                "email": BREVO_SENDER_EMAIL,
                "name": BREVO_SENDER_NAME
            }
        }
        
        response = requests.post(brevo_url, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 201:
            logger.info(f"✅ Email sent to {user_email} via Brevo")
            return True
        else:
            logger.error(f"❌ Brevo API error for {user_email}: {response.status_code} - {response.text}")
            return False
        
    except Exception as e:
        logger.error(f"❌ Brevo error for {user_email}: {e}")
        return False

# Notification function with fallback
def send_medicine_notification(user_email, medicine_name, dosage, time_str):
    """Send email notification with Brevo"""
    try:
        # Try Brevo first
        if BREVO_API_KEY:
            success = send_email_via_brevo(user_email, medicine_name, dosage, time_str)
            if success:
                return True
            else:
                logger.warning(f"⚠️ Brevo failed for {user_email}")
        
        # Fallback: Log to console
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_day = now_ph.strftime('%A')
        
        logger.info(f"""
        📧 EMAIL WOULD BE SENT (Brevo configured):
        ─────────────────────────────────────
        To: {user_email}
        Subject: 💊 Medicine Reminder: {medicine_name}
        Medicine: {medicine_name}
        Dosage: {dosage or 'As prescribed'}
        Time: {time_str} (Philippine Time)
        Day: {current_day}
        ─────────────────────────────────────
        """)
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Notification error: {e}")
        return False

# Check reminders function
def check_due_medicines():
    """Check for medicines due RIGHT NOW (within 2 minute window)"""
    with app.app_context():
        try:
            # Get current time in UTC
            now_utc = datetime.utcnow()
            
            # Convert to Philippine Time (UTC+8)
            now_ph = now_utc + timedelta(hours=8)
            current_hour = now_ph.hour
            current_minute = now_ph.minute
            current_day_ph = now_ph.strftime('%a')  # 'Sun', 'Mon', etc.
            
            logger.info(f"🕒 Checking at {current_hour:02d}:{current_minute:02d} PH Time ({current_day_ph})")
            
            # Get all pending medicines
            all_medicines = Medicine.query.filter_by(status='pending').all()
            
            due_medicines = []
            for medicine in all_medicines:
                # Check if today is in the medicine's days
                medicine_days = medicine.days.split(',') if medicine.days else []
                
                if current_day_ph in medicine_days:
                    # Get medicine time
                    medicine_hour = medicine.time.hour
                    medicine_minute = medicine.time.minute
                    medicine_time_str = f"{medicine_hour:02d}:{medicine_minute:02d}"
                    
                    # Check if time matches (within 2 minutes)
                    time_diff = abs((current_hour * 60 + current_minute) - (medicine_hour * 60 + medicine_minute))
                    
                    if time_diff <= 2:  # Within 2 minutes window
                        due_medicines.append(medicine)
                        logger.info(f"   ⏰ Found: '{medicine.name}' at {medicine_time_str}")
            
            logger.info(f"📋 Total due medicines: {len(due_medicines)}")
            
            for medicine in due_medicines:
                # Check if not notified in last 30 minutes
                if (medicine.last_notified is None or 
                    (now_utc - medicine.last_notified) > timedelta(minutes=30)):
                    
                    logger.info(f"📤 Sending reminder for '{medicine.name}' -> {medicine.user.email}")
                    
                    # Send notification
                    success = send_medicine_notification(
                        medicine.user.email,
                        medicine.name,
                        medicine.dosage or "As prescribed",
                        medicine.time.strftime('%I:%M %p')
                    )
                    
                    if success:
                        medicine.last_notified = now_utc
                        try:
                            db.session.commit()
                            logger.info(f"✅ Reminder processed for '{medicine.name}'")
                        except Exception as e:
                            logger.error(f"❌ Error saving notification time: {e}")
                            db.session.rollback()
                    else:
                        logger.error(f"❌ Failed to send reminder for '{medicine.name}'")
                else:
                    logger.info(f"   ⏱️  Skipping '{medicine.name}' - already notified recently")
                        
        except Exception as e:
            logger.error(f"❌ Error in check_due_medicines: {e}")

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
        
        # Get current PH time for display
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_ph_time = now_ph.strftime('%I:%M %p')
        current_ph_day = now_ph.strftime('%A')
        current_hour_min = f"{now_ph.hour:02d}:{now_ph.minute:02d}"
        
        # Convert medicine times for display
        for medicine in medicines:
            medicine.display_time = medicine.time.strftime('%I:%M %p')
            medicine.time_24h = medicine.time.strftime('%H:%M')
        
        # Group medicines
        pending_medicines = [m for m in medicines if m.status == 'pending']
        taken_medicines = [m for m in medicines if m.status == 'taken']
        missed_medicines = [m for m in medicines if m.status == 'missed']
        
        # Check if Brevo is configured
        email_enabled = bool(BREVO_API_KEY)
        
        return render_template('dashboard.html', 
                             medicines=medicines,
                             pending_medicines=pending_medicines,
                             taken_medicines=taken_medicines,
                             missed_medicines=missed_medicines,
                             current_ph_time=current_ph_time,
                             current_ph_day=current_ph_day,
                             current_hour_min=current_hour_min,
                             email_enabled=email_enabled)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', medicines=[])

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    days_of_week = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    
    if request.method == 'POST':
        name = request.form.get('name')
        dosage = request.form.get('dosage')
        time_str = request.form.get('time')
        days = request.form.getlist('days')
        
        if not name or not time_str or not days:
            flash('Please fill in all required fields')
            return render_template('add_medicine.html', days=days_of_week)
        
        try:
            # User enters time in 24-hour format
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
            
            display_time = time_obj.strftime('%I:%M %p')
            flash(f'✅ Medicine "{name}" added for {display_time} Philippine Time!')
            logger.info(f"User {current_user.email} added medicine: {name} at {display_time}")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Add medicine error: {e}")
            flash('Error adding medicine. Please try again.')
            return render_template('add_medicine.html', days=days_of_week)
    
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
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

@app.route('/test_email')
@login_required
def test_email():
    """Send a test email to verify Brevo system"""
    try:
        # Test with Brevo if configured
        if BREVO_API_KEY:
            success = send_email_via_brevo(
                current_user.email,
                "Test Medicine",
                "1 tablet",
                datetime.utcnow().strftime('%I:%M %p')
            )
            
            if success:
                flash('✅ Test email sent via Brevo! Check your inbox.')
            else:
                flash('❌ Failed to send test email via Brevo.')
        else:
            # Log test notification
            logger.info(f"Test email would be sent to {current_user.email} (Brevo not configured)")
            flash('⚠️ Brevo not configured. Set BREVO_API_KEY environment variable.')
            
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Test email error: {e}")
        flash(f'Error: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/email_status')
@login_required
def email_status():
    """Check email configuration status"""
    status = {
        'brevo_configured': bool(BREVO_API_KEY),
        'sender_email': BREVO_SENDER_EMAIL,
        'sender_name': BREVO_SENDER_NAME,
        'user_email': current_user.email,
        'status': 'ready' if BREVO_API_KEY else 'not_configured'
    }
    return jsonify(status)

@app.route('/add_test_medicine')
@login_required
def add_test_medicine():
    """Add a test medicine for 1 minute from now"""
    try:
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        
        # Add medicine for 1 minute from now
        future_time = (now_ph + timedelta(minutes=1)).time()
        current_day = now_ph.strftime('%a')
        
        medicine = Medicine(
            name='Test Medicine',
            dosage='1 tablet',
            time=future_time,
            days=current_day,
            user_id=current_user.id
        )
        
        db.session.add(medicine)
        db.session.commit()
        
        flash(f'✅ Test medicine added for {future_time.strftime("%I:%M %p")} (in 1 minute)')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Test medicine error: {e}")
        flash('Error adding test medicine')
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.route('/health')
def health_check():
    """Health check for Render"""
    try:
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'medicine-reminder',
            'version': '1.0',
            'brevo': 'configured' if BREVO_API_KEY else 'not_configured'
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Initialize scheduler
try:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=check_due_medicines,
        trigger='interval',
        minutes=1,
        id='medicine_checker',
        max_instances=1,
        replace_existing=True
    )
    scheduler.start()
    logger.info("✅ Scheduler started successfully - checking every minute")
except Exception as e:
    logger.error(f"❌ Failed to start scheduler: {e}")

# Shutdown scheduler on exit
atexit.register(lambda: scheduler.shutdown() if 'scheduler' in locals() else None)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
