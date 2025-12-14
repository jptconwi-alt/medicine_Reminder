import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message
from dotenv import load_dotenv
import atexit
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Email configuration for Gmail - FIXED
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'jpconwi2005@gmail.com')  # FIXED
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'dyrsdcntrrvkauor')  # Your app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'jpconwi2005@gmail.com')  # FIXED

# Initialize Flask-Mail
mail = Mail(app)

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
            
            # Debug: Log environment variables (without password)
            logger.info(f"📧 Email configured for: {app.config['MAIL_USERNAME']}")
            logger.info(f"📧 Mail server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")

init_db()

# Email notification function
def send_email_notification(user_email, medicine_name, dosage, time_str):
    """Send email notification using Gmail SMTP"""
    try:
        # Get current PH time
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_day = now_ph.strftime('%A')
        
        subject = f"💊 Medicine Reminder: {medicine_name}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <div style="background: linear-gradient(to right, #4b6cb7, #182848); padding: 20px; border-radius: 10px 10px 0 0; color: white; text-align: center;">
                    <h1 style="margin: 0;">💊 Medicine Reminder</h1>
                </div>
                
                <div style="padding: 30px;">
                    <h2>Time to take your medicine!</h2>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4b6cb7;">
                        <h3 style="margin-top: 0; color: #2c3e50;">{medicine_name}</h3>
                        <p><strong>Dosage:</strong> {dosage or 'As prescribed'}</p>
                        <p><strong>Time:</strong> {time_str} (Philippine Time)</p>
                        <p><strong>Day:</strong> {current_day}</p>
                    </div>
                    
                    <p>Please don't forget to take your medicine on time. Your health is important!</p>
                    
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                        <p style="color: #666; font-size: 14px;">
                            This is an automated reminder from your Medicine Reminder app.<br>
                            You can manage your reminders at <a href="https://medicine-reminder-85qu.onrender.com">Medicine Reminder App</a>
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject=subject,
            recipients=[user_email],
            html=html_body,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        mail.send(msg)
        logger.info(f"✅ Email sent successfully to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send email to {user_email}: {e}")
        return False

# Check reminders function - SIMPLE AND RELIABLE
def check_due_medicines():
    """Check for medicines due in the next 2 minutes"""
    with app.app_context():
        try:
            # Get current time in UTC
            now_utc = datetime.utcnow()
            
            # Convert to Philippine Time (UTC+8)
            now_ph = now_utc + timedelta(hours=8)
            current_hour = now_ph.hour
            current_minute = now_ph.minute
            current_day_ph = now_ph.strftime('%a')  # 'Sun', 'Mon', etc.
            
            logger.info(f"🔍 Checking medicines for {current_day_ph} at {current_hour:02d}:{current_minute:02d} PH Time")
            
            # Find medicines due at this exact minute
            medicines = Medicine.query.filter(
                db.extract('hour', Medicine.time) == current_hour,
                db.extract('minute', Medicine.time) == current_minute,
                Medicine.days.like(f'%{current_day_ph}%'),
                Medicine.status == 'pending'
            ).all()
            
            logger.info(f"📋 Found {len(medicines)} medicines due now")
            
            for medicine in medicines:
                # Check if not notified in last 30 minutes
                if (medicine.last_notified is None or 
                    (now_utc - medicine.last_notified) > timedelta(minutes=30)):
                    
                    logger.info(f"📤 Sending reminder for '{medicine.name}' to {medicine.user.email}")
                    
                    success = send_email_notification(
                        medicine.user.email,
                        medicine.name,
                        medicine.dosage or "As prescribed",
                        medicine.time.strftime('%I:%M %p')
                    )
                    
                    if success:
                        medicine.last_notified = now_utc
                        db.session.commit()
                        logger.info(f"✅ Reminder sent for '{medicine.name}'")
                    else:
                        logger.error(f"❌ Failed to send reminder for '{medicine.name}'")
                        
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
        
        # Group medicines
        pending_medicines = [m for m in medicines if m.status == 'pending']
        taken_medicines = [m for m in medicines if m.status == 'taken']
        missed_medicines = [m for m in medicines if m.status == 'missed']
        
        return render_template('dashboard.html', 
                             medicines=medicines,
                             pending_medicines=pending_medicines,
                             taken_medicines=taken_medicines,
                             missed_medicines=missed_medicines,
                             current_ph_time=current_ph_time,
                             current_ph_day=current_ph_day)
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
                time=time_obj,  # Store as Philippine Time
                days=days_str,
                user_id=current_user.id
            )
            
            db.session.add(medicine)
            db.session.commit()
            
            flash(f'✅ Medicine "{name}" added for {time_obj.strftime("%I:%M %p")} Philippine Time!')
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
    """Test email functionality"""
    try:
        # Simple test email
        msg = Message(
            subject='✅ Test Email from Medicine Reminder',
            recipients=[current_user.email],
            body=f'This is a test email sent at {datetime.utcnow().strftime("%H:%M:%S")} UTC.\n\nIf you received this, email notifications are working!',
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        mail.send(msg)
        flash('✅ Test email sent! Check your inbox (and spam folder).')
        logger.info(f"✅ Test email sent to {current_user.email}")
        
    except Exception as e:
        logger.error(f"❌ Test email error: {e}")
        flash(f'❌ Error sending test email: {str(e)}')
    
    return redirect(url_for('dashboard'))

@app.route('/debug_info')
@login_required
def debug_info():
    """Debug page to check system status"""
    medicines = Medicine.query.filter_by(user_id=current_user.id).all()
    
    debug_info = []
    for medicine in medicines:
        debug_info.append({
            'name': medicine.name,
            'time': medicine.time.strftime('%H:%M:%S'),
            'display_time': medicine.time.strftime('%I:%M %p'),
            'days': medicine.days,
            'status': medicine.status,
            'last_notified': medicine.last_notified.strftime('%H:%M:%S') if medicine.last_notified else 'Never'
        })
    
    # Current time info
    now_utc = datetime.utcnow()
    now_ph = now_utc + timedelta(hours=8)
    
    return jsonify({
        'user_email': current_user.email,
        'current_utc': now_utc.strftime('%H:%M:%S'),
        'current_ph': now_ph.strftime('%I:%M %p'),
        'ph_day': now_ph.strftime('%a'),
        'medicines': debug_info,
        'email_config': {
            'server': app.config['MAIL_SERVER'],
            'port': app.config['MAIL_PORT'],
            'username': app.config['MAIL_USERNAME'],
            'sender': app.config['MAIL_DEFAULT_SENDER']
        }
    })

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
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Initialize scheduler
scheduler = BackgroundScheduler()
# Check every minute at :00 seconds
scheduler.add_job(func=check_due_medicines, trigger='interval', minutes=1, id='check_medicines')
scheduler.start()
logger.info("✅ Scheduler started - checking medicines every minute")

# Shutdown scheduler on exit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
