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

# Email configuration for Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Your Gmail address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Your Gmail app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@medreminder.com')

# Initialize Flask-Mail
mail = Mail(app)

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
            # This will create tables if they don't exist.
            db.create_all()
            logger.info("✅ Database tables checked/created")
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")

# Initialize database
init_db()

# Email notification function using Flask-Mail (Gmail)
def send_email_notification(user_email, medicine_name, dosage, time_str):
    """Send email notification using Gmail SMTP"""
    try:
        # Create email message
        subject = f"⏰ Medicine Reminder: {medicine_name}"
        
        # Get current day in Philippine Time
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_day = now_ph.strftime('%A')
        
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
                        <p><strong>Time:</strong> {time_str}</p>
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
        
        # Create message
        msg = Message(
            subject=subject,
            recipients=[user_email],
            html=html_body
        )
        
        # Send email
        mail.send(msg)
        logger.info(f"✅ Email sent successfully to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send email to {user_email}: {e}")
        return False

# Check reminders function - Fixed for Philippine Time (UTC+8)
def check_due_medicines():
    with app.app_context():
        try:
            # Get current UTC time
            now_utc = datetime.utcnow()
            
            # Convert to Philippine Time (UTC+8)
            now_ph = now_utc + timedelta(hours=8)
            current_time_ph = now_ph.time()
            current_day_ph = now_ph.strftime('%a')  # e.g., 'Sun', 'Mon'
            
            logger.info(f"🔍 Checking due medicines for {current_day_ph} at {current_time_ph} (PH Time)")
            
            # Calculate time window: current time to 5 minutes later in PH Time
            five_minutes_later_ph = (datetime.combine(now_ph.date(), current_time_ph) + timedelta(minutes=5)).time()
            
            # Convert PH time window to UTC for database comparison
            # Medicines are stored as UTC, so we need to subtract 8 hours
            current_time_ph_dt = datetime.combine(now_ph.date(), current_time_ph)
            current_time_utc = (current_time_ph_dt - timedelta(hours=8)).time()
            
            five_minutes_later_ph_dt = datetime.combine(now_ph.date(), five_minutes_later_ph)
            five_minutes_later_utc = (five_minutes_later_ph_dt - timedelta(hours=8)).time()
            
            logger.info(f"🕒 Time window in PH: {current_time_ph} to {five_minutes_later_ph}")
            logger.info(f"🕒 Time window in UTC (DB): {current_time_utc} to {five_minutes_later_utc}")
            
            # Find medicines due in the next 5 minutes
            medicines = Medicine.query.filter(
                Medicine.time.between(current_time_utc, five_minutes_later_utc),
                Medicine.days.like(f'%{current_day_ph}%'),
                Medicine.status == 'pending'
            ).all()
            
            logger.info(f"📋 Found {len(medicines)} medicines due in PH Time")
            
            for medicine in medicines:
                # Check if we haven't notified in the last hour
                if (medicine.last_notified is None or 
                    (now_utc - medicine.last_notified) > timedelta(hours=1)):
                    
                    # Convert stored UTC time to PH Time for display
                    medicine_time_utc = medicine.time
                    medicine_time_ph_dt = datetime.combine(datetime.utcnow().date(), medicine_time_utc) + timedelta(hours=8)
                    medicine_time_ph = medicine_time_ph_dt.time()
                    
                    logger.info(f"📤 Sending reminder for '{medicine.name}' to {medicine.user.email}")
                    logger.info(f"   Stored UTC: {medicine_time_utc}, Display PH: {medicine_time_ph.strftime('%I:%M %p')}")
                    
                    success = send_email_notification(
                        medicine.user.email,
                        medicine.name,
                        medicine.dosage or "As prescribed",
                        medicine_time_ph.strftime('%I:%M %p')
                    )
                    
                    if success:
                        medicine.last_notified = now_utc
                        db.session.commit()
                        logger.info(f"✅ Reminder sent for '{medicine.name}'")
                    else:
                        logger.error(f"❌ Failed to send reminder for '{medicine.name}'")
                        
        except Exception as e:
            logger.error(f"❌ Error checking reminders: {e}")

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

        # Convert each medicine's time to Philippine Time for display
        for medicine in medicines:
            # Medicine.time is stored as UTC
            utc_datetime = datetime.combine(datetime.utcnow().date(), medicine.time)
            ph_datetime = utc_datetime + timedelta(hours=8)
            medicine.display_time = ph_datetime.time().strftime('%I:%M %p')
            medicine.stored_utc_time = medicine.time.strftime('%H:%M:%S')

        # Group medicines by status
        pending_medicines = [m for m in medicines if m.status == 'pending']
        taken_medicines = [m for m in medicines if m.status == 'taken']
        missed_medicines = [m for m in medicines if m.status == 'missed']
        
        # Get current PH time for display
        now_utc = datetime.utcnow()
        now_ph = now_utc + timedelta(hours=8)
        current_ph_time = now_ph.strftime('%I:%M %p')
        current_ph_day = now_ph.strftime('%A')

        return render_template('dashboard.html', 
                             medicines=medicines,
                             pending_medicines=pending_medicines,
                             taken_medicines=taken_medicines,
                             missed_medicines=missed_medicines,
                             current_ph_time=current_ph_time,
                             current_ph_day=current_ph_day)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('An error occurred while loading dashboard')
        return render_template('dashboard.html', medicines=[])

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    # Define days_of_week at the TOP so it's available for both GET and POST
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
            # User enters Philippine Time (UTC+8)
            time_ph = datetime.strptime(time_str, '%H:%M').time()
            
            # Convert to UTC for storage (subtract 8 hours)
            time_ph_dt = datetime.combine(datetime.utcnow().date(), time_ph)
            time_utc_dt = time_ph_dt - timedelta(hours=8)
            time_utc = time_utc_dt.time()
            
            days_str = ','.join(days)
            
            medicine = Medicine(
                name=name,
                dosage=dosage,
                time=time_utc,  # Store as UTC
                days=days_str,
                user_id=current_user.id
            )
            
            db.session.add(medicine)
            db.session.commit()
            
            # Convert back to PH time for success message
            display_time_ph = (datetime.combine(datetime.utcnow().date(), time_utc) + timedelta(hours=8)).time().strftime('%I:%M %p')
            flash(f'Medicine "{name}" added successfully for {display_time_ph} Philippine Time!')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid time format. Please use HH:MM format (24-hour)')
            return render_template('add_medicine.html', days=days_of_week)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Add medicine error: {e}")
            flash('An error occurred. Please try again.')
            return render_template('add_medicine.html', days=days_of_week)
    
    # GET request - render the form
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
        db.session.execute('SELECT 1')
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500

@app.route('/test_email')
@login_required
def test_email():
    """Send a test email to the logged-in user"""
    try:
        # Debug logging
        logger.info(f"=== TEST EMAIL DEBUG ===")
        logger.info(f"User email: {current_user.email}")
        logger.info(f"MAIL_USERNAME from env: {os.environ.get('MAIL_USERNAME')}")
        logger.info(f"MAIL_PASSWORD set: {'Yes' if os.environ.get('MAIL_PASSWORD') else 'No'}")
        logger.info(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        logger.info(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        
        # Try a simple email first
        msg = Message(
            subject='Test from Medicine Reminder',
            recipients=[current_user.email],
            body='This is a test email from your Medicine Reminder app.'
        )
        
        mail.send(msg)
        logger.info("✅ Test email sent successfully!")
        flash('Test email sent successfully! Check your inbox (and spam).')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"❌ Test email error: {str(e)}", exc_info=True)
        flash(f'Error sending test email: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/debug_times')
@login_required
def debug_times():
    """Debug page to see all medicine times in different timezones"""
    medicines = Medicine.query.filter_by(user_id=current_user.id).all()
    
    debug_info = []
    for medicine in medicines:
        # Convert stored UTC to PH Time
        utc_time = medicine.time
        ph_time_dt = datetime.combine(datetime.utcnow().date(), utc_time) + timedelta(hours=8)
        ph_time = ph_time_dt.time()
        
        debug_info.append({
            'name': medicine.name,
            'stored_utc': utc_time.strftime('%H:%M:%S'),
            'ph_time': ph_time.strftime('%I:%M %p'),
            'days': medicine.days
        })
    
    # Current time info
    now_utc = datetime.utcnow()
    now_ph = now_utc + timedelta(hours=8)
    
    return render_template('debug_times.html', 
                         debug_info=debug_info,
                         current_utc=now_utc.strftime('%H:%M:%S'),
                         current_ph=now_ph.strftime('%I:%M %p'))

# Initialize scheduler
if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    scheduler = BackgroundScheduler()
    # Check every minute
    scheduler.add_job(func=check_due_medicines, trigger='interval', minutes=1)
    scheduler.start()
    
    # Shut down scheduler on exit
    atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # Get port from environment (Render sets PORT)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
