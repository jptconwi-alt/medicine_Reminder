import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from email.mime.text import MIMEText
import smtplib
import ssl
from dotenv import load_dotenv
import atexit

load_dotenv()

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Email configuration
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = os.environ.get('EMAIL_PORT', 587)
EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    medicines = db.relationship('Medicine', backref='user', lazy=True)

class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50))
    time = db.Column(db.Time, nullable=False)
    days = db.Column(db.String(100))  # Comma-separated days (e.g., "Mon,Tue,Wed")
    status = db.Column(db.String(20), default='pending')  # pending, taken, missed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    medicines = Medicine.query.filter_by(user_id=current_user.id).order_by(Medicine.time).all()
    return render_template('dashboard.html', medicines=medicines)

@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        name = request.form.get('name')
        dosage = request.form.get('dosage')
        time_str = request.form.get('time')
        days = ','.join(request.form.getlist('days'))
        
        try:
            time_obj = datetime.strptime(time_str, '%H:%M').time()
        except:
            flash('Invalid time format')
            return redirect(url_for('add_medicine'))
        
        medicine = Medicine(
            name=name,
            dosage=dosage,
            time=time_obj,
            days=days,
            user_id=current_user.id
        )
        
        db.session.add(medicine)
        db.session.commit()
        flash('Medicine added successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('add_medicine.html')

@app.route('/update_status/<int:medicine_id>', methods=['POST'])
@login_required
def update_status(medicine_id):
    medicine = Medicine.query.get_or_404(medicine_id)
    if medicine.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    medicine.status = request.json.get('status')
    db.session.commit()
    return jsonify({'message': 'Status updated'})

@app.route('/delete_medicine/<int:medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    medicine = Medicine.query.get_or_404(medicine_id)
    if medicine.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(medicine)
    db.session.commit()
    return jsonify({'message': 'Medicine deleted'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Email notification function
def send_email_notification(user_email, medicine_name, dosage, time):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        print("Email credentials not configured")
        return
    
    subject = f"Medicine Reminder: {medicine_name}"
    body = f"""
    Hello,
    
    It's time to take your medicine:
    
    Medicine: {medicine_name}
    Dosage: {dosage}
    Time: {time}
    
    Please don't forget to take it!
    
    Best regards,
    Medicine Reminder App
    """
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = user_email
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls(context=context)
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {user_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Scheduler for checking reminders
def check_reminders():
    with app.app_context():
        now = datetime.now()
        current_time = now.time()
        current_day = now.strftime('%a')
        
        # Find medicines due now
        medicines = Medicine.query.filter(
            Medicine.time.between(
                (datetime.combine(datetime.today(), current_time) - timedelta(minutes=5)).time(),
                current_time
            ),
            Medicine.days.like(f'%{current_day}%'),
            Medicine.status == 'pending'
        ).all()
        
        for medicine in medicines:
            send_email_notification(
                medicine.user.email,
                medicine.name,
                medicine.dosage,
                medicine.time.strftime('%I:%M %p')
            )

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_reminders, trigger="interval", minutes=1)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
