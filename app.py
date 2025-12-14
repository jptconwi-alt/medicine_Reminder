import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import atexit
import requests
import json

load_dotenv()

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# EmailJS Configuration
EMAILJS_SERVICE_ID = os.environ.get('EMAILJS_SERVICE_ID')
EMAILJS_TEMPLATE_ID = os.environ.get('EMAILJS_TEMPLATE_ID')
EMAILJS_USER_ID = os.environ.get('EMAILJS_USER_ID')
EMAILJS_ACCESS_TOKEN = os.environ.get('EMAILJS_ACCESS_TOKEN')

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

# EmailJS Notification Function
def send_emailjs_notification(user_email, medicine_name, dosage, time_str):
    """
    Send email using EmailJS REST API
    """
    if not all([EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_USER_ID]):
        print("EmailJS credentials not configured")
        return False
    
    url = "https://api.emailjs.com/api/v1.0/email/send"
    
    data = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_USER_ID,
        "template_params": {
            "to_email": user_email,
            "medicine_name": medicine_name,
            "dosage": dosage,
            "time": time_str,
            "to_name": "Valued User",
            "reply_to": "noreply@medicine-reminder.com"
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    # Add access token if provided (for private templates)
    if EMAILJS_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {EMAILJS_ACCESS_TOKEN}"
    
    try:
        response = requests.post(url, json=data, headers=headers)
        
        if response.status_code == 200:
            print(f"Email sent successfully to {user_email}")
            return True
        else:
            print(f"Failed to send email: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Scheduler for checking reminders
def check_reminders():
    with app.app_context():
        now = datetime.now()
        current_time = now.time()
        current_day = now.strftime('%a')
        
        # Find medicines due now (within a 5-minute window)
        medicines = Medicine.query.filter(
            Medicine.time.between(
                (datetime.combine(datetime.today(), current_time) - timedelta(minutes=5)).time(),
                current_time
            ),
            Medicine.days.like(f'%{current_day}%'),
            Medicine.status == 'pending'
        ).all()
        
        for medicine in medicines:
            success = send_emailjs_notification(
                medicine.user.email,
                medicine.name,
                medicine.dosage or "As prescribed",
                medicine.time.strftime('%I:%M %p')
            )
            
            if success:
                # You can update the medicine status or log the notification
                print(f"Reminder sent for {medicine.name} to {medicine.user.email}")

# Routes (same as before, just showing the updated ones)
@app.route('/test_email', methods=['POST'])
@login_required
def test_email():
    """Endpoint to test email sending from frontend"""
    data = request.get_json()
    
    # Send email using frontend credentials (if provided)
    return jsonify({
        'status': 'success',
        'message': 'Test email configured for frontend'
    })

# ... [All other routes remain the same as in previous implementation] ...

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
