from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user, login_user, login_required, logout_user
import app
from flask import Blueprint, render_template
from app import db, login_manager
from app.models import User, Note, Client, UserIP
from app.forms import RegistrationForm, LoginForm, NoteForm, PasswordForm, OTPForm
from bleach import clean
from sqlalchemy import or_
from cryptography.fernet import Fernet
import hashlib
import base64
import time
from datetime import datetime
import pyotp
from flask import session
import sys

# Create a TOTP (Time-based One-Time Password) instance
totp = pyotp.TOTP(pyotp.random_base32(), interval=60)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    session['two_step_authenticated'] = False
    if current_user.is_authenticated:
        user_notes = db.session.query(Note, User).filter(or_(Note.user_id == current_user.id, Note.public == True)).join(User).all()
    else:
        user_notes = db.session.query(Note, User).filter(Note.public == True).join(User).all()

    return render_template('index.html', notes=user_notes)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)

        try:
            user.set_password(form.password.data)

            ip_address = request.remote_addr
            user_ip = UserIP(ip_address=ip_address, user=user, is_associated=True)
            
            db.session.add_all([user, user_ip])
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('main.login'))
        except ValueError as e:
            flash(str(e), 'danger')
    else:
        if form.errors.items():
            flash('Account creation failed, check your inputs and try again.', 'danger')

    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    client = Client.query.filter_by(ip=request.remote_addr).first()
    if client is None:
        client = Client(ip=request.remote_addr, failed_login_requests=0, last_request_date=datetime.utcnow())
        db.session.add(client)
        db.session.commit()

    delay_seconds = 1
    form = LoginForm()
    elapsed_time = datetime.utcnow() - client.last_request_date

    if client.failed_login_requests >= 10 and elapsed_time.total_seconds() < 3600:
        flash('Too many login attempts, wait an hour', 'danger')
        return redirect(url_for('main.index'))
    else:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                # login_user(user)
                session['two_step_authenticated'] = True
                # o3 = generate_otp(totp)
                # sys.stdout.write("o3")
                # sys.stdout.flush()
                return redirect(url_for('main.provide_otp'))
                login_ip = request.remote_addr
                associated_ips = [ip.ip_address for ip in user.ips if ip.is_associated]
                not_associated_ips = [ip.ip_address for ip in user.ips if not ip.is_associated]

                if login_ip not in associated_ips:
                    new_user_ip = UserIP(ip_address=login_ip, user=user, is_associated=False)
                    db.session.add(new_user_ip)
                elif not not_associated_ips is None:
                    flash('There were new devices that logged into your account', 'danger')
                    return render_template('new_ips.html', ips=not_associated_ips)

                flash('Logged in!', 'success')
                client.failed_login_requests = 0
                return redirect(url_for('main.index'))
            else:
                flash('Login unsuccessful. Please check email and password.', 'danger')
                time.sleep(delay_seconds)
                client.failed_login_requests +=1
            db.session.commit()
        else:
            if form.errors.items():
                flash('Login unsuccessful. Please check email and password.', 'danger')
                time.sleep(delay_seconds)
    return render_template('login.html', form=form)

@bp.route('/provide-otp', methods=['GET', 'POST'])
def provide_otp():
    # o1 = generate_otp(totp)
    # sys.stdout.write("token 1")
    o2 = generate_otp(totp)
    sys.stdout.write("o2")
    # sys.stdout.flush()
    if 'two_step_authenticated' not in session or not session['two_step_authenticated']:
        return redirect(url_for('main.index'))

    form = OTPForm()



    if form.validate_on_submit():
        user_entered_otp = form.otp.data
        generated_otp = generate_otp(totp)

        # Validate the entered OTP
        if user_entered_otp == generated_otp:  # Replace 'generated_otp' with the actual OTP
            # Clear the session variable
            session.pop('two_step_authenticated', None)

            # Log the user in
            login_user(current_user)

            flash('Logged in!', 'success')
            return redirect(url_for('main.index'))

        flash('Invalid OTP. Please try again.', 'danger')

    return render_template('provide_otp.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for('main.index'))

@bp.route('/note/new', methods=['GET', 'POST'])
@login_required
def new_note():
    form = NoteForm()
    if form.is_submitted():
        form.validate()  # Explicitly validate the form
    if form.validate_on_submit():
        content = sanitize_content(form.content.data)
        if(form.encrypted.data):
            if(form.password.data):
                key = base64.urlsafe_b64encode(hashlib.sha256(form.password.data.encode()).digest())
                content=Fernet(key).encrypt(content.encode('utf-8'))
            else:
                flash('Encrypted note must have a password', 'danger')
                return render_template('new_note.html', form=form,)

        note = Note(content=content, encrypted=form.encrypted.data, public=form.public.data, user_id=current_user.id)
        db.session.add(note)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('main.index'))
    
    return render_template('new_note.html', form=form,)

@bp.route('/decrypt_note/<int:note_id>', methods=['GET', 'POST'])
def decrypt_note(note_id):
    note = Note.query.get_or_404(note_id)
    user = User.query.get_or_404(note.user_id)

    if note.public or not current_user.is_anonymous and current_user.id == note.user_id :

        password_form = PasswordForm()

        if password_form.validate_on_submit():
            try:
                key = base64.urlsafe_b64encode(hashlib.sha256(password_form.password.data.encode()).digest())
                note.content = Fernet(key).decrypt(note.content).decode('utf-8')
                return render_template('decrypted_note.html', note=note, user=user)
            except Exception as e:
                flash("Invalid password. Please try again.", 'danger')

        return render_template('password_form.html', form=password_form, note=note)
    else:
        flash("You don't have permission to decrypt this note.", 'danger')
        return redirect(url_for('main.index'))

def sanitize_content(content):
    allowed_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'strong', 'a', 'img', 'i']
    allowed_attributes = {'a': ['href', 'title'],'img': ['src', 'alt']}
    
    cleaned_content = clean(content, tags=allowed_tags, attributes=allowed_attributes)
    return cleaned_content

def generate_otp(totp):

    # Generate and print the OTP
    otp = totp.now()
    print(f"Generated OTP: {otp}")
    sys.stdout.write("token: "+otp)
    sys.stdout.flush()

    return otp