import os
import re
from dotenv import load_dotenv
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from slugify import slugify
from flask import flash
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
csrf.init_app(app)

db = SQLAlchemy(app)  # Primary database
migrate = Migrate(app, db)

serializer = URLSafeTimedSerializer(os.urandom(24))

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add this line for email
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.Integer, default=0)  # 0 for regular user, 1 for admin
    slug = db.Column(db.String(50), unique=True, nullable=False)

    def get_id(self):
        return str(self.id)


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/user')
@login_required
def user():
    return render_template("userpage.html", username=current_user.username)


@app.route('/top_movies')
def top_movies():
    return render_template('topmovies.html')


@app.route('/top_movies_by_oleg')
def top_movies_by_oleg():
    return render_template("topmovies_oleg.html")


@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')

        # Check if the new username already exists
        existing_user = User.query.filter(User.username == new_username, User.id != current_user.id).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('edit_user'))

        # Update the user's information in the database
        current_user.username = new_username
        current_user.email = new_email
        current_user.slug = slugify(new_username, max_length=50)  # Update the slug
        db.session.commit()

        flash('Changes saved successfully.', 'success')
        return redirect(url_for('user_profile', slug=current_user.slug))

    return render_template('edit.html', username=current_user.username, email=current_user.email)


@app.route('/account')
def account():
    if current_user.is_authenticated:
        return redirect(url_for('user_profile', slug=current_user.slug))
    return render_template("account.html")



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if current_user.is_authenticated:
            flash('You are already logged in. Please log out to register a new account.', 'info')
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            # Check if the username already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email address is already in use. Please choose a different one.', 'danger')
                return redirect(url_for('register'))

            if not (2 <= len(username) <= 35):
                flash('Username must be between 2 and 35 characters long.', 'danger')
                return redirect(url_for('register'))

            if not re.match(r'^[a-zA-Z0-9_-]+$', username):
                flash('Username can only contain letters, numbers, underscores, and hyphens.', 'danger')
                return redirect(url_for('register'))

            # Use the correct method for hashing the password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            slug = slugify(username, max_length=50)

            new_user = User(username=username, email=email, password=hashed_password, slug=slug)
            try:
                db.session.add(new_user)
                db.session.commit()


                flash('Registration successful. Please check your email to confirm your account.', 'success')
                return redirect(url_for('login'))
            except IntegrityError:
                db.session.rollback()
                flash('Email address is already in use. Please choose a different one.', 'danger')
                return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.session.query(User).filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            session['user_id'] = user.id

            if user.role == 1:  # Admin role
                session['is_admin'] = True
                flash('Welcome back, admin!', 'success')  # Admin-specific welcome message
            else:
                session['is_admin'] = False
                flash('You have been successfully logged in.', 'success')

            return redirect(url_for('user_profile', slug=user.slug))
        else:
            flash('Invalid email or password. Please try again.', 'danger')  # Login failed

    return render_template('login.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/user/<slug>')
@login_required
def user_profile(slug):
    if current_user.slug == slug:
        return render_template('userpage.html', username=current_user.username, email=current_user.email)
    else:
        return redirect(url_for('account'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('account'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))

    user = db.session.query(User).get(session['user_id'])

    if user.role != 1:
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = int(request.form.get('user_id'))

        if action == 'delete':
            user = db.session.query(User).get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash(f'User {user.username} deleted successfully.', 'success')
            else:
                flash('User not found.', 'danger')

        elif action == 'change_password':
            new_password = request.form.get('new_password')
            if new_password is not None:
                user = db.session.query(User).get(user_id)
                if user:
                    user.password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)
                    db.session.commit()
                    flash(f'Password for {user.username} changed successfully.', 'success')
                else:
                    flash('User not found.', 'danger')
            else:
                flash('User not found.', 'danger')

    return render_template('admin.html', users=users)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=1000, debug=False)