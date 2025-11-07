# setup.py
from app import app, db, User
from werkzeug.security import generate_password_hash
from slugify import slugify


def create_admin_user():
    with app.app_context():  # Ensure you have the application context
        with app.app_context():  # Ensure you have the application context
            admin_username = 'admin'
            admin_email = 'klimoleh045@email.com'
            admin_password = '1'  # You might want to use a secure password here

            existing_user = User.query.filter_by(email=admin_email).first()
            if existing_user:
                print(f"Admin user '{admin_username}' already exists.")
                return

            hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256', salt_length=8)

            # Generate a unique slug based on the username
            admin_slug = slugify(admin_username, max_length=50)

            admin_user = User(username=admin_username, email=admin_email, password=hashed_password, role=1, slug=admin_slug)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Admin user '{admin_username}' created successfully.")


if __name__ == '__main__':
    create_admin_user()