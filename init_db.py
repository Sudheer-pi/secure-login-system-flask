import os
from flask import Flask
from config import Config
from models import db, User

def initialize_database():
    """Initializes the SQLite database schema and seeds default administrative and test accounts."""
    print("[*] Starting Secure Login System Database Initialization...")
    
    # Instantiate temporary minimal Flask app to bind db
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    # Ensure physical database directory exists
    db_dir = os.path.dirname(Config.DB_FILE_PATH)
    if not os.path.exists(db_dir):
        print(f"[*] Creating database folder: {db_dir}")
        os.makedirs(db_dir)
        
    with app.app_context():
        # Create all tables if they don't exist
        print("[*] Generating database tables...")
        db.create_all()
        
        # Check and seed Default Admin
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("[+] Seeding default administrator account...")
            admin = User(
                username='admin',
                email='admin@securesentinel.local',
                role='admin',
                is_active=True
            )
            admin.set_password('AdminSecure2026!')
            db.session.add(admin)
        else:
            print("[.] Administrator account 'admin' already exists.")
            
        # Check and seed Default Test User
        user = User.query.filter_by(username='user1').first()
        if not user:
            print("[+] Seeding default standard user account...")
            user = User(
                username='user1',
                email='user1@securesentinel.local',
                role='user',
                is_active=True
            )
            user.set_password('UserSecure2026!')
            db.session.add(user)
        else:
            print("[.] Standard user 'user1' already exists.")
            
        # Commit modifications
        db.session.commit()
        print("[+] Database initialized and seeded successfully!")
        print("\nDefault Credentials:")
        print("  - Admin:  username: admin   | password: AdminSecure2026!")
        print("  - User:   username: user1   | password: UserSecure2026!")

if __name__ == '__main__':
    initialize_database()
