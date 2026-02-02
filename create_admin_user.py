"""
Create Admin User Script

This script creates a new admin user in the password manager database.
Run this from the AdvancedPasswordManager directory.

Usage:
    python create_admin_user.py
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from storage.mysql_engine import MySQLEngine
from crypto.fernet_engine import FernetEngine
import getpass


def create_admin_user():
    """Create a new admin user."""
    print("=" * 60)
    print("🛡️  Create Admin User")
    print("=" * 60)
    
    # Database configuration
    config = {
        'host': 'localhost',
        'port': 3306,
        'user': 'root',
        'password': 'root',
        'database': 'password_manager'
    }
    
    # Initialize database engine
    print("\n📊 Connecting to database...")
    db = MySQLEngine(config)
    
    if not db.connect():
        print("❌ ERROR: Cannot connect to database!")
        print("   Please check your database credentials in the config")
        return False
    
    print("✅ Connected to database successfully")
    
    # Initialize database tables
    print("\n📋 Initializing database tables...")
    if not db.initialize_database():
        print("⚠️  Warning: Could not initialize tables (they may already exist)")
    else:
        print("✅ Tables initialized")
    
    # Get user input
    print("\n" + "=" * 60)
    print("Enter Admin User Details")
    print("=" * 60)
    
    while True:
        admin_username = input("\n👤 Admin Username: ").strip()
        
        if not admin_username:
            print("❌ Username cannot be empty")
            continue
        
        # Check if user already exists
        existing_user = db.get_user(admin_username)
        if existing_user:
            print(f"❌ User '{admin_username}' already exists!")
            continue
        
        break
    
    while True:
        admin_password = getpass.getpass("🔐 Master Password: ")
        confirm_password = getpass.getpass("🔐 Confirm Password: ")
        
        if not admin_password:
            print("❌ Password cannot be empty")
            continue
        
        if len(admin_password) < 8:
            print("❌ Password must be at least 8 characters long")
            continue
        
        if admin_password != confirm_password:
            print("❌ Passwords do not match")
            continue
        
        break
    
    # Create crypto engine and hash password
    print("\n🔧 Generating password hash...")
    crypto = FernetEngine()
    salt = crypto.generate_salt()
    password_hash = crypto.hash_password(admin_password, salt)
    
    print("✅ Password hash generated")
    
    # Create admin user
    print("\n💾 Creating admin user in database...")
    try:
        user_id = db.create_user(
            username=admin_username,
            password_hash=password_hash,
            salt=salt.hex(),
            role='admin'  # Set role to admin
        )
        
        if user_id:
            print(f"✅ Admin user created successfully!")
            print("\n" + "=" * 60)
            print("Admin User Details")
            print("=" * 60)
            print(f"📌 User ID: {user_id}")
            print(f"👤 Username: {admin_username}")
            print(f"🛡️  Role: ADMIN")
            print(f"🔐 Password Hash: {password_hash[:50]}...")
            print("=" * 60)
            print("\n✨ You can now login with these credentials!")
            print("   The admin user has access to:")
            print("   • System monitoring dashboard")
            print("   • User management")
            print("   • Process and thread monitoring")
            print("   • Database statistics")
            print("   • Activity logs")
            return True
        else:
            print("❌ Failed to create admin user")
            return False
    
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False
    
    finally:
        db.disconnect()


def main():
    """Main entry point."""
    try:
        success = create_admin_user()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
