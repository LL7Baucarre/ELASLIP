#!/usr/bin/env python
"""Script to make a user an admin."""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.auth import User

app = create_app()

with app.app_context():
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter username to make admin: ").strip()
    
    user = User.get_by_username(username)
    if not user:
        print(f"User '{username}' not found")
        sys.exit(1)
    
    # Update user to be admin
    user.update(is_admin=True)
    print(f"User '{username}' is now an admin")
