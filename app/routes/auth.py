from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user

from app.auth import User
from app import login_manager

auth_bp = Blueprint('auth', __name__)


@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    return User.get_by_id(user_id)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        # Handle JSON API request
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'error': 'Username and password required'}), 400
            flash('Username and password required', 'error')
            return render_template('auth/login.html')
        
        user = User.get_by_username(username)
        
        if user and user.check_password(password):
            login_user(user)
            user.update_last_login()
            
            if request.is_json:
                return jsonify({
                    'message': 'Login successful',
                    'user': user.to_dict()
                })
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        
        if request.is_json:
            return jsonify({'error': 'Invalid username or password'}), 401
        flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout handler."""
    logout_user()
    
    if request.is_json:
        return jsonify({'message': 'Logged out successfully'})
    
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    """User profile page."""
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/api/me')
@login_required
def get_current_user():
    """Get current user info (API)."""
    return jsonify(current_user.to_dict())


@auth_bp.route('/api/auth/change-password', methods=['POST'])
@login_required
def change_password():
    """
    Change user's password.
    ---
    tags:
      - Authentication
    security:
      - BasicAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - current_password
            - new_password
          properties:
            current_password:
              type: string
              description: Current password for verification
            new_password:
              type: string
              description: New password (minimum 8 characters)
    responses:
      200:
        description: Password changed successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Password changed successfully"
      400:
        description: Bad request (missing fields, weak password)
        schema:
          type: object
          properties:
            error:
              type: string
      401:
        description: Unauthorized (current password incorrect)
        schema:
          type: object
          properties:
            error:
              type: string
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not current_password or not new_password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400
    
    current_user.update(password=new_password)
    
    return jsonify({'message': 'Password changed successfully'}), 200
