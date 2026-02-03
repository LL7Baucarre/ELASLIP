from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user

from app.auth import User
from app.services.otp_service import OTPService
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
            # Check if user has OTP enabled
            if user.otp_enabled:
                # Create temporary session for OTP verification
                otp_service = OTPService()
                temp_session = otp_service.create_temp_session(user.id)
                
                if request.is_json:
                    return jsonify({
                        'status': 'otp_required',
                        'temp_session': temp_session,
                        'message': 'OTP code required'
                    }), 202
                else:
                    # Redirect to verify-otp with temp_session as query parameter
                    return redirect(url_for('auth.verify_otp', temp_session=temp_session))
            
            # No OTP, login directly
            user.update_last_login()
            login_user(user)
            
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


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP verification page and handler."""
    otp_service = OTPService()
    
    if request.method == 'GET':
        # Display OTP verification form
        temp_session = request.args.get('temp_session')
        
        if not temp_session or not otp_service.get_temp_session(temp_session):
            flash('OTP verification session expired. Please login again.', 'error')
            return redirect(url_for('auth.login'))
        
        return render_template('auth/verify_otp.html', temp_session=temp_session)
    
    # POST request - verify OTP code
    if request.is_json:
        data = request.get_json()
        temp_session = data.get('temp_session')
        code = data.get('code')
        use_backup = data.get('use_backup', False)
    else:
        temp_session = request.form.get('temp_session')
        code = request.form.get('code')
        use_backup = request.form.get('use_backup') == 'on'
    
    if not temp_session or not code:
        if request.is_json:
            return jsonify({'error': 'OTP code and session required'}), 400
        flash('OTP code required', 'error')
        return render_template('auth/verify_otp.html', temp_session=temp_session)
    
    # Get temporary session
    session_data = otp_service.get_temp_session(temp_session)
    if not session_data:
        if request.is_json:
            return jsonify({'error': 'Invalid or expired OTP session'}), 401
        flash('OTP session expired. Please login again.', 'error')
        return redirect(url_for('auth.login'))
    
    user_id = session_data['user_id']
    user = User.get_by_id(user_id)
    
    if not user:
        if request.is_json:
            return jsonify({'error': 'User not found'}), 401
        flash('User not found. Please login again.', 'error')
        return redirect(url_for('auth.login'))
    
    # Verify OTP code or backup code
    code_valid = False
    
    if use_backup:
        # Verify backup code
        code_valid = otp_service.verify_backup_code(user, code)
        if code_valid:
            otp_service.consume_backup_code(user, code)
            # Reload user to get updated backup codes
            user = User.get_by_id(user_id)
    else:
        # Verify TOTP code
        code_valid = otp_service.verify_token(user.otp_secret, code)
    
    if code_valid:
        # Valid code, login user
        user.update_last_login()
        login_user(user)
        otp_service.delete_temp_session(temp_session)
        
        if request.is_json:
            return jsonify({
                'message': 'OTP verified',
                'user': user.to_dict()
            })
        
        flash('Login successful!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('main.dashboard'))
    
    # Invalid code, update attempt counter
    otp_service.update_temp_session_attempts(temp_session)
    remaining = otp_service.get_remaining_attempts(temp_session)
    
    error_msg = f'Invalid OTP code. {remaining} attempts remaining.'
    
    if request.is_json:
        return jsonify({
            'error': 'Invalid OTP code',
            'attempts_remaining': remaining
        }), 401
    
    flash(error_msg, 'error')
    return render_template('auth/verify_otp.html', temp_session=temp_session, attempts_remaining=remaining)


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


# OTP Management Routes

@auth_bp.route('/otp/setup', methods=['GET'])
@login_required
def otp_setup_get():
    """Get OTP setup data (secret, QR code, backup codes)."""
    otp_service = OTPService()
    
    # Generate new secret and backup codes
    secret = otp_service.generate_secret()
    backup_codes = otp_service.generate_backup_codes()
    
    # Generate QR code
    qr_code_bytes = otp_service.generate_qr_code(current_user.username, secret)
    
    # Convert QR code to base64 for display
    import base64
    qr_code_b64 = base64.b64encode(qr_code_bytes).decode('utf-8')
    
    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_code_b64}',
        'backup_codes': backup_codes,
        'message': 'Scan the QR code with an authenticator app, then verify with a code'
    })


@auth_bp.route('/otp/setup', methods=['POST'])
@login_required
def otp_setup_post():
    """Verify OTP and enable it."""
    otp_service = OTPService()
    
    if request.is_json:
        data = request.get_json()
        code = data.get('code')
        secret = data.get('secret')
        backup_codes = data.get('backup_codes', [])
    else:
        code = request.form.get('code')
        secret = request.form.get('secret')
        backup_codes = request.form.getlist('backup_codes[]')
    
    if not code or not secret or not backup_codes:
        msg = 'Code, secret, and backup codes required'
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Verify the code matches the secret
    if not otp_service.verify_token(secret, code):
        msg = 'Invalid OTP code. Please try again.'
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Enable OTP for user
    otp_service.enable_otp(current_user, secret, backup_codes)
    
    # Reload user to get updated OTP status
    updated_user = User.get_by_id(current_user.id)
    if updated_user:
        from flask_login import current_user as cu
        cu.otp_enabled = updated_user.otp_enabled
        cu.otp_secret = updated_user.otp_secret
        cu.otp_backup_codes = updated_user.otp_backup_codes
        cu.otp_verified_at = updated_user.otp_verified_at
        cu.otp_created_at = updated_user.otp_created_at
    
    msg = 'Two-Factor Authentication (OTP) enabled successfully!'
    if request.is_json:
        return jsonify({
            'success': True,
            'message': msg,
            'otp_status': otp_service.get_otp_status(current_user)
        })
    
    flash(msg, 'success')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/otp/disable', methods=['POST'])
@login_required
def otp_disable():
    """Disable OTP for current user."""
    otp_service = OTPService()
    
    if request.is_json:
        data = request.get_json()
        password = data.get('password')
    else:
        password = request.form.get('password')
    
    if not password:
        msg = 'Password required to disable OTP'
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Verify password
    if not current_user.check_password(password):
        msg = 'Invalid password'
        if request.is_json:
            return jsonify({'error': msg}), 401
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Disable OTP
    otp_service.disable_otp(current_user)
    
    # Reload user
    updated_user = User.get_by_id(current_user.id)
    if updated_user:
        from flask_login import current_user as cu
        cu.otp_enabled = False
        cu.otp_secret = None
        cu.otp_backup_codes = []
        cu.otp_verified_at = None
        cu.otp_created_at = None
    
    msg = 'Two-Factor Authentication (OTP) disabled'
    if request.is_json:
        return jsonify({'message': msg})
    
    flash(msg, 'info')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/otp/status', methods=['GET'])
@login_required
def otp_status():
    """Get current OTP status for user."""
    otp_service = OTPService()
    return jsonify(otp_service.get_otp_status(current_user))


@auth_bp.route('/otp/backup-codes', methods=['POST'])
@login_required
def otp_regenerate_backup_codes():
    """Regenerate backup codes for user."""
    otp_service = OTPService()
    
    if request.is_json:
        data = request.get_json()
        code = data.get('code')
        password = data.get('password')
    else:
        code = request.form.get('code')
        password = request.form.get('password')
    
    if not code or not password:
        msg = 'OTP code and password required'
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Verify OTP code
    if not otp_service.verify_token(current_user.otp_secret, code):
        msg = 'Invalid OTP code'
        if request.is_json:
            return jsonify({'error': msg}), 401
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Verify password
    if not current_user.check_password(password):
        msg = 'Invalid password'
        if request.is_json:
            return jsonify({'error': msg}), 401
        flash(msg, 'error')
        return redirect(url_for('auth.profile'))
    
    # Generate new backup codes
    new_backup_codes = otp_service.generate_backup_codes()
    
    # Update user
    otp_service.enable_otp(current_user, current_user.otp_secret, new_backup_codes)
    
    # Reload user
    updated_user = User.get_by_id(current_user.id)
    if updated_user:
        from flask_login import current_user as cu
        cu.otp_backup_codes = updated_user.otp_backup_codes
    
    if request.is_json:
        return jsonify({
            'message': 'Backup codes regenerated successfully',
            'backup_codes': new_backup_codes
        })
    
    flash('Backup codes regenerated successfully', 'success')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password via API."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    # Validate required fields
    if not all([current_password, new_password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    # Verify current password
    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Verify passwords match
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    # Validate password strength (minimum 8 characters)
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    
    # Update password
    current_user.set_password(new_password)
    current_user.save()
    
    return jsonify({
        'message': 'Password changed successfully',
        'status': 'success'
    }), 200
