"""OAuth authentication routes."""

import logging
from flask import Blueprint, request, redirect, url_for, flash, render_template, jsonify, current_app, session
from flask_login import login_user, current_user, logout_user

from app.services.oauth_service import OAuthService


logger = logging.getLogger(__name__)

oauth_bp = Blueprint('oauth', __name__)


@oauth_bp.route('/login/<provider>')
def login(provider):
    if not current_app.config.get('OAUTH_ENABLED', False):
        flash('OAuth authentication is not enabled', 'error')
        return redirect(url_for('auth.login'))
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    oauth_service = OAuthService()
    auth_url, error = oauth_service.initiate_login(provider)
    
    if error:
        logger.warning(f'OAuth login initiation failed for {provider}: {error}')
        flash(error, 'error')
        return redirect(url_for('auth.login'))
    
    return redirect(auth_url)


@oauth_bp.route('/callback/<provider>')
def callback(provider):
    if not current_app.config.get('OAUTH_ENABLED', False):
        flash('OAuth authentication is not enabled', 'error')
        return redirect(url_for('auth.login'))
    
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        logger.warning(f'OAuth authorization error from {provider}: {error} - {error_description}')
        flash(f'Authorization failed: {error_description}', 'error')
        return redirect(url_for('auth.login'))
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or not state:
        flash('Invalid OAuth callback: missing code or state', 'error')
        return redirect(url_for('auth.login'))
    
    oauth_service = OAuthService()
    user, error = oauth_service.handle_callback(provider, code, state)
    
    if error:
        logger.warning(f'OAuth callback handling failed for {provider}: {error}')
        flash(error, 'error')
        return redirect(url_for('auth.login'))
    
    if not user:
        flash('Authentication failed', 'error')
        return redirect(url_for('auth.login'))
    
    login_user(user)
    flash(f'Successfully logged in with {provider.capitalize()}!', 'success')
    logger.info(f'User {user.username} logged in via OAuth ({provider})')
    
    next_page = request.args.get('next')
    return redirect(next_page or url_for('main.dashboard'))


@oauth_bp.route('/link/<provider>')
def link_account(provider):
    if not current_user.is_authenticated:
        flash('You must be logged in to link an OAuth account', 'error')
        return redirect(url_for('auth.login'))
    
    if not current_app.config.get('OAUTH_ENABLED', False):
        flash('OAuth authentication is not enabled', 'error')
        return redirect(url_for('auth.profile'))
    
    oauth_service = OAuthService()
    session['oauth_link_user_id'] = current_user.id
    
    auth_url, error = oauth_service.initiate_login(provider)
    
    if error:
        flash(error, 'error')
        return redirect(url_for('auth.profile'))
    
    return redirect(auth_url)


@oauth_bp.route('/unlink/<provider>', methods=['POST'])
def unlink_account(provider):
    if not current_user.is_authenticated:
        if request.is_json:
            return jsonify({'error': 'Authentication required'}), 401
        flash('You must be logged in', 'error')
        return redirect(url_for('auth.login'))
    
    from app.services.oauth_account_service import OAuthAccountService
    
    account_service = OAuthAccountService()
    oauth_accounts = account_service.get_oauth_accounts_by_user(current_user.id)
    
    target_account = None
    for account in oauth_accounts:
        if account.provider == provider:
            target_account = account
            break
    
    if not target_account:
        if request.is_json:
            return jsonify({'error': f'No linked {provider} account found'}), 404
        flash(f'No linked {provider.capitalize()} account found', 'error')
        return redirect(url_for('auth.profile'))
    
    account_service.delete_oauth_account(target_account.id)
    logger.info(f'User {current_user.username} unlinked {provider} OAuth account')
    
    if request.is_json:
        return jsonify({'message': f'{provider.capitalize()} account unlinked successfully'})
    
    flash(f'{provider.capitalize()} account unlinked successfully', 'success')
    return redirect(url_for('auth.profile'))


@oauth_bp.route('/accounts')
def list_accounts():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    from app.services.oauth_account_service import OAuthAccountService
    
    account_service = OAuthAccountService()
    oauth_accounts = account_service.get_oauth_accounts_by_user(current_user.id)
    accounts_data = [account.to_dict() for account in oauth_accounts]
    
    return jsonify({
        'accounts': accounts_data,
        'count': len(accounts_data)
    })


@oauth_bp.route('/providers')
def list_providers():
    oauth_service = OAuthService()
    providers = oauth_service.get_enabled_providers_info()
    
    return jsonify({
        'providers': list(providers.values()),
        'count': len(providers)
    })
