#!/usr/bin/env python3
"""
HTTP Honeypot Module
"""
from flask import Flask, request, Response, send_file
from pathlib import Path
import time
import logging

WORDPRESS_TEMPLATE = {
    "title": "WordPress Site",
    "admin_path": "/wp-admin",
    "login_path": "/wp-login.php",
    "version": "WordPress 6.4.3",
    "headers": {"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "PHP/8.2.12"},
}

def create_flask_app(args, logger):
    app = Flask(__name__)
    template = WORDPRESS_TEMPLATE

    @app.before_request
    def before_request():
        time.sleep(0.3)  # simulate delay
        
        # log the req
        client_ip = request.remote_addr
        extra = {
            'ip': client_ip,
            'port': args.http_port,
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
        }
        
        # suspicious activity
        is_suspicious = False
        suspicious_paths = ['/wp-admin', '/wp-login', '/admin', '/shell', '/cmd']
        path_lower = request.path.lower()
        
        for path in suspicious_paths:
            if path in path_lower:
                is_suspicious = True
                extra['suspicious_paths'] = path
                break
        
        # check for SQL injection
        query_string = request.query_string.decode('utf-8', errors='ignore').lower()
        sql_patterns = ["' or '1'='1", "' or 1=1--", "union select", "select * from"]
        
        for pattern in sql_patterns:
            if pattern in query_string:
                is_suspicious = True
                extra['sql_injection'] = pattern
                break
        
        if is_suspicious:
            logger.info(
                f"Suspicious HTTP request - IP: {client_ip}, "
                f"Method: {request.method}, Path: {request.path}",
                extra=extra
            )
        else:
            logger.info(
                f"HTTP request - IP: {client_ip}, "
                f"Method: {request.method}, Path: {request.path}",
                extra=extra
            )

    @app.route('/', methods=['GET', 'POST'])
    def index():
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{template['title']}</title>
            <link rel="stylesheet" href="/wp-content/themes/twentyTwenty/style.css">
        </head>
        <body>
            <div class="wp-site-blocks">
                <main>
                    <article>
                        <h2>Hello world!</h2>
                        <p>Welcome to WordPress. This is your first post</p>
                        <p><a href="{template['login_path']}">Log in</a></p>
                    </article>
                </main>
                <footer>Powered by {template['version']}</footer>
            </div>
        </body>
        </html>
        """
        
        response = Response(html, mimetype='text/html')
        for key, value in template['headers'].items():
            response.headers[key] = value
        return response

    @app.route('/logo.png')
    def serve_logo():
        current_path = Path(__file__).resolve() 
        project_root = current_path.parent.parent
        images_dir = project_root / "images"
        logo_path = images_dir / "logo.png"  
        
        if not logo_path.exists():
            raise FileNotFoundError("logo.png not found in /images directory")
        
        return send_file(str(logo_path), mimetype='image/png')

    @app.route('/wp-login.php', methods=['GET', 'POST'])
    def login_page():
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            # log login attempt
            extra = {
                'ip': request.remote_addr,
                'username': username,
                'password': password,
                'login_page': request.path,
            }
            
            logger.info(
                f"HTTP Login attempt - IP: {request.remote_addr}, "
                f"Username: '{username}', Password: '{password}'",
                extra=extra
            )
            
            # always return invalid credentials
            return """
            <div style="margin: 40px; padding: 20px; border: 1px solid #f00; background: #fee;">
                <h3>Login Error</h3>
                <p>The username or password you entered is incorrect.</p>
                <p><a href="/wp-login.php">Try again</a></p>
            </div>
            """, 401
        
        # show login form
        html = """
        <!DOCTYPE html>
        <html lang="en-US">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>Log In &lsaquo; WordPress &mdash; WordPress</title>
            <meta name='robots' content='max-image-preview:large, noindex, noarchive'>
            <link rel='stylesheet' id='dashicons-css' href='https://wordpress.org/wp-includes/css/dashicons.min.css' type='text/css' media='all'>
            <link rel='stylesheet' id='buttons-css' href='https://wordpress.org/wp-includes/css/buttons.min.css' type='text/css' media='all'>
            <link rel='stylesheet' id='forms-css' href='https://wordpress.org/wp-admin/css/forms.min.css' type='text/css' media='all'>
            <link rel='stylesheet' id='l10n-css' href='https://wordpress.org/wp-admin/css/l10n.min.css' type='text/css' media='all'>
            <link rel='stylesheet' id='login-css' href='https://wordpress.org/wp-admin/css/login.min.css' type='text/css' media='all'>
            <meta name='referrer' content='strict-origin-when-cross-origin'>
            <meta name="viewport" content="width=device-width">
            <style>
                /* Additional custom styling to perfect the look */
                .login h1 a {
                    background-image: url('/logo.png');
                    background-size: contain;
                    background-repeat: no-repeat;
                    background-position: center;
                    width: 84px;
                    height: 84px;
                }
            </style>
        </head>
        <body class="login no-js login-action-login wp-core-ui locale-en-us">
        <script type="text/javascript">document.body.className = document.body.className.replace('no-js','js');</script>
        
        <div id="login">
            <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
            
            <form name="loginform" id="loginform" action="/wp-login.php" method="post">
                <p>
                    <label for="user_login">Username or Email Address</label>
                    <input type="text" name="username" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required>
                </p>
                
                <div class="user-pass-wrap">
                    <label for="user_pass">Password</label>
                    <div class="wp-pwd">
                        <input type="password" name="password" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" required>
                        <button type="button" class="button button-secondary wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
                            <span class="dashicons dashicons-visibility" aria-hidden="true"></span>
                        </button>
                    </div>
                </div>
                
                <p class="forgetmenot">
                    <input name="rememberme" type="checkbox" id="rememberme" value="forever">
                    <label for="rememberme">Remember Me</label>
                </p>
                
                <p class="submit">
                    <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
                    <input type="hidden" name="redirect_to" value="/wp-admin/">
                    <input type="hidden" name="testcookie" value="1">
                </p>
            </form>
            
            <p id="nav">
                <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
            </p>
            
            <p id="backtoblog">
                <a href="/">&larr; Go to Site</a>
            </p>
        </div>
        
        <script type='text/javascript' src='https://wordpress.org/wp-includes/js/jquery/jquery.min.js'></script>
        <script type='text/javascript'>
            (function(){
                var showButton = document.querySelector('.wp-hide-pw');
                var passwordInput = document.getElementById('user_pass');
                
                if (showButton && passwordInput) {
                    showButton.addEventListener('click', function() {
                        if (passwordInput.type === 'password') {
                            passwordInput.type = 'text';
                            showButton.querySelector('.dashicons').classList.remove('dashicons-visibility');
                            showButton.querySelector('.dashicons').classList.add('dashicons-hidden');
                            showButton.setAttribute('aria-label', 'Hide password');
                        } else {
                            passwordInput.type = 'password';
                            showButton.querySelector('.dashicons').classList.remove('dashicons-hidden');
                            showButton.querySelector('.dashicons').classList.add('dashicons-visibility');
                            showButton.setAttribute('aria-label', 'Show password');
                        }
                    });
                }
            })();
        </script>
        
        <div class="clear"></div>
        </body>
        </html>
        """
        
        response = Response(html, mimetype='text/html')
        for key, value in template['headers'].items():
            response.headers[key] = value
        return response

    @app.route('/wp-admin', methods=['GET'])
    def admin_page():
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WordPress Admin • {template['title']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; background: #f1f1f1; }}
                .wp-admin-bar {{ background: #23282d; color: white; padding: 15px; }}
                .admin-content {{ padding: 20px; }}
                .notice {{ background: #fff; border-left: 4px solid #00a0d2; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="wp-admin-bar">
                <strong>WordPress Admin</strong> • {template['title']}
            </div>
            <div class="admin-content">
                <h2>Dashboard</h2>
                <div class="notice">
                    <p>Please log in to access the WordPress admin area.</p>
                    <p><a href="/wp-login.php">Log in here</a></p>
                </div>
            </div>
        </body>
        </html>
        """
            
        response = Response(html, mimetype='text/html')
        for key, value in template['headers'].items():
            response.headers[key] = value
        return response

    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    def catch_all(path):
        # return 404 for rest of paths
        return "404 - Page not found", 404

    return app

def start_http_honeypot(args, logger):
    app = create_flask_app(args, logger)
    
    # Disable Flask logging
    flask_log = logging.getLogger('werkzeug')
    flask_log.setLevel(logging.ERROR)
    
    # run flask in dev mode
    try:
        app.run(
            host='0.0.0.0',
            port=args.http_port,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    except Exception as e:
        logger.error(f"Failed to start HTTP honeypot: {e}")