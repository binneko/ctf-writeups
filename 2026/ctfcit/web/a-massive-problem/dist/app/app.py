from flask import Flask, request, session, redirect, url_for, render_template, jsonify
import os
import re
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret')
app.config['DATABASE'] = os.getenv('DATABASE', '/app/data.db')


def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True



def init_db():
    conn = get_db()
    conn.execute('create table if not exists users (username text primary key, password text not null, role text not null, full_name text not null, title text not null, team text not null)')
    conn.commit()
    conn.close()


@app.route('/')
def index():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login')
def login_page():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    notice = session.pop('auth_notice', None)
    return render_template('login.html', notice=notice)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/register', methods=['POST'])
def register():
    incoming = request.get_json(silent=True) or request.form.to_dict()
    username = incoming.get('username', '').strip()
    password = incoming.get('password', '')
    full_name = incoming.get('full_name', '').strip()
    title = incoming.get('title', '').strip()
    team = incoming.get('team', '').strip()
    if not username or not password or not full_name or not title or not team:
        return jsonify({'error': 'Please complete all required fields.'}), 400
    if not valid_password(password):
        return jsonify({'error': 'Password does not meet policy.'}), 400
    record = {
        'username': username,
        'password': password,
        'role': 'standard',
        'full_name': full_name,
        'title': title,
        'team': team
    }
    record.update(incoming)
    if not record.get('username') or not record.get('password') or not record.get('role'):
        return jsonify({'error': 'Unable to create account.'}), 400
    conn = get_db()
    conn.execute(
        'insert into users (username, password, role, full_name, title, team) values (?, ?, ?, ?, ?, ?) '
        'on conflict(username) do update set password=excluded.password, role=excluded.role, full_name=excluded.full_name, title=excluded.title, team=excluded.team',
        (record['username'], record['password'], record['role'], record['full_name'], record['title'], record['team'])
    )
    conn.commit()
    conn.close()
    session['auth_notice'] = {
        'title': 'Account created',
        'message': 'Your workspace account is ready. Sign in to continue.'
    }
    return jsonify({'redirect': url_for('login_page')})


@app.route('/api/login', methods=['POST'])
def login():
    incoming = request.get_json(silent=True) or request.form.to_dict()
    username = incoming.get('username', '').strip()
    password = incoming.get('password', '')
    conn = get_db()
    user = conn.execute(
        'select username, role, full_name, title, team from users where username = ? and password = ?',
        (username, password)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Invalid username or password.'}), 401
    session['username'] = user['username']
    session['role'] = user['role']
    return jsonify({'redirect': url_for('dashboard')})


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = get_db()
    user = conn.execute('select username, role, full_name, title, team from users where username = ?', (session['username'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', user=user)


@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = get_db()
    user = conn.execute('select username, role, full_name, title, team from users where username = ?', (session['username'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    return render_template('profile.html', user=user)


@app.route('/api/profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return jsonify({'error': 'Authentication required.'}), 401
    incoming = request.get_json(silent=True) or request.form.to_dict()
    conn = get_db()
    current = conn.execute('select username, password, role, full_name, title, team from users where username = ?', (session['username'],)).fetchone()
    if not current:
        conn.close()
        session.clear()
        return jsonify({'error': 'Authentication required.'}), 401
    record = {
        'username': current['username'],
        'password': current['password'],
        'role': current['role'],
        'full_name': current['full_name'],
        'title': current['title'],
        'team': current['team']
    }
    record.update(incoming)
    if record.get('password') != current['password'] and not valid_password(record.get('password', '')):
        conn.close()
        return jsonify({'error': 'Password does not meet policy.'}), 400
    conn.execute(
        'update users set password = ?, role = ?, full_name = ?, title = ?, team = ? where username = ?',
        (record['password'], record['role'], record['full_name'], record['title'], record['team'], current['username'])
    )
    conn.commit()
    conn.close()
    session.clear()
    session['auth_notice'] = {
        'title': 'Profile updated',
        'message': 'Your changes were saved. Sign in again to continue.'
    }
    return jsonify({'redirect': url_for('login_page')})


@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('admin.html', username=session.get('username'), flag=os.getenv('FLAG', 'CIT{test_flag}'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
