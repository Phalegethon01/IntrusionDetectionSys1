# from flask import Flask, render_template, redirect, url_for, request, session
# from ids import start_ids, stop_ids  # Import from the IDS file
# import os

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'

# # Mock user database
# users = {
#     "testuser": "password123"
# }

# # Global variable to keep track of the currently monitored IP
# current_ip = None

# @app.route('/')
# def index():
#     if 'username' in session:
#         return redirect(url_for('dashboard'))
#     return redirect(url_for('login'))

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         if username in users and users[username] == password:
#             session['username'] = username
#             return redirect(url_for('dashboard'))
#         else:
#             return render_template('login.html', error="Invalid username or password")
#     return render_template('login.html')

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         if username in users:
#             return render_template('signup.html', error="Username already exists")
#         users[username] = password
#         session['username'] = username
#         return redirect(url_for('dashboard'))
#     return render_template('signup.html')

# @app.route('/dashboard', methods=['GET', 'POST'])
# def dashboard():
#     global current_ip
#     if 'username' in session:
#         if request.method == 'POST':
#             action = request.form.get('action')
            
#             if action == 'Stop':
#                 print("Stop button pressed.")  # Debugging info
#                 try:
#                     stop_ids()  # Attempt to stop the IDS
#                     current_ip = None
#                     print("IDS stopped successfully.")  # More debugging info
#                 except Exception as e:
#                     print(f"Error stopping IDS: {e}")
#                     return render_template('index.html', error=f"Error stopping IDS: {str(e)}")
                
#             elif action == 'Start':
#                 ip_address = request.form['ip_address']
#                 if ip_address:
#                     try:
#                         start_ids(ip_address)  # Start IDS monitoring
#                         current_ip = ip_address
#                         print(f"Started monitoring IP: {ip_address}")
#                     except Exception as e:
#                         print(f"Error starting IDS: {e}")
#                         return render_template('index.html', error=f"Error starting IDS: {str(e)}")
#                 else:
#                     return render_template('index.html', error="No IP address provided.")
            
#             return redirect(url_for('dashboard'))

#         # Read alerts from log file
#         alerts = []
#         if os.path.exists("alerts.log"):
#             with open("alerts.log", "r") as f:
#                 alerts = f.readlines()
        
#         alerts = alerts[::-1]  # Reverse alerts to show latest first
        
#         return render_template('index.html', user=session['username'], current_ip=current_ip, alerts=alerts)
#     return redirect(url_for('login'))

# @app.route('/logout', methods=['POST'])
# def logout():
#     if 'username' in session:
#         stop_ids()
#     session.pop('username', None)
#     session.pop('ip_address', None)
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)


# from flask import Flask, render_template, redirect, url_for, request, session
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
# import os
# from ids import start_ids, stop_ids  # Import IDS functions
# from passlib.hash import sha256_crypt

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'

# # Database Configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)

# # Database Model for Users
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(150), unique=True, nullable=False)
#     password_hash = db.Column(db.String(150), nullable=False)

# # Create the database and tables
# with app.app_context():
#     db.create_all()

# # Global variable to keep track of the currently monitored IP
# current_ip = None

# @app.route('/')
# def index():
#     if 'username' in session:
#         return redirect(url_for('dashboard'))
#     return redirect(url_for('login'))

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
        
#         # Check if username already exists
#         existing_user = User.query.filter_by(username=username).first()
#         if existing_user:
#             return render_template('signup.html', error="Username already exists")
        
#         # Hash the password before saving it in the database
#         # hashed_password = generate_password_hash(password, method='sha256')
#         hashed_password = sha256_crypt.hash(password)
#         new_user = User(username=username, password_hash=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
        
#         session['username'] = username
#         return redirect(url_for('dashboard'))
    
#     return render_template('signup.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
        
#         # Check if user exists in the database
#         user = User.query.filter_by(username=username).first()
        
#         # Verify if the entered password matches the stored hashed password
#         if user and check_password_hash(user.password_hash, password):
#             session['username'] = username
#             return redirect(url_for('dashboard'))
#         else:
#             return render_template('login.html', error="Invalid username or password")
    
#     return render_template('login.html')

# @app.route('/dashboard', methods=['GET', 'POST'])
# def dashboard():
#     global current_ip
#     if 'username' in session:
#         if request.method == 'POST':
#             action = request.form.get('action')
#             if action == 'Stop':
#                 stop_ids()
#                 current_ip = None
#             elif action == 'Start':
#                 ip_address = request.form['ip_address']
#                 start_ids(ip_address)
#                 current_ip = ip_address
#             return redirect(url_for('dashboard'))

#         # Read alerts from log file
#         alerts = []
#         if os.path.exists("alerts.log"):
#             with open("alerts.log", "r") as f:
#                 alerts = f.readlines()

#         alerts = alerts[::-1]  # Show latest alerts first
#         return render_template('index.html', user=session['username'], current_ip=current_ip, alerts=alerts)
#     return redirect(url_for('login'))

# @app.route('/logout', methods=['POST'])
# def logout():
#     if 'username' in session:
#         stop_ids()
#     session.pop('username', None)
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)



from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from ids import start_ids, stop_ids  # Import IDS functions

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model for Users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# Global variable to keep track of the currently monitored IP
current_ip = None

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('signup.html', error="Username already exists")
        
        # Hash the password using Werkzeug
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        session['username'] = username
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user exists in the database
        user = User.query.filter_by(username=username).first()
        
        # Verify if the entered password matches the stored hashed password
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    global current_ip
    if 'username' in session:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'Stop':
                # stop_ids()
                # current_ip = None

                print("Stop button pressed.")  # Debugging info
                try:
                    stop_ids()  # Attempt to stop the IDS
                    current_ip = None
                    print("IDS stopped successfully.")
                except Exception as e:
                    print(f"Error stopping IDS: {e}")
                    return render_template('index.html', error=f"Error stopping IDS: {str(e)}")

            elif action == 'Start':
                ip_address = request.form['ip_address']
                start_ids(ip_address)
                current_ip = ip_address
            return redirect(url_for('dashboard'))

        # Read alerts from log file
        alerts = []
        if os.path.exists("alerts.log"):
            with open("alerts.log", "r") as f:
                alerts = f.readlines()

        alerts = alerts[::-1]  # Show latest alerts first
        return render_template('index.html', user=session['username'], current_ip=current_ip, alerts=alerts)
    return redirect(url_for('login'))

# Logout Route
@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        stop_ids()
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
