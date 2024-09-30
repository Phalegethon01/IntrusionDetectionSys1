# from flask import Flask, render_template, redirect, url_for, request, session
# from ids import start_ids, stop_ids
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
            
#             # Stopping IDS
#             if action == 'Stop':
#                 try:
#                     stop_ids()
#                     current_ip = None  # Clear current IP when stopping IDS
#                 except Exception as e:
#                     return render_template('index.html', user=session['username'], current_ip=current_ip, error=f"Error stopping IDS: {e}")
            
#             # Starting IDS
#             elif action == 'Start':
#                 ip_address = request.form['ip_address']
#                 if ip_address:
#                     try:
#                         start_ids(ip_address)
#                         current_ip = ip_address  # Update current IP on successful start
#                     except Exception as e:
#                         return render_template('index.html', user=session['username'], current_ip=current_ip, error=f"Error starting IDS: {e}")
#                 else:
#                     return render_template('index.html', user=session['username'], current_ip=current_ip, error="IP address is required to start IDS.")
            
#             return redirect(url_for('dashboard'))
        
#         # Read alerts from log file
#         alerts = []
#         if os.path.exists("alerts.log"):
#             with open("alerts.log", "r") as f:
#                 alerts = f.readlines()
        
#         # Reverse to show the latest alerts first
#         alerts = alerts[::-1]
        
#         return render_template('index.html', user=session['username'], current_ip=current_ip, alerts=alerts)
    
#     return redirect(url_for('login'))

# @app.route('/logout', methods=['POST'])
# def logout():
#     global current_ip
#     if 'username' in session:
#         try:
#             stop_ids()  # Stop IDS on logout
#         except Exception as e:
#             print(f"Error stopping IDS during logout: {e}")
    
#     session.pop('username', None)
#     session.pop('ip_address', None)
#     current_ip = None  # Reset current IP on logout
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)




from flask import Flask, render_template, redirect, url_for, request, session
from ids import start_ids, stop_ids  # Import from the IDS file
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Mock user database
users = {
    "testuser": "password123"
}

# Global variable to keep track of the currently monitored IP
current_ip = None

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return render_template('signup.html', error="Username already exists")
        users[username] = password
        session['username'] = username
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    global current_ip
    if 'username' in session:
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'Stop':
                print("Stop button pressed.")  # Debugging info
                try:
                    stop_ids()  # Attempt to stop the IDS
                    current_ip = None
                    print("IDS stopped successfully.")  # More debugging info
                except Exception as e:
                    print(f"Error stopping IDS: {e}")
                    return render_template('index.html', error=f"Error stopping IDS: {str(e)}")
                
            elif action == 'Start':
                ip_address = request.form['ip_address']
                if ip_address:
                    try:
                        start_ids(ip_address)  # Start IDS monitoring
                        current_ip = ip_address
                        print(f"Started monitoring IP: {ip_address}")
                    except Exception as e:
                        print(f"Error starting IDS: {e}")
                        return render_template('index.html', error=f"Error starting IDS: {str(e)}")
                else:
                    return render_template('index.html', error="No IP address provided.")
            
            return redirect(url_for('dashboard'))

        # Read alerts from log file
        alerts = []
        if os.path.exists("alerts.log"):
            with open("alerts.log", "r") as f:
                alerts = f.readlines()
        
        alerts = alerts[::-1]  # Reverse alerts to show latest first
        
        return render_template('index.html', user=session['username'], current_ip=current_ip, alerts=alerts)
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        stop_ids()
    session.pop('username', None)
    session.pop('ip_address', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
