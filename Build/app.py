from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import hashlib

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""  # Set your MySQL root password
app.config["MYSQL_DB"] = "certificate_system"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    
    if user_data:
        return User(user_data["id"], user_data["name"], user_data["email"])
    return None

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        sslc_school = request.form['sslc_school']
        sslc_percentage = request.form['sslc_percentage']
        puc_college = request.form['puc_college']
        puc_percentage = request.form['puc_percentage']
        graduation_college = request.form['graduation_college']
        graduation_percentage = request.form['graduation_percentage']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for('login'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (name, email, password_hash, sslc_school, sslc_percentage, puc_college, puc_percentage, graduation_college, graduation_percentage) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", 
            (name, email, password_hash, sslc_school, sslc_percentage, puc_college, puc_percentage, graduation_college, graduation_percentage)
        )
        mysql.connection.commit()
        cursor.close()

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template("signup.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        cursor.close()

        if user_data and bcrypt.check_password_hash(user_data["password_hash"], password):
            user = User(user_data["id"], user_data["name"], user_data["email"])
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route('/dashboard')
@login_required
def dashboard():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, name, course, date, status, cert_hash, txn_hash FROM certificate_requests WHERE user_id = %s", (current_user.id,))
    requests = cursor.fetchall()
    cursor.close()

    print("Fetched Certificate Requests:", requests)  # Debugging Line

    return render_template("dashboard.html", requests=requests, name=current_user.name)


@app.route('/request_certificate', methods=['GET', 'POST'])
@login_required
def request_certificate():
    if request.method == 'POST':
        name = request.form['name']
        course = request.form['course']
        date = request.form['date']

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO certificate_requests (user_id, name, course, date, status) VALUES (%s, %s, %s, %s, 'Pending')", 
                       (current_user.id, name, course, date))
        mysql.connection.commit()
        cursor.close()

        flash("Certificate request submitted successfully! Awaiting admin approval.", "success")
        return redirect(url_for('dashboard'))

    return render_template("request_certificate.html")


from flask import request, jsonify  # Import jsonify

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    try:
        cert_hash = request.form.get('cert_hash')

        if not cert_hash:
            return jsonify({'status': 'error', 'message': 'No certificate hash provided!'})

        print(f"🔍 Verifying certificate hash: {cert_hash}")

        is_valid = contract.functions.verifyCertificate(cert_hash).call()

        print(f"✅ Blockchain Response: {is_valid}")

        if is_valid:
            return jsonify({'status': 'valid', 'message': '✅ Certificate is VALID on the Blockchain!'})
        else:
            return jsonify({'status': 'invalid', 'message': '❌ Certificate NOT FOUND on Blockchain!'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Blockchain Error: {str(e)}'})

from flask_login import login_required, current_user

@app.route('/user_profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        sslc_school = request.form['sslc_school']
        puc_college = request.form['puc_college']
        graduation_college = request.form['graduation_college']
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
        user = cursor.fetchone()

        # ✅ Update Basic Info
        cursor.execute("""
            UPDATE users SET name = %s, email = %s, sslc_school = %s, puc_college = %s, graduation_college = %s 
            WHERE id = %s
        """, (name, email, sslc_school, puc_college, graduation_college, current_user.id))

        # ✅ Check if a new password is entered
        if new_password.strip():
            # Verify the current password first
            if not bcrypt.check_password_hash(user['password_hash'], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('user_profile'))
            
            # Hash the new password
            password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # ✅ Update password in DB
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, current_user.id))

        # ✅ Commit changes
        mysql.connection.commit()
        cursor.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('user_profile'))

    # ✅ Fetch user details
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
    user = cursor.fetchone()
    cursor.close()

    return render_template("user_profile.html", user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for('login'))


################# Admin Side #########################

@app.route('/admin_signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
        existing_admin = cursor.fetchone()

        if existing_admin:
            flash("Email already registered as admin. Please log in.", "danger")
            return redirect(url_for('admin_login'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO admins (name, email, password_hash) VALUES (%s, %s, %s)", 
                       (name, email, password_hash))
        mysql.connection.commit()
        cursor.close()

        flash("Admin signup successful! Please log in.", "success")
        return redirect(url_for('admin_login'))

    return render_template("admin_signup.html")

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
        admin_data = cursor.fetchone()
        cursor.close()

        if admin_data and bcrypt.check_password_hash(admin_data["password_hash"], password):
            session['admin_id'] = admin_data["id"]
            session['admin_name'] = admin_data["name"]
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))

        flash("Invalid email or password.", "danger")

    return render_template("admin_login.html")

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in as admin first.", "danger")
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM certificate_requests WHERE status = %s", ("Pending",))
    pending_requests = cursor.fetchall()
    cursor.close()

    return render_template("admin_dashboard.html", requests=pending_requests)

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import MySQLdb.cursors

@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if 'admin_id' not in session:
        flash("Please log in as admin first.", "danger")
        return redirect(url_for('admin_login'))

    admin_id = session['admin_id']

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
        admin = cursor.fetchone()

        # Verify current password
        if not bcrypt.check_password_hash(admin['password_hash'], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for('admin_profile'))

        # Update name and email
        cursor.execute("UPDATE admins SET name = %s, email = %s WHERE id = %s", 
                       (name, email, admin_id))

        # Update password if new password is provided
        if new_password:
            password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE admins SET password_hash = %s WHERE id = %s", 
                           (password_hash, admin_id))

        mysql.connection.commit()
        cursor.close()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('admin_profile'))

    # Fetch admin details for display
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
    admin = cursor.fetchone()
    cursor.close()

    return render_template("admin_profile.html", admin=admin)

@app.route('/view_all_requests')
def view_all_requests():
    # Check if admin is logged in
    if 'admin_id' not in session:
        flash("Please log in as admin first.", "danger")
        return redirect(url_for('admin_login'))

    # Fetch all certificate requests
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM certificate_requests")
    all_requests = cursor.fetchall()
    cursor.close()

    return render_template("view_all_requests.html", requests=all_requests)

from web3 import Web3
import json

# Connect to Ganache
ganache_url = "HTTP://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

if not web3.is_connected():
    print("Failed to connect to Ganache!")

# Load compiled contract
with open("compiled_contract.json", "r") as file:
    compiled_contract = json.load(file)

contract_abi = compiled_contract["contracts"]["CertificateRegistry.sol"]["CertificateRegistry"]["abi"]

# Load contract address
with open("contract_address.txt", "r") as file:
    contract_address = file.read().strip()

# Load the smart contract
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Admin address from Ganache
admin_address = web3.eth.accounts[0]

# @app.route('/approve_certificate/<int:request_id>')
# def approve_certificate(request_id):
#     if 'admin_id' not in session:
#         flash("Please log in as admin first.", "danger")
#         return redirect(url_for('admin_login'))

#     cursor = mysql.connection.cursor()
#     cursor.execute("SELECT user_id, name, course, date FROM certificate_requests WHERE id = %s", (request_id,))
#     cert_data = cursor.fetchone()

#     if not cert_data:
#         flash("Certificate request not found.", "danger")
#         return redirect(url_for('admin_dashboard'))

#     user_id, name, course, date = cert_data

#     # ✅ Use request_id to make hash unique
#     cert_hash = hashlib.sha256(f"{request_id}{user_id}{name}{course}{date}".encode()).hexdigest()

#     print(f"Generated Hash for Request {request_id}: {cert_hash}")  # Debugging line

#     # Store on Blockchain
#     try:
#         txn_hash = contract.functions.issueCertificate(name, course, cert_hash).transact({'from': web3.eth.accounts[0]})
#         receipt = web3.eth.wait_for_transaction_receipt(txn_hash)

#         # ✅ Store cert_hash and blockchain transaction hash in MySQL
#         txn_hash_hex = txn_hash.hex()  # Convert to readable format
#         cursor.execute("UPDATE certificate_requests SET status='Approved', cert_hash=%s, txn_hash=%s WHERE id=%s",
#                        (cert_hash, txn_hash_hex, request_id))
#         mysql.connection.commit()

#         flash("✅ Certificate Approved & Stored on Blockchain!", "success")
#     except Exception as e:
#         flash(f"❌ Blockchain Error: {str(e)}", "danger")
    
#     cursor.close()
#     return redirect(url_for('admin_dashboard'))

@app.route('/approve_certificate/<int:request_id>')
def approve_certificate(request_id):
    if 'admin_id' not in session:
        flash("Please log in as admin first.", "danger")
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id, name, course, date FROM certificate_requests WHERE id = %s", (request_id,))
    cert_data = cursor.fetchone()

    if not cert_data:
        flash("Certificate request not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    user_id, name, course, date = cert_data

    # ✅ Use request_id to make hash unique
    cert_hash = hashlib.sha256(f"{request_id}{user_id}{name}{course}{date}".encode()).hexdigest()

    print(f"Generated Hash for Request {request_id}: {cert_hash}")  # Debugging line

    # Store on Blockchain
    try:
        txn_hash = contract.functions.issueCertificate(name, course, cert_hash).transact({'from': web3.eth.accounts[0]})
        receipt = web3.eth.wait_for_transaction_receipt(txn_hash)

        # ✅ Store cert_hash and blockchain transaction hash in MySQL
        txn_hash_hex = txn_hash.hex()  # Convert to readable format
        cursor.execute("UPDATE certificate_requests SET status='Approved', cert_hash=%s, txn_hash=%s WHERE id=%s",
                       (cert_hash, txn_hash_hex, request_id))
        mysql.connection.commit()

        flash("✅ Certificate Approved & Stored on Blockchain!", "success")
    except Exception as e:
        flash(f"❌ Blockchain Error: {str(e)}", "danger")
    
    cursor.close()
    return redirect(url_for('admin_dashboard'))  # Fixed the incomplete function return



@app.route('/reject_certificate/<int:request_id>')
def reject_certificate(request_id):
    if 'admin_id' not in session:
        flash("Please log in as admin first.", "danger")
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE certificate_requests SET status='Rejected' WHERE id=%s", (request_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Certificate Rejected!", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    flash("You have logged out as admin.", "info")
    return redirect(url_for('admin_login'))


#################################################

from flask import send_file, flash, redirect, url_for
import os
from generate_certificate import create_certificate_pdf

@app.route('/generate_certificate/<cert_hash>')
def generate_and_download_certificate(cert_hash):
    """Generate and allow download of the certificate PDF."""
    try:
        print(f"📝 Received cert_hash: {cert_hash}")  # Debugging

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT name, course, date, cert_path FROM certificate_requests WHERE cert_hash = %s", (cert_hash,))
        cert_data = cursor.fetchone()
        cursor.close()

        if not cert_data:
            flash("❌ Certificate not found!", "danger")
            print(f"❌ Error: No data for cert_hash {cert_hash}")
            return redirect(url_for('dashboard'))  # ✅ Fixed

        name, course, date, cert_path = cert_data['name'], cert_data['course'], cert_data['date'], cert_data['cert_path']

        # Debugging: Print values
        print(f"🔍 DB Data -> Name: {name}, Course: {course}, Date: {date}, Cert_Path: {cert_path}")

        # Ensure the file exists
        if cert_path and os.path.exists(cert_path):
            print(f"✅ Certificate found: {cert_path}")
            return send_file(cert_path, as_attachment=True)

        print("⚠️ Certificate file missing, regenerating...")

        # Regenerate the certificate
        cert_dir = "certificates"
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        new_cert_path = os.path.join(cert_dir, f"{cert_hash}.pdf").replace("\\", "/")

        # Generate certificate
        create_certificate_pdf(name, course, date, cert_hash)

        # Ensure the file was created
        if not os.path.exists(new_cert_path):
            flash("❌ Error: Certificate file not created!", "danger")
            print(f"❌ File missing after generation: {new_cert_path}")
            return redirect(url_for('dashboard'))  # ✅ Fixed

        # Update database with new path
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE certificate_requests SET cert_path=%s WHERE cert_hash=%s", (new_cert_path, cert_hash))
        mysql.connection.commit()
        cursor.close()

        print(f"✅ Certificate generated successfully: {new_cert_path}")
        return send_file(new_cert_path, as_attachment=True)

    except Exception as e:
        flash(f"❌ Error: {str(e)}", "danger")
        print(f"❌ Exception: {str(e)}")
        return redirect(url_for('dashboard'))  # ✅ Fixed
    
    
###########################################
@app.route('/explorer/<txn_hash>')
def blockchain_explorer(txn_hash):
    try:
        txn_details = web3.eth.get_transaction(txn_hash)
        receipt = web3.eth.get_transaction_receipt(txn_hash)

        print(f"✅ Found Transaction: {txn_hash}")  # Debugging
        print("Transaction Details:", txn_details)  # Debugging
        print("Transaction Receipt:", receipt)  # Debugging

        return render_template('explorer.html', txn=txn_details, receipt=receipt)

    except Exception as e:
        print(f"❌ Error Fetching Transaction: {txn_hash}, Error: {e}")  # Debugging
        flash(f"❌ Transaction not found: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
