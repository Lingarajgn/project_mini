from flask import Flask, flash, request, jsonify, render_template, redirect, url_for, session 
from flask_cors import CORS
from pymongo import MongoClient
from flask_mail import Mail, Message
from bson import ObjectId
from bson.objectid import ObjectId
import random
import string
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
import uuid

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = "lingarajgn1108"  # Add a secret key for session management
CORS(app)



app.permanent_session_lifetime = timedelta(hours=1)  # Set session lifetime to 1 hour

# MongoDB Configuration
client = MongoClient("mongodb+srv://lingarajgn45:1plpD2mXPql7nw29@cluster0.xt9rd.mongodb.net/")
db = client["userd"]
users_collection = db["users"]
tasks_collection = db["tasks"]
routine_collection = db["routine"]

bcrypt = Bcrypt(app)

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp-relay.brevo.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '817f29001@smtp-brevo.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = '1VbyndjB7Ok9D4Kq'  # Replace with your email password
mail = Mail(app)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def check_session_expiry():
    if 'user' not in session:
        flash("Your session has expired. Please log in again.", "error")
        return redirect(url_for('login_page'))
    return None

@app.before_request
def enforce_session_expiry():
    protected_routes = ['/index', '/task', '/routine']
    if request.path in protected_routes:
        session_check = check_session_expiry()
        if session_check:  # Redirect to login if session is expired
            return session_check

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]
        user = users_collection.find_one({"email": email})
        if user:
            otp = generate_otp()
            session["otp"] = otp
            session["reset_email"] = email
            msg = Message("Password Reset OTP", sender="lingarajgn45@gmail.com", recipients=[email])
            msg.body = f"Your OTP is {otp}."
            mail.send(msg)
            return redirect(url_for("reset_password"))
        flash("Email not found.", "error")
    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        otp = int(request.form["otp"])
        if otp == session.get("otp"):
            new_password = generate_password_hash(request.form["new_password"])
            email = session.get("reset_email")
            users_collection.update_one({"email": email}, {"$set": {"password": new_password}})
            flash("Password updated successfully. Please log in.", "success")
            return redirect(url_for("login_page"))
        else:
            flash("Invalid OTP.", "error")
    return render_template("reset_password.html")

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/index')
def index_page():
    session_check = check_session_expiry()
    if session_check:
        return session_check
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid email or password"}), 401

    session['user'] = user['name']
    return jsonify({"redirect_url": "/index"}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not name or not email or not password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"name": name, "email": email, "password": hashed_password})

    return jsonify({"message": "Registration successful"}), 201

@app.route("/get_username", methods=["GET"])
def get_username():
    user_name = session.get("user")
    if not user_name:
        return jsonify({"error": "User not logged in"}), 401
    return jsonify({"username": user_name}), 200

# Task Routes
@app.route('/task', methods=['GET'])
def task_page():
    session_check = check_session_expiry()
    if session_check:
        return session_check

    user_name = session.get('user')
    tasks = list(tasks_collection.find({"username": user_name}, {"_id": 0}))
    return render_template("task.html", tasks=tasks)

@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    user_name = session.get('user')
    if request.method == 'GET':
        if not user_name:
            return jsonify({"error": "User not logged in"}), 401

        tasks = list(tasks_collection.find({"username": user_name}, {"_id": 0}))
        return jsonify(tasks), 200

    elif request.method == 'POST':
        data = request.json
        task_name = data.get('taskName')
        deadline = data.get('deadline')
        priority = data.get('priority')

        if not task_name or not deadline:
            return jsonify({"error": "Task name and deadline are required"}), 400

        task_data = {
            "taskName": task_name,
            "deadline": deadline,
            "priority": priority,
            "username": user_name
        }

        tasks_collection.insert_one(task_data)
        return jsonify({"message": "Task added successfully"}), 201

@app.route("/tasks/<task_id>", methods=["DELETE"])
def delete_task(task_id):
    user_name = session.get("user")
    if not user_name:
        return jsonify({"error": "User not logged in"}), 401

    try:
        task_object_id = ObjectId(task_id)
    except Exception:
        return jsonify({"error": "Invalid task ID format"}), 400

    task = tasks_collection.find_one({"_id": task_object_id, "username": user_name})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    result = tasks_collection.delete_one({"_id": task_object_id})
    if result.deleted_count == 1:
        return jsonify({"message": "Task deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete task"}), 500

@app.route('/routine')
def routine_page():
    return render_template('routine.html')

@app.route('/routine/tasks', methods=['GET', 'POST'])
def manage_tasks():
    username = session.get("user", "default_user")  # Example username
    if request.method == 'GET':
        tasks = list(routine_collection.find({"username": username}))
        for task in tasks:
            task["_id"] = str(task["_id"])  # Convert ObjectId to string
        return jsonify(tasks)
    elif request.method == 'POST':
        data = request.json
        task_name = data.get("taskName")
        if not task_name:
            return jsonify({"error": "Task name is required"}), 400
        new_task = {"username": username, "taskName": task_name, "checked": False}
        result = routine_collection.insert_one(new_task)
        new_task["_id"] = str(result.inserted_id)
        return jsonify(new_task)

@app.route('/routine/tasks/<task_id>', methods=['PUT', 'DELETE'])
def update_or_delete_task(task_id):
    if request.method == 'PUT':
        data = request.json
        checked = data.get("checked", False)
        routine_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"checked": checked}})
        return jsonify({"message": "Task updated successfully"})
    elif request.method == 'DELETE':
        routine_collection.delete_one({"_id": ObjectId(task_id)})
        return jsonify({"message": "Task deleted successfully"})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"redirect_url": "/"})


if __name__ == "__main__":
    app.run(debug=True)
