from pymongo import MongoClient
import os
from flask import Flask, request, jsonify, send_file, session, send_from_directory, render_template

from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from urllib.parse import quote_plus
from requests import post
from datetime import datetime

DB_USER = quote_plus(os.getenv("DB_USER", "user"))
DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", "user"))
DB_NAME = os.getenv("DB_NAME", "bibs")
DB_CLUSTER = os.getenv("DB_CLUSTER", "cluster0.mx7kl.mongodb.net")

db = MongoClient(f"mongodb+srv://{DB_USER}:{DB_PASSWORD}@{DB_CLUSTER}/{DB_NAME}")[DB_NAME]
print(f"mongodb+srv://{DB_USER}:{DB_PASSWORD}@{DB_CLUSTER}/{DB_NAME}")
users = db["users"]

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'
CORS(app)


@app.route("/submit_order", methods=["POST"])
def submit_order():
    try:
        files = request.files.getlist("files[]")
        file_details = []
        for file in files:
            file_url = upload_file(file=file)
            file_details.append({
                "url": file_url,
                "filename": file.filename
            })

        print_type = request.form.getlist("printType[]")
        copies = request.form.getlist("copies[]")
        style = request.form.getlist("style[]")
        binding = request.form.getlist("binding[]")
        paper_size = request.form.getlist("paperSize[]")
        notes = request.form.getlist("notes[]")
        email = request.form.get("email")

        if not (files and print_type and copies and style and binding and paper_size):
            return jsonify({"error": "Missing required fields"}), 400

        # Get last order to calculate queue position
        last_order = db.orders.find_one(sort=[("queue_position", -1)])
        queue_position = last_order["queue_position"] + 1 if last_order else 1

        order_details = {
            "files": file_details,
            "printType": print_type,
            "copies": copies,
            "style": style,
            "binding": binding,
            "paperSize": paper_size,
            "notes": notes,
            "email": email,
            "timestamp": datetime.now(),
            "status": "queued",
            "queue_position": queue_position
        }

        db.orders.insert_one(order_details)
        order_details["_id"] = str(order_details["_id"])
        return jsonify({
            "message": "Order submitted successfully",
            "orderDetails": order_details,
            "queue_position": queue_position
        }), 201

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/get_user", methods=["GET"])
def get_user():
    try:
        user = users.find_one({"email": request.args.get("email")})
        if not user:
            return jsonify({"error": "User not found"}), 404
        user.pop("password")
        user["_id"] = str(user["_id"])
        return jsonify({"user": user}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/update_user", methods=["POST"])
def update_user():
    try:
        data = request.json
        if not data or not all(key in data for key in ("email", "name", "phone")):
            return jsonify({"error": "Invalid input"}), 400

        user = users.find_one({"email": data["email"]})
        if not user:
            return jsonify({"error": "User not found"}), 404

        users.update_one({"email": data["email"]}, {"$set": {"firstName": data["name"].split()[0], "lastName": data["name"].split()[1], "phone": data["phone"]}})
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/update_pfp", methods=["POST"])
def update_pfp():
    try:
        email = request.form.get("email")
        file = request.files.get("file")
        if not email or not file:
            return jsonify({"error": "Invalid input"}), 400

        user = users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        fi = upload_file(file)
        users.update_one({"email": email}, {"$set": {"profilePicture": fi}})
        return jsonify({"message": "Profile picture updated successfully", "profilePicture": fi}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/get_orders", methods=["GET"])
def get_orders():
    try:
        email = request.args.get("email")
        orders = list(db.orders.find({"email": email}))
        for order in orders:
            order["_id"] = str(order["_id"])
            user = users.find_one({"email": order["email"]})
            if user:
                order["user_name"] = f"{user.get('firstName', '')} {user.get('lastName', '')}"
        return jsonify({"orders": orders}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/get_all_orders", methods=["GET"])
def get_all_orders():
    try:
        orders = list(db.orders.find().sort("timestamp", -1))
        for order in orders:
            order["_id"] = str(order["_id"])
            user = users.find_one({"email": order["email"]})
            if user:
                order["user_name"] = f"{user.get('firstName', '')} {user.get('lastName', '')}"
                order["priority"] = user.get("priority", 1)
        return jsonify({"orders": orders}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/get_customers", methods=["GET"])
def get_customers():
    try:
        customers = []
        orders = list(db.orders.find().sort("timestamp", -1))
        for order in orders:
            user = users.find_one({"email": order["email"]})
            if user and user not in customers:
                user["_id"] = str(user["_id"])
                user["last_order"] = order["timestamp"]
                customers.append(user)
        return jsonify({"customers": customers}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/update_priority", methods=["POST"])
def update_priority():
    try:
        data = request.json
        if not data or "email" not in data or "priority" not in data:
            return jsonify({"error": "Invalid input"}), 400
            
        users.update_one(
            {"email": data["email"]},
            {"$set": {"priority": int(data["priority"])}}
        )
        return jsonify({"message": "Priority updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


def upload_file(file):
    """Upload file to cloud storage"""

    cloud = "https://envs.sh"
    response = post(f"{cloud}", files={"file": file})
    return response.content.decode("utf-8").strip()

@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        if not data or not all(key in data for key in ("email", "password", "firstName", "lastName")):
            return jsonify({"error": "Invalid input"}), 400

        if users.find_one({"email": data["email"]}):
            return jsonify({"error": "User already exists"}), 409

        hashed_password = generate_password_hash(data["password"])
        users.insert_one({**data, "password": hashed_password})
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        if not data or not all(key in data for key in ("email", "password")):
            return jsonify({"error": "Invalid input"}), 400

        if data["email"] == "admin@admin" and data["password"] == "admin":
            session['user'] = {'email': 'admin@admin', 'role': 'admin'}
            return jsonify({"message": "Admin login successful", "redirect": "/admin"}), 200

        user = users.find_one({"email": data["email"]})
        if not user or not check_password_hash(user["password"], data["password"]):
            return jsonify({"error": "Invalid credentials"}), 401

        user.pop("password")
        user["_id"] = str(user["_id"])
        return jsonify({"message": "Login successful", "user": user}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/login", methods=["GET"])
def login_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "login.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Login page not found"}), 404

@app.route("/signup", methods=["GET"])
def signup_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "signup.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Signup page not found"}), 404
    
@app.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"message": "Welcome to printing page"}), 200
    
@app.route("/admin", methods=["GET"])
def admin():
    try:
        return send_from_directory(os.path.dirname(__file__), "admin.html")



    except Exception as e:
        app.logger.error(f"Error loading admin page: {str(e)}", exc_info=True)
        return jsonify({
            "message": "Admin page not found", 
            "error": str(e),
            "details": {
                "current_dir": os.getcwd(),
                "base_dir": base_dir,
                "file_path": file_path
            }
        }), 404
    
@app.route("/overview", methods=["GET"])
def overview_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "overview.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Overview page not found"}), 404

@app.route("/orders", methods=["GET"])
def orders_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "orders.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Orders page not found"}), 404
    
@app.route("/notifications", methods=["GET"])
def notifications_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "notifiations.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Notification page not found"}), 404
    
@app.route("/profile", methods=["GET"])
def profile_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "profile.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Profile page not found"}), 404
    
@app.route("/Default Pfp.jpg", methods=["GET"])
def profile_img():
    try:
        return send_file("Default Pfp.jpg", mimetype="image/png")
    except FileNotFoundError:
        return jsonify({"message": "No Profile Picture"}), 404
    
@app.route("/camera_image.png", methods=["GET"])
def camera_img():
    try:
        return send_file("camera_image.png", mimetype="image/png")
    except FileNotFoundError:
        return jsonify({"message": "No Camera Picture"}), 404

@app.route("/", methods=["GET"])
def index():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "index.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"message": "Welcome to printing page"}), 200

@app.route("/pixelcut-export-Photoroom_upscaled.png", methods=["GET"])
def pixel_img():
    try:
        return send_file("pixelcut-export-Photoroom_upscaled.png", mimetype="image/png")
    except FileNotFoundError:
        return jsonify({"message": "Welcome to the printing page. The requested image was not found."}), 404
    
@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        session.pop('user', None)
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
def logout_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "index.html")
        return open(file_path).read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Login page not found"}), 404

@app.route("/get_order_queue", methods=["GET"])
def get_order_queue():
    try:
        orders = list(db.orders.find({"status": "queued"}).sort("queue_position", 1))
        for order in orders:
            order["_id"] = str(order["_id"])
        return jsonify({"orders": orders}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/process_next_order", methods=["POST"])
def process_next_order():
    try:
        next_order = db.orders.find_one_and_update(
            {"status": "queued"},
            {"$set": {"status": "processing"}},
            sort=[("queue_position", 1)],
            return_document=True
        )
        if next_order:
            return jsonify({
                "message": "Processing next order", 
                "order_id": str(next_order["_id"])
            }), 200
        return jsonify({"message": "No orders in queue"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/complete_order", methods=["POST"])
def complete_order():
    try:
        order_id = request.json.get("order_id")
        if not order_id:
            return jsonify({"error": "Missing order ID"}), 400
        
        result = db.orders.find_one_and_update(
            {"_id": order_id, "status": "processing"},
            {"$set": {"status": "completed"}},
            return_document=True
        )
        
        if result:
            return jsonify({"message": "Order marked as completed"}), 200
        return jsonify({"error": "Order not found or not in processing state"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)
