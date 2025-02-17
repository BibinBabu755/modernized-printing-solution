from pymongo import MongoClient
from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
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
CORS(app)


@app.route("/submit_order", methods=["POST"])
def submit_order():
    try:
        # Ensure the request is of the correct content type
        # Retrieve the form data
        files = request.files.getlist("files[]")
        print_type = request.form.getlist("printType[]")
        copies = request.form.getlist("copies[]")
        style = request.form.getlist("style[]")
        binding = request.form.getlist("binding[]")
        paper_size = request.form.getlist("paperSize[]")
        notes = request.form.getlist("notes[]")
        email = request.form.get("email")

        if not (files and print_type and copies and style and binding and paper_size):
            return jsonify({"error": "Missing required fields"}), 400

        order_details = {
            "files": [upload_file(file=file) for file in files],
            "printType": print_type,
            "copies": copies,
            "style": style,
            "binding": binding,
            "paperSize": paper_size,
            "notes": notes,
            "email": email,
            "timestamp": datetime.now(),
            "status": "submitted",
        }

        db.orders.insert_one(order_details)
        order_details["_id"] = str(order_details["_id"])

        print(order_details)
        return jsonify({"message": "Order submitted successfully", "orderDetails": order_details}), 201

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

# const formData = new FormData();
#                 formData.append("email", localStorage.getItem("email"));
#                 formData.append("file", file);

#                 fetch("/update_pfp", {
#                     method: "POST",
#                     body: formData
#                 });

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
        return jsonify({"orders": orders}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500   

def upload_file(file):
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
            return jsonify({"error": "Admin"}, 200)

        user = users.find_one({"email": data["email"]})
        if not user or not check_password_hash(user["password"], data["password"]):
            return jsonify({"error": "Invalid credentials"}), 401

        user.pop("password")
        user["_id"] = str(user["_id"])
        print(user)
        return jsonify({"message": "Login successful", "user": user}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/login", methods=["GET"])
def login_page():
    try:
        return open("login.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Login page not found"}), 404

@app.route("/signup", methods=["GET"])
def signup_page():
    try:
        return open("signup.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Signup page not found"}), 404
    
@app.route("/dashboard", methods=["GET"])
def dashboard():
    try:
        return open("dashboard.html").read(), 200
    except FileNotFoundError:
        return jsonify({"message": "Welcome to printing page"}), 200
    
    
@app.route("/admin", methods=["GET"])
def admin():
    try:
        return open("admin.html").read(), 200
    except FileNotFoundError:
        return jsonify({"message": "Welcome to printing page"}), 200
    
@app.route("/overview", methods=["GET"])
def overview_page():
    try:
        return open("overview.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Overview page not found"}), 404

@app.route("/orders", methods=["GET"])
def orders_page():
    try:
        return open("orders.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Orders page not found"}), 404
    
@app.route("/notifications", methods=["GET"])
def notifications_page():
    try:
        return open("notifiations.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Notification page not found"}), 404
    
@app.route("/profile", methods=["GET"])
def profile_page():
    try:
        return open("profile.html").read(), 200
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
        return open("index.html").read(), 200
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
        # Clear the session
        session.pop('user', None)
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    
@app.route("/logout", methods=["GET"])
def logout_page():
    try:
        return open("index.html").read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Login page not found"}), 404
    


if __name__ == "__main__":
    app.run(port=5000, debug=True)
