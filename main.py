from pymongo import MongoClient
import os
from flask import Flask, request, jsonify, send_file, session, send_from_directory, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from urllib.parse import quote_plus
from requests import post
from datetime import datetime
import PyPDF2
import io
import razorpay


DB_USER = quote_plus(os.getenv("DB_USER", "user"))
DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", "user"))
DB_NAME = os.getenv("DB_NAME", "bibs")
DB_CLUSTER = os.getenv("DB_CLUSTER", "cluster0.mx7kl.mongodb.net")



db = MongoClient(f"mongodb+srv://{DB_USER}:{DB_PASSWORD}@{DB_CLUSTER}/{DB_NAME}")[DB_NAME]
print(f"mongodb+srv://{DB_USER}:{DB_PASSWORD}@{DB_CLUSTER}/{DB_NAME}")
users = db["users"]
feedback = db["feedbacks"]

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'
CORS(app)

RAZORPAY_KEY_ID = "rzp_test_uWQB1jUeTRrqGS"
RAZORPAY_KEY_SECRET = "9AiZepOIynKtEPTlAqEf0JbK"

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


@app.route("/submit_order", methods=["POST"])
def submit_order():
    try:
        files = request.files.getlist("files[]")
        file_details = []
        for file in files:
            file_url = upload_file(file=file)
            file_details.append({"url": file_url, "filename": file.filename})

        print_type = request.form.getlist("printType[]")
        copies = request.form.getlist("copies[]")
        style = request.form.getlist("style[]")
        binding = request.form.getlist("binding[]")
        paper_size = request.form.getlist("paperSize[]")
        notes = request.form.getlist("notes[]")
        email = request.form.get("email")
        total_cost = float(request.form.get("total_cost", 0))
        payment_id = request.form.get("payment_id")

        if not payment_id:
            return jsonify({"error": "Payment ID missing"}), 400
        
        

        last_order = db.orders.find_one(sort=[("queue_position", -1)])
        queue_position = last_order["queue_position"] + 1 if last_order else 1

        payment_status = "paid" if payment_id else "unpaid"

        order_details = {
            "files": file_details,
            "printType": print_type,
            "copies": copies,
            "style": style,
            "binding": binding,
            "paperSize": paper_size,
            "notes": notes,
            "email": email,
            "total_cost": total_cost,
            "payment_id": payment_id,
            "payment_status": payment_status,
            "timestamp": datetime.now().isoformat(),
            "status": "queued",
            "queue_position": queue_position
        }

        db.orders.insert_one(order_details)
        return jsonify({"message": "Order submitted successfully"}), 201

    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

    
@app.route("/create_order", methods=["POST"])
def create_order():
    try:
        data = request.json
        amount = int(data.get("total_cost", 0) * 100)  # Convert to paise (INR)
        currency = "INR"
        receipt = f"receipt_{int(datetime.timestamp(datetime.now()))}"

        razorpay_order = razorpay_client.order.create({
            "amount": amount,
            "currency": currency,
            "receipt": receipt,
            "payment_capture": 1
        })

        return jsonify({"order_id": razorpay_order["id"], "amount": amount, "currency": currency})
    except Exception as e:
        return jsonify({"error": "Error creating order", "details": str(e)}), 500


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

@app.route("/update_password", methods=["POST"])
def update_password():
    try:
        data = request.get_json()
        email = data.get("email")
        new_password = data.get("newPassword")

        if not email or not new_password:
            return jsonify({"success": False, "message": "Email and password are required"}), 400

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the user's password in the database
        result = users.update_one({"email": email}, {"$set": {"password": hashed_password}})

        if result.modified_count == 1:
            return jsonify({"success": True, "message": "Password updated successfully"})
        else:
            return jsonify({"success": False, "message": "User not found or password not changed"}), 404

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


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

@app.route("/get_orders_overview", methods=["GET"])
def get_orders_overview():
    if "user" not in session:
        return jsonify({"error": "User not logged in"}), 401  # Unauthorized

    email = session["user"]["email"]  # Fetch logged-in user's email

    orders = list(db.orders.find({"email": email}, {"_id": 1, "status": 1, "paperSize": 1, "style": 1,  "printType": 1}))
    
    # Convert ObjectId to string
    for order in orders:
        order["_id"] = str(order["_id"])

    return jsonify({"orders": orders}), 200

@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    data = request.json
    print("Received feedback data:", data)  # Debugging

    order_id = data.get("order_id")
    feedback_text = data.get("feedback") 

    if not order_id or not feedback_text:
            return jsonify({"error": "Missing fields"}), 400

    feedback_entry = {
        "order_id": order_id,
        "feedback": feedback_text,
        "timestamp": datetime.utcnow() 
    }

    db.feedback.insert_one(feedback_entry)
    return jsonify({"message": "Feedback submitted successfully"}), 200


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
        session["user"] = {"email": user["email"], "role": "user"}

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
        return open(file_path, encoding="utf-8").read(), 200

    except FileNotFoundError:
        return jsonify({"error": "Overview page not found"}), 404


@app.route("/get_payment_overview", methods=["GET"])
def get_payment_overview():
    try:
        email = request.args.get("email")
        
        if not email:
            return jsonify({"error": "Email parameter is missing"}), 400
        
        # Fetch orders for this email
        orders = db.orders.find(
            {"email": email}, {"_id": 1, "timestamp": 1, "total_cost": 1, }
        )

        payments = []
        for order in orders:
            timestamp = order.get("timestamp")
            
            # Ensure timestamp is a valid datetime object
            if isinstance(timestamp, datetime):
                date_str = timestamp.strftime('%Y-%m-%d')
            else:
                date_str = "Unknown"

            payments.append({
                "_id": str(order.get("_id")),
                "date": date_str,
                "total_cost": order.get("total_cost", 0)  # Ensure default 0 if missing
            })

        print("Payments Data:", payments)  # Debugging in logs
        return jsonify({"payments": payments})

    except Exception as e:
        print("Error in get_payment_overview:", str(e))  # Print the error in Flask logs
        return jsonify({"error": "Internal Server Error"}), 500


    
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

@app.route("/get_pdf_page_count", methods=["POST"])
def get_pdf_page_count():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
            
        file = request.files['file']
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({"error": "File must be a PDF"}), 400

        # Read the PDF file
        pdf_stream = io.BytesIO(file.read())
        pdf_reader = PyPDF2.PdfReader(pdf_stream)
        page_count = len(pdf_reader.pages)

        return jsonify({
            "page_count": page_count,
            "filename": file.filename
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)
