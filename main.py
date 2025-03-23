from pymongo import MongoClient
import os
from bson.objectid import ObjectId
from flask import Flask, request, jsonify, send_file, session, send_from_directory, render_template
import win32evtlog
import win32evtlogutil
import win32con
import json
import time

from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from urllib.parse import quote_plus
from requests import post
from datetime import datetime
import PyPDF2
import io
import razorpay
import firebase_admin
from firebase_admin import credentials, auth
import requests
from firebase_admin import auth



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

cred = credentials.Certificate(r"C:\Users\Ashish\Desktop\Mini project\Confidential\modernized-printing-solution-firebase-adminsdk-fbsvc-31596e3d1a.json")
firebase_admin.initialize_app(cred)
FIREBASE_API_KEY = "AIzaSyCUYR-bTjZFUbCBKUIJX_RFwnockOymYYk"

# Event IDs for print jobs
PRINT_JOB_STARTED = 307
PRINT_JOB_COMPLETED = 308

def fetch_print_events():
    server = 'Application'
    log_type = 'Microsoft-Windows-PrintService/Operational'
    hand = win32evtlog.OpenEventLog(None, log_type)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    events = []

    for i in range(total):
        try:
            event = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            for e in event:
                if e.EventID in (PRINT_JOB_STARTED, PRINT_JOB_COMPLETED):
                    events.append(parse_event(e))
        except Exception as e:
            print(f"Error reading event log: {e}")
            break

    return events

def parse_event(event):
    event_data = {
        'EventID': event.EventID,
        'TimeGenerated': event.TimeGenerated,
        'SourceName': event.SourceName,
        'Message': win32evtlogutil.SafeFormatMessage(event, win32con.EVENTLOG_SUCCESS)
    }
    return event_data

@app.route("/fetch_print_events", methods=["GET"])
def fetch_print_events_route():
    events = fetch_print_events()
    return jsonify(events), 200

@app.route("/submit_order", methods=["POST"])
def submit_order():  
    try:
        payment_id = request.form.get("payment_id")  # Get Razorpay payment ID
        email = request.form.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        

        if payment_id=="null":
            payment_status = "unpaid"
        else:
            payment_status = "paid"

        # ✅ Prepare order details
        files = request.files.getlist("files[]")
        uploaded_files = []
        for file in files:
            if file.filename:
                uploaded_files.append(upload_file(file))

        order_details = {
            "email": email,
            "files": uploaded_files,
            "printType": request.form.getlist("printType[]"),
            "copies": request.form.getlist("copies[]"),
            "style": request.form.getlist("style[]"),
            "binding": request.form.getlist("binding[]"),
            "paperSize": request.form.getlist("paperSize[]"),
            "notes": request.form.getlist("notes[]"),
            "total_cost": float(request.form.get("total_cost", 0)),
            "payment_id": payment_id,  # Store payment ID if available
            "payment_status": payment_status,  # Store payment status
            "timestamp": datetime.now().isoformat(),
            "status": "queued"
        }

        # Insert into MongoDB
        db.orders.insert_one(order_details)
        
        # Send notification for new order
        notification = {
            "email": email,
            "order_id": str(order_details["_id"]),
            "type": "order_created",
            "message": "Your order has been successfully submitted",
            "timestamp": datetime.now().isoformat(),
            "status": "unread"
        }
        db.notifications.insert_one(notification)

        return jsonify({"message": "Order submitted successfully"}), 201

    except Exception as e:
        import traceback
        print(" Error in submit_order:", traceback.format_exc())
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
    # New endpoint to fetch order stats
    total_orders = db.orders.count_documents({})
    completed_orders = db.orders.count_documents({"status": "completed"})
    return jsonify({"totalOrders": total_orders, "completedOrders": completed_orders}), 200

base_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(base_dir, "admin.html")

@app.route("/user_orders", methods=["GET"])
def user_orders():
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

@app.route("/get_order_by_id", methods=["GET"])
def get_order_by_id():
    try:
        order_id = request.args.get("order_id")
        order = db.orders.find_one({"_id": ObjectId(order_id)}
                                   )
        order["_id"] = str(order["_id"])
        if not order:
            return jsonify({"error": "Order not found"}), 404

        return jsonify({"order": order}), 200
    except:
        return jsonify({"order": "nah"}), 200
    
@app.route("/fileproxy", methods=["GET"])
def fiproxy():
    url = request.args.get("url")
    resp = requests.get(url)
    return send_file(io.BytesIO(resp.content), mimetype="application/pdf")

@app.route("/mark_as_completed", methods=["POST"])
def mark_as_completed():
    data = request.json
    order_id = data.get("order_id")

    if not order_id:
        return jsonify({"error": "Missing order_id"}), 400

    try:
        db.orders.update_one({"_id": ObjectId(order_id)}, {"$set": {"status": "completed"}})
        return jsonify({"message": "Order marked as completed"}), 200
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
        if not data or not all(key in data for key in ("uid", "firstName", "lastName", "email", "phone", "password")):
            return jsonify({"error": "Invalid input"}), 400
        
        if users.find_one({"email": data["email"]}):
            return jsonify({"error": "User already exists"}), 409

        # Hash the password (optional, since Firebase already hashes it)
        hashed_password = generate_password_hash(data["password"])

        # Prepare user data
        user_data = {
            "uid": data["uid"],
            "firstName": data["firstName"],
            "lastName": data["lastName"],
            "email": data["email"],
            "phone": data["phone"],
            "password": hashed_password,  # Optional: Store hashed password
            "verified": False  # You can set this to True after email verification
        }

        # Insert user data into MongoDB
        users.insert_one(user_data)

        return jsonify({"message": "User data stored successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
           
            return jsonify({"error": "Invalid input"}), 400

        
        if data["email"] == "admin@admin" and data["password"] == "admin":
             session['user'] = {'email': 'admin@admin', 'role': 'admin'}
             return jsonify({"message": "Admin login successful", "redirect": "/admin"}), 200

        else:

            firebase_auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            firebase_response = requests.post(firebase_auth_url, json=payload)
            firebase_data = firebase_response.json()

            if "error" in firebase_data:
                return jsonify({"error": "Invalid credentials"}), 401
            
            firebase_user = auth.get_user_by_email(email)
            

            session["user"] = {"email": email, "role": "user"}
            return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200

    except Exception as e:
        print("🔥 INTERNAL SERVER ERROR:", str(e))
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


    
@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Generate password reset link
        reset_link = auth.generate_password_reset_link(email)

        # When a user resets their password, update MongoDB with a placeholder password
        users.update_one({"email": email}, {"$set": {"password": "firebase_reset"}})

        return jsonify({"message": "Password reset email sent. Please check your inbox.", "reset_link": reset_link}), 200
    except auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@app.route("/login", methods=["GET"])
def login_page():
    try:
        file_path = os.path.join(os.path.dirname(__file__), "login.html")
        return open(file_path, encoding="utf-8").read(), 200
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
    orderId = request.json.get("orderId")
    orderId = orderId.split("-")[1]

    try:
        email = db.orders.find_one({"_id": ObjectId(orderId)})["email"]
        orders = db.orders.update_many({"email": email, "status": "queued"}, {"$set": {"status": "processing"}})

        if orders.modified_count > 0:
            for order in db.orders.find({"email": email, "status": "processing"}):
                notification = {
                    "email": email,
                    "order_id": str(order["_id"]),
                    "type": "order_processing",
                    "message": "Your order is now being processed",
                    "timestamp": datetime.now().isoformat(),
                    "status": "unread"
                }
                db.notifications.insert_one(notification)

            return jsonify({"message": "Processing next order", "order_id": orderId}), 200
        else:
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
            # Send completion notification
            notification = {
                "email": result["email"],
                "order_id": str(result["_id"]),
                "type": "order_completed",
                "message": "Your order has been completed",
                "timestamp": datetime.now().isoformat(),
                "status": "unread"
            }
            db.notifications.insert_one(notification)
            
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
