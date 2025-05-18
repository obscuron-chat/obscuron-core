from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from datetime import datetime
from dotenv import load_dotenv
import hashlib
import jwt
import os
from supabase import create_client
import bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)

# Enable CORS for all routes and WebSocket connections
CORS(app, supports_credentials=True)

# Initialize SocketIO with CORS allowed origins
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=400, ping_interval=5)  # This allows all origins; you can specify specific ones like ["http://localhost:3000"]

# Keep track of connected users by username and their session IDs
users = {}

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_jwt(api_key):
    payload = {
        "sub": api_key,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=90),
    }
    return jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")

# When a client connects
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('message', {'from': 'Server', 'message': 'Welcome to the chat!', 'timestamp': str(datetime.now())}, room=request.sid)

# When a client joins a room
@socketio.on('join')
def handle_join(username):
    sid = request.sid  # Get the session ID from Flask-SocketIO
    users[username] = sid  # Store the session ID with the username
    print(f"{username} joined. SID: {request.sid}")
    emit('user_list', list(users.keys()), broadcast=True)
    
    # Add the user to a room named after their username
    join_room(username)
    
    # Notify everyone that the user has joined
    emit('message', {'from': 'Server', 'message': f'{username} has joined the chat!', 'timestamp': str(datetime.now())}, broadcast=True)

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    if username:
        users[username] = request.sid
        print(f"User registered: {username} with sid: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    disconnected_user = None
    for user, sid in users.items():
        if sid == request.sid:
            disconnected_user = user
            break
    if disconnected_user:
        print(f"{disconnected_user} disconnected")
        del users[disconnected_user]
        emit('user_list', list(users.keys()), broadcast=True)

@app.route("/auth/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        if "user_name" not in data:
            return jsonify({"status": "Register Failed", "error": "Username is required"}),400
        if "password" not in data: # Hash password in the back end for security
            return jsonify({"status": "Register Failed", "error": "Password is required"}),400
        if "public_key" not in data:
            return jsonify({"status": "Register Failed", "error": "Public Key is required"}),400

        # Check pass and user name in database

        load_dotenv()

        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")

        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

        response = supabase.table("User").select("*").eq("user_name", data["user_name"]).execute()

        if response.data:
            return jsonify({"status": "Register Failed", "error": "Username found. Please Login!"}),400
        
        password = data["password"].encode("utf-8")
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        data_reg = {
            "user_name": data["user_name"],
            "password_hashed": hashed.decode("utf-8"),
            "public_key": data["public_key"], 
            "user_token": generate_jwt("user_name")
        }

        response_register = supabase.table("User").insert(data_reg).execute()

        # Check the response
        if response_register.data:
            return jsonify({"status": "Register Success"}, 200)
        else:
            return jsonify({"status": "Register Failed", "error": "Try again later"}),500

    except Exception as e:
        return jsonify({"status": "Failed", "error": f"{str(e)}"}),500


@app.route("/get/users", methods=["GET"])
def get_user(): 
        load_dotenv()

        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")

        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

        response = supabase.table("User").select("user_name").execute()
        
        # Or you can check if data is empty or None
        if not response.data:
            return jsonify({"error": "No data found"}), 404
        
        return jsonify(response.data), 200

# Return Public Key based on Username
@app.route("/get/public_key", methods=["POST"])
def get_public_key(): 

        data = request.get_json()

        if "user_name" not in data:
            return jsonify({"status": "Login Failed", "error": "Username is required"}),200
        load_dotenv()

        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")

        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

        response = supabase.table("User").select("public_key").eq("user_name", data["user_name"]).execute()
        
        # Or you can check if data is empty or None
        if not response.data:
            return jsonify({"error": "No data found"}), 404
        
        return jsonify(response.data), 200
        
@app.route("/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        if "user_name" not in data:
            return jsonify({"status": "Login Failed", "error": "Username is required"}),200
        if "password" not in data:
            return jsonify({"status": "Login Failed", "error": "Password is required"}),200

        # Check pass and user name in database

        load_dotenv()

        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")

        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

        response = supabase.table("User").select("*").eq("user_name", data["user_name"]).execute()
        
        if not response.data:
            return jsonify({"status": "Login Failed", "error": "Username not found. Please register first!"}),200

        if bcrypt.checkpw(data["password"].encode("utf-8"), response.data[0]["password_hashed"].encode("utf-8")) : 
            username = data["user_name"]
            response = supabase.table("Chat") \
            .select("*") \
            .or_(f"sender.eq.{username},receiver.eq.{username}") \
            .order("timestamp", desc=False) \
            .execute()

            messages = response.data if response.data else []

            return jsonify({
                "status": "Login Success",
                "messages": messages
            }), 200

        # TODO: Add last login session in database
        return jsonify({"status": "Login Failed", "error": "Wrong password"}),200
    except Exception as e:
        return jsonify({"status": "Error", "error": f"{str(e)}"}),400

@app.route('/chat_history/<user1>/<user2>')
def chat_history(user1, user2):
    try:

        load_dotenv()

        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")

        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        # Query messages where (from_user == user1 AND to_user == user2)
        # OR (from_user == user2 AND to_user == user1)
        messages_from_user1 = supabase.table('Chat')\
            .select('*')\
            .eq('sender', user1)\
            .eq('receiver', user2)

        messages_from_user2 = supabase.table('Chat')\
            .select('*')\
            .eq('sender', user2)\
            .eq('receiver', user1)

        # Fetch results
        data1 = messages_from_user1.execute()
        data2 = messages_from_user2.execute()

        # Combine results
        messages = (data1.data or []) + (data2.data or [])

        # Sort messages by timestamp ascending
        messages.sort(key=lambda m: m['timestamp'])

        # Format timestamps (assuming ISO string, adjust if needed)
        for m in messages:
            if 'timestamp' in m:
                # Optionally format or just keep as is
                pass

        return jsonify(messages)

    except Exception as e:
        print("Error fetching chat history:", e)
        return jsonify({"error": str(e)}), 500

@socketio.on('message')
def handle_message(data):
    sender = data['from_user']
    recipient = data['to_user']
    message = data['message']
    hashed_message = data['hashed_message']
    digital_signature = data['digital_signature'] # In JSON format
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    msg = {
        'sender': sender,
        'receiver': recipient,
        'message': message,
        'hashed_message': hashed_message,
        'digital_signature': digital_signature,  
        'timestamp': timestamp
    }

    load_dotenv()

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    supabase.table("Chat").insert({
        "sender": sender,
        "receiver": recipient,
        "message": message,
        "hashed_message": hashed_message,
        "digital_signature" : digital_signature, # In JSON format
        "timestamp": timestamp
    }).execute()

    # Send to recipient
    if recipient in users:
        emit('message', msg, room=users[recipient])

    # Send to sender (so they see their own message)
    emit('message', msg, room=request.sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host='0.0.0.0')
