from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS
import json
import hashlib
import jwt
import datetime
import os
from functools import wraps
from blockchain import Blockchain
from zoneinfo import ZoneInfo

app = Flask(__name__, static_folder='src', static_url_path='/')
vietnam_time = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
# Route để phục vụ trang index.html
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

# Route để phục vụ các file tĩnh (CSS, JS, v.v.)
@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

CORS(app)

# Instantiate blockchain
blockchain = Blockchain()

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
USER_FILE = 'data/users.json'
DONATIONS_FILE = 'data/donations.json'

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Initialize JSON files if they don't exist
def init_json_files():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, 'w') as f:
            json.dump([], f)
    if not os.path.exists(DONATIONS_FILE):
        with open(DONATIONS_FILE, 'w') as f:
            json.dump([], f)

init_json_files()

# Helper functions
def read_json_file(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def write_json_file(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split()[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((user for user in read_json_file(USER_FILE) 
                               if user['email'] == data['email']), None)
            if not current_user:
                return jsonify({'message': 'Invalid token'}), 401
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/auth/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    users = read_json_file(USER_FILE)
    
    if any(user['email'] == email for user in users):
        return jsonify({'success': False, 'message': 'Email already exists'})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = {
        'name': name,
        'email': email,
        'password': hashed_password,
        'created_at': vietnam_time
    }
    
    users.append(new_user)
    write_json_file(USER_FILE, users)
    
    return jsonify({'success': True, 'message': 'Registration successful'})

@app.route('/auth/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    users = read_json_file(USER_FILE)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    user = next((user for user in users if user['email'] == email 
                 and user['password'] == hashed_password), None)
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid email or password'})

    token = jwt.encode({
        'email': user['email'],
        'exp': vietnam_time + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'name': user['name'],
            'email': user['email']
        }
    })

@app.route('/auth/api/donate', methods=['POST'])
@token_required
def donate(current_user):
    data = request.get_json()
    amount = data.get('amount')
    cause = data.get('cause')
    card_number = data.get('cardNumber')
    password = data.get('password')  # Get the password from the request

    # Validate input fields
    if not all([amount, cause]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    # Validate amount is a positive number
    if amount <= 0:
        return jsonify({'success': False, 'message': 'Amount must be a positive number'}), 400

    # Validate password
    if not password:
        return jsonify({'success': False, 'message': 'Password is required'}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if hashed_password != current_user['password']:
        return jsonify({
            'success': False,
            'message': 'Invalid password'
        }), 403

    # Validate cause
    valid_causes = ['education', 'healthcare', 'environment', 'hunger']
    if cause not in valid_causes:
        return jsonify({
            'success': False, 
            'message': 'Invalid cause selected'
        }), 400

    # Encrypt card number
    encrypted_card_number = hashlib.sha256(card_number.encode()).hexdigest()

    # Create a new transaction in the blockchain
    transaction = blockchain.new_transaction(current_user['email'], cause, amount)

    # Create a new donation record
    new_donation = {
        'user_email': current_user['email'],
        'user_name': current_user['name'],
        'amount': amount,
        'cause': cause,
        'card_number': encrypted_card_number,
        'date': vietnam_time,
        'transaction_id': transaction['transaction_id']
    }

    # Save the donation to donations.json
    try:
        donations = read_json_file(DONATIONS_FILE)
        donations.append(new_donation)
        write_json_file(DONATIONS_FILE, donations)
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to save donation data'}), 500

    # Return success response with donation details
    return jsonify({
        'success': True,
        'message': 'Donation successful',
        'transaction_id': transaction['transaction_id'],
        'donation_details': new_donation  # Include donation details for the dashboard
    })

@app.route('/auth/api/user', methods=['GET'])
@token_required
def get_user_info(current_user):
    return jsonify({'success': True, 'user': current_user}), 200

@app.route('/auth/api/donations', methods=['GET'])
@token_required
def get_donations(current_user):
    if not os.path.exists('data/donations.json'):
        return jsonify({'success': True, 'donations': []}), 200

    with open('data/donations.json', 'r') as file:
        donations = json.load(file)

    # Filter donations for the current user
    user_donations = [donation for donation in donations if donation['user_email'] == current_user['email']]
    
    return jsonify({'success': True, 'donations': user_donations}), 200

@app.route('/auth/api/donation_stats', methods=['GET'])
def get_donation_stats():
    donations = read_json_file(DONATIONS_FILE)
    stats = {}
    total = 0

    for donation in donations:
        cause = donation['cause']
        amount = donation['amount']
        if cause in stats:
            stats[cause] += amount
        else:
            stats[cause] = amount
        total += amount

    return jsonify({'success': True, 'stats': stats}), 200

@app.route('/auth/api/all_donations', methods=['GET'])
def get_all_donations():
    donations = read_json_file(DONATIONS_FILE)
    return jsonify({'success': True, 'donations': donations}), 200
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
