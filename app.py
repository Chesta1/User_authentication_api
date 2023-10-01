from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps
import sqlite3

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisthesecretkey'

# Store the token in a global variable for reuse
global_token = None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 403
            
        return f(*args, **kwargs)
    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'message': 'Anyone can view this'})

def get_db_connection():
    conn = sqlite3.connect('olympics_data.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/protected',methods=['GET'])
@token_required
def protected():
    decoded_payload = jwt.decode(request.args.get('token'), app.config['SECRET_KEY'],algorithms=['HS256'])
    print(decoded_payload)
    try:
        conn = get_db_connection()
        crsr = conn.cursor()
        crsr.execute("SELECT * FROM athlete_data LIMIT 50")
        rows = crsr.fetchall()

        data_list = [{'id': row[0], 'name': row[1], 'age': row[2], 'country': row[3]} for row in rows]

        return jsonify(data_list)
    except Exception as e:
        return jsonify({'error': str(e)})
    finally:
        conn.close()
# Define a simple user database (for demonstration purposes)
user_database = {
    'username1': 'hashed_password1',
    'username2': 'hashed_password2',
}

@app.route('/login', methods=['POST'])
def login():
    global global_token
    if global_token is None:
        auth = request.authorization
        print("Received Credentials: username =", auth.username, "password =", auth.password) 
        if auth and auth.username in user_database:
            # In a real application, you would use a library like bcrypt to check the hashed password
            if auth.password == user_database[auth.username]:
                global_token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=80)}, app.config['SECRET_KEY'],algorithm='HS256')
                print("Encoded Token:", global_token)
                return jsonify({'token': global_token})
    
    return jsonify({'message': 'Authentication failed'}), 401

if __name__ == '__main__':
    app.run(debug=True)

## for the login route to work in Postman app for getting the jwt token **there is need to set the "Authorization" in the postman to type "Basic Auth" & 
## provide the username and password there