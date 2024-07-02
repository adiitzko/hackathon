import requests
import json
from pymongo import MongoClient
from multiprocessing import get_context
import jwt
from datetime import datetime, timedelta


#BASE_URL = "https://app.the-safe-zone.online"
BASE_URL = "http://127.0.0.1:8000"

def create_jwt_token(payload):
    # Your secret key (guard it with your life!)
    secret_key = 'supersecretkey'
    # Algorithm for token generation
    algorithm = 'HS256'
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token

def login_user(username, password):
    url = f"https://app.the-safe-zone.online/users/login"
    #url = f"{BASE_URL}/users/login"
    payload = {
        "username": username,
        "password": password
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        token = create_jwt_token(payload)
        print("Login Successful, Token:", token)
        return token
    else:
        print("Login Failed:", response.json())
        return None

def create_location(token, name, description):
    url = f"{BASE_URL}/locations"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "name": name,
        "description": description
    }
    response = requests.post(url, json=payload, headers=headers)
    print("Create Location Response:", response.json())

def list_locations(token):
    url = f"{BASE_URL}/locations"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    print("List Locations Response:", response.json())

def get_location(token, location_id):
    url = f"{BASE_URL}/locations/{location_id}"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    print(f"Get Location {location_id} Response:", response.json())

def update_location(token, location_id, name=None, description=None):
    url = f"{BASE_URL}/locations/{location_id}"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {}
    if name:
        payload["name"] = name
    if description:
        payload["description"] = description
    response = requests.put(url, json=payload, headers=headers)
    print(f"Update Location {location_id} Response:", response.json())

def delete_location(token, location_id):
    url = f"{BASE_URL}/locations/{location_id}"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.delete(url, headers=headers)
    print(f"Delete Location {location_id} Response:", response.status_code)

def run_tests():
  #  register_user("testuser", "test@example.com", "testpassword")
    token = login_user("adam", "123")
    if token:
        create_location(token, "Test Location", "This is a test location.")
        list_locations(token)
        location_id = "put_existing_location_id_here"
        get_location(token, location_id)
        update_location(token, location_id, name="Updated Location")
        delete_location(token, location_id)

if __name__ == "__main__":


    # Load MongoDB URI from environment variable or configuration
    # #MONGO_URI = r"mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/"
    # MONGO_URI = r"mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/locationDB?ssl=true&ssl_cert_reqs=CERT_NONE"


    # # Initialize MongoDB client and database
    # mongodb_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # db = mongodb_client.get_database('locationDB')  # Replace 'your_database_name' with your actual database name
    # collection = db.get_collection('users')
    # user = collection.find_one({"username": "adam"})
   
    run_tests()
