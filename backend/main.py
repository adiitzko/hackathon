import os
from fastapi import FastAPI,Body,Request,Response, HTTPException, status, HTTPException,status,Form
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
# from routes import router
import atexit
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from pydantic import BaseModel
import bcrypt
from pydantic import BaseModel, EmailStr,Field
from typing import Optional
import random
import string
from typing import List, Dict
import hashlib
from bson import ObjectId
from fastapi import APIRouter
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
import base64


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    id: str
    username: str
    password: str
    role: str
    phone_number: str
    address: str
    isAdmin:bool=False

class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: datetime = Field(default_factory=datetime.utcnow)

class UserDelete(BaseModel):
    username: str= Field(None, description="Username of the user")
    id: str = Field(None, description="ID of the user")
    
class LoginParams(BaseModel):
    username: str
    password: str

#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MONGO_URI=MongoClient("mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

# Load environment variables from .env file
load_dotenv(".env")
#frontend_url = "https://app.the-safe-zone.online"
frontend_url = "https://app.the-safe-zone.online"
database = MONGO_URI.locationDB
app = FastAPI()
users_collection = database.users  
locations_collection = database.locations
#app.config = {'SECRET_KEY': os.getenv("SECRET_KEY")}  

#api_base_url = os.getenv("SERVER_NAME")

# CORS (Cross-Origin Resource Sharing) middleware
origins = [
    "http://localhost:3000",
    "https://localhost",
    "https://app.the-safe-zone.online"
]

# def generate_random_string(min_length=32, max_length=32):
#     # הגדרת אורך המחרוזת
#     length = random.randint(min_length, max_length)
    
#     # יצירת המחרוזת מאותיות ותווים
#     random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
#     return random_string
# secret_key = generate_random_string()


# def create_jwt_token(username: str):
#     payload = {
#         "sub": username,
#         "exp": datetime.utcnow() + timedelta(minutes=30)
#         }
#     # Your secret key (guard it with your life!)
#     # Algorithm for token generation
#     algorithm = 'HS256'
#     token = jwt.encode(payload, secret_key, algorithm=algorithm)
#     return token



app.add_middleware(
    CORSMiddleware,
    # allow_origins=origins, 
    allow_origins=[frontend_url],  
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # השיטות שמותרות
    allow_headers=["*"], 
)


# Define MongoDB connection setup function
def connect_to_mongo():
    mongo_uri = r"mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/"
    #mongo_uri = os.getenv("MONGO_URI") 
    if not mongo_uri:
        raise ValueError("No MONGO_URI set for MongoDB connection")
    app.mongodb_client  = MongoClient(mongo_uri)
    app.database = app.mongodb_client["locationDB"]



# Define MongoDB shutdown function
def close_mongo_connection():
    if hasattr(app, "mongodb_client"):
        app.mongodb_client.close()


# Call MongoDB connection setup function explicitly
connect_to_mongo()

# def generate_key(length=32):
#     characters = string.ascii_letters + string.digits + string.punctuation
#     key = ''.join(random.choice(characters) for _ in range(length))
#     return key

# Register shutdown hook to close MongoDB connection
atexit.register(close_mongo_connection)
router = APIRouter()
# Include router for location API
app.include_router(router, tags=["locations", "users","messages"], prefix="/api/v1")
# secret_key = generate_random_string()
# def encrypt_message(key, message):
#     backend = default_backend()
#     iv = b'\x00' * 16  # initialization vector, for simplicity using all zeros
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
#     encryptor = cipher.encryptor()
#     padder = padding.PKCS7(algorithms.AES.block_size).padder()
#     padded_data = padder.update(message.encode()) + padder.finalize()
#     encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
#     return b64encode(encrypted_data).decode()
# # פונקציה לפענוח הודעה מ-JWT

# def decrypt_message(key, encrypted_message):
#     backend = default_backend()
#     iv = b'\x00' * 16  # initialization vector, should be the same as used for encryption
#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
#     decryptor = cipher.decryptor()
#     encrypted_data = b64decode(encrypted_message.encode())
#     decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
#     unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#     decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
#     return decrypted_data.decode()

# def generate_random_string(min_length=10, max_length=20):
#     # הגדרת אורך המחרוזת
#     length = random.randint(min_length, max_length)
    
#     # יצירת המחרוזת מאותיות ותווים
#     random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
#     return random_string

# def create_jwt_token(username: str):
#     payload = {
#         "sub": username,
#         "exp": datetime.utcnow() + timedelta(minutes=30)
#         }
#     # Your secret key (guard it with your life!)
#     # Algorithm for token generation
#     algorithm = 'HS256'
#     token = jwt.encode(payload, secret_key, algorithm=algorithm)
#     return token


# def verify_jwt_token(token: str):
   
#     try:
#         payload = jwt.decode(token, secret_key, algorithms=['HS256'])
#         return payload['sub']
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
@app.post("/test-login")
def login(login_params: LoginParams):
    user = app.database["users"].find_one({"username":login_params.username})
    is_admin = user.get("isAdmin")
    password=user.get("password")
    passw=hash_password(login_params.password)
    
    if user is not None and password==passw:
    #and bcrypt.checkpw(login_params.password.encode('utf-8'), user["password"].encode('utf-8')) :
        #token = create_jwt_token(login_params.username)
       
        #token=create_jwt_token(user)
        if is_admin:
          return {"status": "success_is_admin","user_id": str(user["_id"])}
        else:
          return {"status": "success_is_not_admin", "user_id": str(user["_id"])}        
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )


@app.post("/create-user")
def create_user(user_create: UserCreate):
    hashed_passwords = hash_password(user_create.password)
    user_create.password=hashed_passwords
    user_dict = user_create.dict()
    # Check if the username or id already exists
    #hashed_password = hash_password(user_create.password)
    existing_user = app.database["users"].find_one({"id": user_create.id})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or ID already exists"
        )


    # Insert the user document into the database
    
    app.database["users"].insert_one(user_dict)
    
    result=app.database["users"].find_one({"id": user_create.id})
    if result:
        return {"status": "success"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    
@app.get("/get-users", response_model=List[Dict[str, str]])
def get_users():
    
    users = []
    cursor = users_collection.find({}, {"_id": 0, "id":1,"username": 1, "password": 1, "address": 1})  
    for user in cursor:
           users.append(user)
    if users!=None:
        print(users)
        return users
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )



def hash_password(password: str) -> str:
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

     


@app.delete("/delete-user")
def delete_user(user: UserDelete):
    # Build the query filter
    users_collection = app.database["users"]  
    usertodelete= users_collection.find_one({"id":user.id})
    username=usertodelete["username"]
    users_collection .delete_one({"id": user.id})

    if locations_collection.find_one({"username":username}):
        locations_collection.delete_one({"username":username})
    result=users_collection.find_one({"id":user.id})
    # Ensure at least one field is provided
    if not result:
        return {"msg": "Item deleted successfully"}
    if result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least username, or id must be provided"
        )


@app.get("/get-locations")
def get_locations():
    locationss = []
    cursor =locations_collection.find({}, {"_id": 0,"username": 1, "latitude": 1, "longitude": 1,"isInDanger":1})  
    for location in cursor:
           if users_collection.find_one({"username":location["username"]}):
              locationss.append(location)
              print(location)
    if locationss!=None:
       # print(locationss)
        return locationss
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


class Location(BaseModel):
    username: str
    latitude: float
    longitude: float
    timestamp: datetime= datetime.now()
    isInDanger: bool = False  # Default value for isInDanger
    
   
  
@app.post("/add_location/")
def add_location(location: Location):
    user = users_collection.find_one({"username": location.username})
    if not user:
        # אם המשתמש לא קיים, ליצור משתמש חדש ולהוסיף אותו למאגר הנתונים
        user_id = str(uuid4())
        users_collection.insert_one({
            "_id": user_id,
            "username": location.username,
            "other_user_fields": "values"  # שדות נוספים אם יש לך
        })
        user = {"_id": user_id, "username": location.username}

    # מחיקת המיקום הקודם של המשתמש אם קיים
    locations_collection.delete_many({"username": location.username})

    # יצירת מזהה ייחודי חדש למיקום
    location_id = str(uuid4())
    
    # הכנת הנתונים להוספה למאגר הנתונים
    location_data = {
        "_id": location_id,
        "user_id": user["_id"],
        "username": location.username,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "timestamp": location.timestamp.isoformat()
    }
    
    # הוספת המיקום החדש למאגר הנתונים
    locations_collection.insert_one(location_data)
    
    return {"message": "Location added successfully", "location_id": location_id}
    
def generate_key():
    return Fernet.generate_key()

# הצפנת מחרוזת תווים
def encrypt_string(key, string):
    fernet = Fernet(key)
    encrypted_string = fernet.encrypt(string.encode())
    return encrypted_string

def decrypt_string(encrypted_message, key):
    try:
        fernet = Fernet(key)
        decrypted_bytes = fernet.decrypt(encrypted_message)
        decrypted_message = decrypted_bytes.decode()
        return decrypted_message
    except Exception as e:
        return str(e)
# def decrypt_string(key, encrypted_string):
#     fernet = Fernet(key)
#     decrypted_bytes = fernet.decrypt(encrypted_string)
#     decrypted_string = decrypted_bytes.decode()
#     return decrypted_string
    
class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: str = Field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
#key = "qJ5kC3V9wE1mN8aZ2rU7xL4oT6pB0yW7fS2gH9dI4uM"
#key=generate_key()
# key='NGn8yk9PMEqrfkP_jBpFnxAk8XOFUSJuklZ2X0cBZ60='
key=generate_key()
@app.post("/create_message/")
def create_message(messages: Message):
    try:
       # print(encrypt_message(key,messages.content))
        #print(encrypt_message_jwt(m,key))
        
        #encrypted_messaged = encrypt_message(messages.content, key)
        #print(encrypted_messaged)
        #message_dict["message"] = encrypted_messaged
        encrypted_messaged=encrypt_string(key, messages.content)
        messages.content = str(encrypted_messaged)
        message_dict = messages.dict()
       
        #print(encrypted_messaged)
       
        

        app.database["messages"].insert_one(message_dict)
        return {"message": "Message created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/read_messages/", response_model=List[Message])
def read_messages():
    try:
        mess=[]
        messages_collection = app.database.messages
        messages = list(messages_collection.find({}, {"send": 1, "content": 1, "time": 1}))

        for message in messages:
            try:
               
                encrypted_content = message["content"]
                decrypted_content = str(decrypt_string(encrypted_content.encode(),key))
                message.content = decrypted_content
                mess.append(message)
            except Exception as e:
                print(f"Error decrypting message: {e}")

        if messages:
            return messages
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No messages found")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")
    # try:
    #     key = os.urandom(32) 
    #     messages_collection = app.database.messages  
    #     messages = list(messages_collection.find({"_id":0}, { "send": 1, "content": 1, "time": 1}).sort("time",-1))
    #     mess=[]
    #     for message in messages:
           
    #         # message["content"]=decrypt_message(message,key)
    #         # m= message["content"]
    #         #mess.append(message)
    #         # message["content"]=encrypt_message(m,key)
    #         mess.append(message)

    #     if mess:
    #         print(mess)
    #         print(messages)
    #         return messages
    #     else:
    #         raise HTTPException(
    #             status_code=status.HTTP_404_NOT_FOUND,
    #             detail="No messages found"
    #         )
    # except Exception as e:
    #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")

@app.put("/isdanger/")
def set_isdanger(user_id: str):
    try:
        users_collection = app.database.users
        result = users_collection.update_one({"id": ObjectId(user_id)}, {"$set": {"isInDanger": True}})
        
        if result.modified_count == 1:
            return {"message": "User's isdanger field updated to true"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")

@app.get("/dangerous_users/", response_model=List[UserCreate])
async def get_dangerous_users():
    try:
        # שליפת כל המשתמשים עם is_danger=True
        users = users_collection.find({"isInDanger": True})
        
        # יצירת רשימת משתמשים במבנה המודל User
        dangerous_users = []
        for user in users:
            dangerous_users.append(Location(
                username=user["username"],
                latitude=user["lstitude"],
                longitude=user["longitude"]
                
            ))
        
        return dangerous_users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_roots():
    
    #token=generate_token("adam")
    #return {generate_token(username='adam')}
    return {"message":"hi"}
    #return {token}

        

if __name__ == "__main__":
    import uvicorn
    #user = app.database["users"].find_one({"username":"adam"})
    try:
       key=generate_key()
         # יצירת מפתח חדש
       original_string = "Hello, World!"
       encrypted_string = encrypt_string(key, original_string)
    
       if encrypted_string is not None:
        decrypted_string = decrypt_string( encrypted_string,key)
    
        print(f"מפתח: {key}")
        print(f"מחרוזת מקורית: {original_string}")
        print(f"מחרוזת מוצפנת: {encrypted_string}")
        print(f"מחרוזת מפוצנת: {decrypted_string}")
       else:
        print("Encryption failed.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    
    uvicorn.run(app, host="0.0.0.0", port=8000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       