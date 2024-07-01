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

def generate_random_string(min_length=10, max_length=20):
    # הגדרת אורך המחרוזת
    length = random.randint(min_length, max_length)
    
    # יצירת המחרוזת מאותיות ותווים
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    return random_string
secret_key = generate_random_string()


def create_jwt_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=30)
        }
    # Your secret key (guard it with your life!)
    # Algorithm for token generation
    algorithm = 'HS256'
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token



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

# Register shutdown hook to close MongoDB connection
atexit.register(close_mongo_connection)
router = APIRouter()
# Include router for location API
app.include_router(router, tags=["locations", "users","messages"], prefix="/api/v1")
secret_key = generate_random_string()
def encrypt_message(message, key):
    # יצירת וקטור אתחול (IV) באורך 16 בתים
    iv = os.urandom(16)
    
    # יצירת cipher להצפנה עם מפתח ה-AES ומצב ה-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # הוספת padding להודעה כדי להתאים לגודל הבלוק של AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    # הצפנת ההודעה
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    
    # החזרת וקטור האתחול (IV) משולב עם ההודעה המוצפנת
    return iv + encrypted_message

def decrypt_message(encrypted_message, key):
    # הפרדת וקטור האתחול (IV) מההודעה המוצפנת
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    
    # יצירת cipher לפענוח עם מפתח ה-AES ומצב ה-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # פענוח ההודעה המוצפנת
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # הסרת padding מההודעה המפוענחת
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    
    return message.decode()

def generate_random_string(min_length=10, max_length=20):
    # הגדרת אורך המחרוזת
    length = random.randint(min_length, max_length)
    
    # יצירת המחרוזת מאותיות ותווים
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    return random_string

def create_jwt_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=30)
        }
    # Your secret key (guard it with your life!)
    # Algorithm for token generation
    algorithm = 'HS256'
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token


def verify_jwt_token(token: str):
   
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


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
    #hashed_passwords = hash_password(user_create.password)
    #user_create.password=hashed_passwords
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
    
    users_collection .delete_one({"id": user.id})
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
    cursor =locations_collection.find({}, {"_id": 0,"username": 1, "latitude": 1, "longitude": 1})  
    for location in cursor:
           if users_collection.find_one({"username":location.username}):
              locationss.append(location)
    if locationss!=None:
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
async def add_location(location: Location):
    user = users_collection.find_one({"username": location.username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    location_id = str(uuid4())
    loc=locations_collection.find_one({"username": location.username})
    if loc:
        loc["latitude"]=location.latitude
        loc["longitude"]=location.longitude
    location_data = {
        "_id": location_id,
        "username": location.username,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "timestamp": location.timestamp.isoformat()
        
    }
    locations_collection.insert_one(location_data)
    return {"message": "Location added successfully", "location_id": location_id}

class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: str = Field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

@app.post("/create_message/")
def create_message(messages: Message):
    try:
        encrypted_messaged = encrypt_message(messages.content, secret_key)
        message_dict = messages.dict()
        print(encrypt_message)
        #message_dict["message"] = encrypted_messaged
        

        app.database["messages"].insert_one(message_dict)
        return {"message": "Message created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/read_messages/")
def read_messages():
    try:
        messages_collection = app.database.messages  
        messages = list(messages_collection.find({"_id":0}, { "send": 1, "content": 1, "time": 1}).sort("time",-1))
        mess=[]
        for message in messages:
            message["_id"] = str(message["_id"])
            message["content"]=decrypt_message(message,secret_key)
            m= message["content"]
            mess.append(message)
            message["content"]=encrypt_message(m,secret_key)
        
        if mess:
            #print(messages)
            return mess
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No messages found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")

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
    user=get_users()
    print(user)
    uvicorn.run(app, host="0.0.0.0", port=8000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       