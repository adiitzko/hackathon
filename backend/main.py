import os
import sys
from fastapi import (
    FastAPI,
    Body,
    Request,
    Response,
    HTTPException,
    status,
    HTTPException,
    status,
    Form,
    Security,
)
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
from pydantic import BaseModel, EmailStr, Field
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
from starlette.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import StreamingResponse
import io
import schedule
import time
import multiprocessing
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from starlette.status import HTTP_403_FORBIDDEN
from fastapi import (
    FastAPI,
    Body,
    Request,
    Response,
    HTTPException,
    status,
    HTTPException,
    status,
    Form,
    Depends,
    Security,
)

from dependencies import get_current_user
from jwt_utils import create_access_token

security = HTTPBearer()

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler(sys.stdout)
log_formatter = logging.Formatter(
    "%(asctime)s [%(processName)s: %(process)d] [%(threadName)s: %(thread)d] [%(levelname)s] %(name)s: %(message)s"
)
stream_handler.setFormatter(log_formatter)
logger.addHandler(stream_handler)
logger.info("API is starting up")

logging.getLogger("uvicorn.access")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler(sys.stdout)


workers = multiprocessing.cpu_count() * 2 + 1

# The address to bind to.
bind = "0.0.0.0:8000"

# Using Uvicorn worker class for ASGI applications.
worker_class = "uvicorn.workers.UvicornWorker"


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserCreate(BaseModel):
    id: str
    username: str
    password: str
    role: str
    phone_number: str
    address: str
    isAdmin: bool = False


class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: datetime = Field(default_factory=datetime.utcnow)


class UserDelete(BaseModel):
    username: str = Field(None, description="Username of the user")
    id: str = Field(None, description="ID of the user")


class LoginParams(BaseModel):
    username: str
    password: str


MONGO_URI = MongoClient(
    "mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
)

# Load environment variables from .env file
load_dotenv(".env")

frontend_url = "https://app.the-safe-zone.online"
database = MONGO_URI.locationDB
app = FastAPI()
users_collection = database.users
locations_collection = database.locations
# app.config = {'SECRET_KEY': os.getenv("SECRET_KEY")}

# api_base_url = os.getenv("SERVER_NAME")

# CORS (Cross-Origin Resource Sharing) middleware
origins = [
    "http://localhost:3000",
    "https://localhost",
    "https://app.the-safe-zone.online",
]


def generate_random_string(min_length=32, max_length=32):
    length = random.randint(min_length, max_length)

    random_string = "".join(
        random.choices(string.ascii_letters + string.digits, k=length)
    )

    return random_string


app.add_middleware(
    CORSMiddleware,
    # allow_origins=origins,
    allow_origins=[frontend_url],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# Define MongoDB connection setup function
def connect_to_mongo():
    mongo_uri = r"mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/"
    # mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("No MONGO_URI set for MongoDB connection")
    app.mongodb_client = MongoClient(mongo_uri)
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
app.include_router(
    router,
    tags=["locations", "users", "messages", "meetings", "actions"],
    prefix="/api/v1",
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# @app.post("/test-login")
# def login(login_params: LoginParams, form_data: OAuth2PasswordRequestForm = Depends()):
#     user = app.database["users"].find_one({"username": login_params.username})
#     is_admin = user.get("isAdmin")
#     password = user.get("password")
#     passw = hash_password(login_params.password)
#     username = form_data.username

#     if user is not None and password == passw:
#         # and bcrypt.checkpw(login_params.password.encode('utf-8'), user["password"].encode('utf-8')) :
#         # token = create_jwt_token(login_params.username)

#         # token=create_jwt_token(user)
#         access_token = create_access_token(data={"username": username})
#         if is_admin:
#             return {
#                 "status": "success_is_admin",
#                 "user_id": str(user["_id"]),
#                 "access_token": access_token,
#                 "token_type": "bearer",
#             }
#         else:
#             return {
#                 "status": "success_is_not_admin",
#                 "user_id": str(user["_id"]),
#                 "access_token": access_token,
#                 "token_type": "bearer",
#             }
#     else:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid username or password",
#         )


@app.post("/test-login")
def login(login_params: LoginParams):
    user = app.database["users"].find_one({"username": login_params.username})
    is_admin = user.get("isAdmin")
    password = user.get("password")
    passw = hash_password(login_params.password)

    if user is not None and password == passw:
        # and bcrypt.checkpw(login_params.password.encode('utf-8'), user["password"].encode('utf-8')) :
        # token = create_jwt_token(login_params.username)

        # token=create_jwt_token(user)
        if is_admin:
            return {"status": "success_is_admin", "user_id": str(user["_id"])}
        else:
            return {"status": "success_is_not_admin", "user_id": str(user["_id"])}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )


@app.get("/secure-endpoint")
async def secure_endpoint(current_user: dict = Depends(get_current_user)):
    return {"message": "Secure data", "user": current_user}


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post("/create-user")
def create_user(user_create: UserCreate):
    hashed_passwords = hash_password(user_create.password)
    user_create.password = hashed_passwords
    user_dict = user_create.dict()
    # Check if the username or id already exists
    # hashed_password = hash_password(user_create.password)
    existing_user = app.database["users"].find_one({"id": user_create.id})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or ID already exists",
        )

    # Insert the user document into the database

    app.database["users"].insert_one(user_dict)

    result = app.database["users"].find_one({"id": user_create.id})
    if result:
        return {"status": "success"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )


# @app.get("/get-users", response_model=List[Dict[str, str]])
# def get_users():

#     users = []
#     cursor = users_collection.find({}, {"_id": 0, "id":1,"username": 1, "password": 1, "address": 1})
#     for user in cursor:
#            users.append(user)
#     if users!=None:
#         return users
#     else:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="User not found"
#         )


@app.get("/get-users", response_model=List[Dict[str, str]])
def get_users(current_user: dict = Depends(get_current_user)):
    try:
        users = []
        cursor = users_collection.find(
            {}, {"_id": 0, "id": 1, "username": 1, "password": 1, "address": 1}
        )
        for user in cursor:
            users.append(user)
        if users:
            return users
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Users not found"
            )
    except Exception as e:
        print(f"An error occurred: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving users",
        )


def hash_password(password: str) -> str:
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password


@app.delete("/delete-user")
def delete_user(user: UserDelete):
    # Build the query filter
    users_collection = app.database["users"]
    usertodelete = users_collection.find_one({"id": user.id})
    username = usertodelete["username"]
    users_collection.delete_one({"id": user.id})

    if locations_collection.find_one({"username": username}):
        locations_collection.delete_one({"username": username})
    result = users_collection.find_one({"id": user.id})
    # Ensure at least one field is provided
    if not result:
        return {"msg": "Item deleted successfully"}
    if result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least username, or id must be provided",
        )


def delete_old_messages():
    try:
        # תאריך לפני יום
        date_before = datetime.now() - timedelta(days=1)

        # מחיקת כל המסרים בהם התאריך שלהם הוא מלפני יום
        result = database.messages.delete_many({"timestamp": {"$lt": date_before}})

        print(f"{result.deleted_count} messages deleted successfully.")

    except Exception as e:
        print(f"An error occurred while deleting messages: {str(e)}")


@app.get("/get-locations")
def get_locations():
    logger.info("suppppp")
    locationss = []
    cursor = locations_collection.find(
        {}, {"_id": 0, "username": 1, "latitude": 1, "longitude": 1, "isInDanger": 1}
    )
    for location in cursor:
        if users_collection.find_one({"username": location["username"]}):
            locationss.append(location)
            # print(location)
    if locationss != None:
        # print(locationss)
        return locationss
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )


@app.get("/get-locations-isInDanger/")
def get_locations_IsIndanger():
    locationss = []
    cursor = locations_collection.find(
        {}, {"_id": 0, "username": 1, "latitude": 1, "longitude": 1, "isInDanger": 1}
    )
    for location in cursor:
        if users_collection.find_one(
            {"username": location["username"], "isInDanger": True}
        ):
            locationss.append(location)
            # rint(location)
    if locationss != None:
        return locationss
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )


class Location(BaseModel):
    username: str
    latitude: float
    longitude: float
    timestamp: datetime = datetime.now()
    isInDanger: bool = False  # Default value for isInDanger


@app.post("/add_location/")
def add_location(location: Location):
    user = users_collection.find_one({"username": location.username})
    if not user:
        user_id = str(uuid4())
        users_collection.insert_one(
            {
                "_id": user_id,
                "username": location.username,
                "other_user_fields": "values",
            }
        )
        user = {"_id": user_id, "username": location.username}

    locations_collection.delete_many({"username": location.username})

    location_id = str(uuid4())

    # הכנת הנתונים להוספה למאגר הנתונים
    location_data = {
        "_id": location_id,
        "user_id": user["_id"],
        "username": location.username,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "timestamp": location.timestamp.isoformat(),
        "isInDanger": location.isInDanger,
    }

    # הוספת המיקום החדש למאגר הנתונים
    locations_collection.insert_one(location_data)

    return {"message": "Location added successfully", "location_id": location_id}


class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: str = Field(
        default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    )


# key = "qJ5kC3V9wE1mN8aZ2rU7xL4oT6pB0yW7fS2gH9dI4uM"
# key=generate_key()
# key='NGn8yk9PMEqrfkP_jBpFnxAk8XOFUSJuklZ2X0cBZ60='


@app.post("/create_message/")
def create_message(messages: Message):
    try:
        # print(encrypt_message(key,messages.content))
        # print(encrypt_message_jwt(m,key))

        # encrypted_messaged = encrypt_message(messages.content, key)
        # print(encrypted_messaged)
        # message_dict["message"] = encrypted_messaged

        message_dict = messages.dict()

        # print(encrypted_messaged)

        app.database["messages"].insert_one(message_dict)

        return {"message": "Message created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")


@app.get("/read_messages/", response_model=List[Message])
def read_messages():
    try:
        mess = []
        messages_collection = app.database.messages
        messages = list(
            messages_collection.find({}, {"send": 1, "content": 1, "time": 1})
        )

        for message in messages:

            message["_id"] = str(message["_id"])

            # print(str(decrypt_string(encrypted_content,key)))

        if messages:

            return messages
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No messages found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.put("/isdanger/")
def set_isdanger(user_id: str):
    try:
        users_collection = app.database.users
        result = users_collection.update_one(
            {"id": ObjectId(user_id)}, {"$set": {"isInDanger": True}}
        )

        if result.modified_count == 1:
            return {"message": "User's isdanger field updated to true"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.get("/dangerous_users/", response_model=List[UserCreate])
async def get_dangerous_users():
    try:
        # שליפת כל המשתמשים עם is_danger=True
        users = users_collection.find({"isInDanger": True})

        # יצירת רשימת משתמשים במבנה המודל User
        dangerous_users = []
        for user in users:
            dangerous_users.append(
                Location(
                    username=user["username"],
                    latitude=user["lstitude"],
                    longitude=user["longitude"],
                )
            )

        return dangerous_users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin-phone/", response_model=str)
def get_admin_phone():
    try:
        # Find the admin user
        admin_user = users_collection.find_one({"isAdmin": {"$eq": "true"}})

        if admin_user:
            return admin_user["phone_number"]
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Admin user not found"
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch admin phone number: {str(e)}",
        )


@app.put("/isdangertrue")
async def set_isdanger_true(user_name: str):
    try:
        users_collection = app.database.users
        locations_collection = app.database.locations

        user = users_collection.find_one({"username": user_name})

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        result = locations_collection.update_one(
            {"username": user_name}, {"$set": {"isInDanger": True}}
        )

        if result.modified_count == 1:

            # מצא את המיקום העדכני של המשתמש
            location = locations_collection.find_one(
                {"username": user_name}, sort=[("timestamp", -1)]
            )

            if location:
                return {
                    "message": "User's isInDanger field updated to true",
                    "location": {
                        "latitude": location["latitude"],
                        "longitude": location["longitude"],
                    },
                }
            else:
                return {
                    "message": "User's isInDanger field updated to true",
                    "location": "Location not found",
                }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.put("/isdangerfalse")
async def set_isdanger_false(user_name: str):
    try:
        users_collection = database.users
        locations_collection = database.locations

        # Check if the user exists
        user = users_collection.find_one({"username": user_name})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # Update the user's location to isInDanger: False
        result = locations_collection.update_one(
            {"username": user_name}, {"$set": {"isInDanger": False}}
        )

        if result.modified_count == 1:
            return {"message": "User's isInDanger field updated to false"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


meetings_collection = database["meetings"]


class Meeting(BaseModel):
    latitude: float
    longitude: float


# Function to calculate center of locations
def calculate_center(locations: list[dict]) -> dict:

    if not isinstance(locations, list):
        print("The provided input is not a list.")
        return {}

    total_lat = 0.0
    total_lon = 0.0
    num_locations = len(locations)

    for i, loc in enumerate(locations):

        total_lat += loc.get("latitude", 0.0)
        total_lon += loc.get("longitude", 0.0)

    if num_locations > 0:
        center_lat = total_lat / num_locations
        center_lon = total_lon / num_locations

        return {"latitude": center_lat, "longitude": center_lon}
    else:

        return {}


# Utility function to create or update the meeting center location
def create_meeting_util():
    try:
        all_locations = locations_collection.find(
            {},
            {"_id": 0, "username": 1, "latitude": 1, "longitude": 1, "isInDanger": 1},
        )

        center_location = calculate_center(list(all_locations))

        # Update the center location in the 'meetings' collection
        meetings_collection.update_one(
            {},
            {
                "$set": {
                    "latitude": center_location["latitude"],
                    "longitude": center_location["longitude"],
                }
            },
            upsert=True,
        )

        return {"message": "Center location updated successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update center location: {str(e)}"
        )


@app.post("/create-meeting", response_model=Meeting)
def create_meeting():
    return create_meeting_util()


# Get meeting endpoint
@app.get("/get-meeting", response_model=Optional[Meeting])
def get_meeting():
    try:
        # Call the create_meeting_util function to update the center location
        create_meeting_util()

        # Retrieve the single location from the 'meetings' collection
        meeting = meetings_collection.find_one({})
        print(meeting)

        if meeting:
            return {"latitude": meeting["latitude"], "longitude": meeting["longitude"]}
        else:
            return None  # or raise an HTTPException if needed

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch meeting: {str(e)}"
        )


actions_collection = database["actions"]


class Action(BaseModel):
    act: bool = False


@app.post("/act_true/", response_model=Action)
async def set_act_true():
    try:
        result = actions_collection.update_one({}, {"$set": {"act": True}}, upsert=True)

        if result.modified_count == 1 or result.upserted_id is not None:
            return {"message": "act set to True"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.post("/act_false/", response_model=Action)
async def set_act_false():
    try:
        result = actions_collection.update_one(
            {}, {"$set": {"act": False}}, upsert=True
        )

        if result.modified_count == 1 or result.upserted_id is not None:
            return {"message": "act set to False"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.get("/act_get", response_model=Action)
async def get_act():
    try:
        action = actions_collection.find_one({}, {"_id": 0, "act": 1})
        if action:
            return {"act": action["act"]}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )


@app.get("/")
def read_roots():
    # נתיב מוחלט לתמונה

    return {""}


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: str = None):
    return {"item_id": item_id, "q": q}


# if __name__ == "main":
#     import uvicorn
#     token = create_jwt_token("testuser")
#     print(token)
#     #user = app.database["users"].find_one({"username":"adam"}
#     uvicorn.run(app, host="0.0.0.0", port=8000)
