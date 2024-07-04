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
import asyncio
app = FastAPI()


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

from main import (
    UserCreate,
    Message,
    generate_random_string,
    create_jwt_token,
    verify_jwt_token,
    encrypt_message,
    decrypt_message,
    hash_password,
    connect_to_mongo,
    close_mongo_connection,
    reset_isindanger,
    get_users
)
app.include_router(router, tags=["locations", "users","messages","meetings","actions"], prefix="/api/v1")


actions_collection = database["actions"]

class Action(BaseModel):
    act: bool

@app.post("/act_true")
async def set_act_true():
    try:
        result = actions_collection.update_one({}, {"$set": {"act": True}}, upsert=True)
        
        if result.modified_count == 1 or result.upserted_id is not None:
            return {"message": "act set to True"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")

@app.post("/act_false")
async def set_act_false():
    try:
        result = actions_collection.update_one({}, {"$set": {"act": False}}, upsert=True)
        
        if result.modified_count == 1 or result.upserted_id is not None:
            return {"message": "act set to False"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")

@app.get("/act_get")
async def get_act():
    try:
        action = actions_collection.find_one({}, {"_id": 0, "act": 1})
        if action:
            return {"act": action["act"]}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Action not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")
    


@app.put("/isdangertrue")
async def set_isdanger_true(user_name: str):
    try:
        users_collection = app.database.users
        locations_collection = app.database.locations
        
        user = users_collection.find_one({"username": user_name})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        result = locations_collection.update_one({"username": user_name}, {"$set": {"isInDanger": True}})
        
        if result.modified_count == 1:
            
            
            # מצא את המיקום העדכני של המשתמש
            location = locations_collection.find_one({"username": user_name}, sort=[("timestamp", -1)])
            
            if location:
                return {
                    "message": "User's isInDanger field updated to true",
                    "location": {
                        "latitude": location["latitude"],
                        "longitude": location["longitude"]
                    }
                }
            else:
                return {
                    "message": "User's isInDanger field updated to true",
                    "location": "Location not found"
                }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")
    
@app.put("/isdangerfalse")
async def set_isdanger_false(user_name: str):
    try:
        users_collection = database.users
        locations_collection = database.locations
        
        # Check if the user exists
        user = users_collection.find_one({"username": user_name})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update the user's location to isInDanger: False
        result = locations_collection.update_one({"username": user_name}, {"$set": {"isInDanger": False}})
        
        if result.modified_count == 1:
            return {
                "message": "User's isInDanger field updated to false"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {e}")


meetings_collection = database["meetings"]

class Meeting(BaseModel):
    latitude: float
    longitude: float

# Function to calculate center of locations
def calculate_center(locations: List[dict]) -> dict:
    total_lat = 0.0
    total_lon = 0.0
    num_locations = len(locations)
    
    for loc in locations:
        total_lat += loc.get('latitude', 0.0)
        total_lon += loc.get('longitude', 0.0)
    
    if num_locations > 0:
        center_lat = total_lat / num_locations
        center_lon = total_lon / num_locations
        return {'latitude': center_lat, 'longitude': center_lon}
    else:
        return {}

# Utility function to create or update the meeting center location
def create_meeting_util():
    try:
        all_locations = list(meetings_collection.find({}, {"_id": 0, "latitude": 1, "longitude": 1}))
        
        # Calculate the center of all locations
        center_location = calculate_center(all_locations)
        
        # Update the center location in the 'meetings' collection
        meetings_collection.update_one(
            {},
            {"$set": {"latitude": center_location['latitude'], "longitude": center_location['longitude']}},
            upsert=True
        )
        
        return {"message": "Center location updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update center location: {str(e)}")


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
        
        if meeting:
            return {
                'latitude': meeting['latitude'],
                'longitude': meeting['longitude']
            }
        else:
            return None  # or raise an HTTPException if needed
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch meeting: {str(e)}")