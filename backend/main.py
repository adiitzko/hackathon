import os
from fastapi import FastAPI,Body,Request,Response, HTTPException, status, HTTPException,status,Form
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
from routes import router
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
# יצירת אובייקט ליצירה ובדיקת סיסמאות

#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MONGO_URI=MongoClient("mongodb+srv://adiitzko:adiitz2004@cluster0.is6jut3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

# Load environment variables from .env file
load_dotenv(".env")
#frontend_url = "https://app.the-safe-zone.online"
frontend_url = "https://app.the-safe-zone.online"
database = MONGO_URI.locationDB
app = FastAPI()
#app.config = {'SECRET_KEY': os.getenv("SECRET_KEY")}  
#secret='SECRET_KEY'
#api_base_url = os.getenv("SERVER_NAME")

# CORS (Cross-Origin Resource Sharing) middleware
origins = [
    "http://localhost:3000",
    "https://localhost",
    "https://app.the-safe-zone.online"
]

app.add_middleware(
    CORSMiddleware,
    # allow_origins=origins, 
    allow_origins=[frontend_url],  
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # השיטות שמותרות
    allow_headers=["*"], 
)

# אפשר להוסיף middleware כדי לאפשר גישה ל-Frontend מה-Backend
# @app.middleware("http")
# async def add_cors_headers(request: Request, call_next):
#     response = await call_next(request)
#     response.headers["Access-Control-Allow-Origin"] = frontend_url
#     response.headers["Access-Control-Allow-Headers"] = "*"
#     return response

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

# Include router for location API
app.include_router(router, tags=["locations", "users"], prefix="/api/v1")


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


def verify_jwt_token(token: str):
   
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


#@app.delete("/users/{id}", response_description="Delete a user")
#def delete_user(id: str, request: Request, response: Response):
    delete_result = request.app.database["users"].delete_one({"_id": id})

    if delete_result.deleted_count == 1:
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"User with ID {id} not found")

class UserCreate(BaseModel):
    id: str
    username: str
    password: str
    role: str
    phone_number: str
    address: str
    isInDanger: bool = False  # Default value for isInDanger



@app.post("/create-user")
def create_user(user_create: UserCreate):
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
    users_collection = app.database.users  
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


@app.get("/get-location")
def get_location():
    # Aggregate to fetch locations with user names
    locations = list(app.database["locations"].aggregate([
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user_info"
            }
        },
        {
            "$project": {
                "_id": 0,
                "location_id": "$_id",
                "user_id": 1,
                "username": {"$arrayElemAt": ["$user_info.username", 0]},
                "latitude": 1,
                "longitude": 1,
                "timestamp": 1
            }
        }
    ]))
    
    return {"locations": locations}


def hash_password(password: str) -> str:
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

class LoginParams(BaseModel):
    username: str
    password: str
# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
@app.post("/test-login")
def login(login_params: LoginParams):
    user = app.database["users"].find_one({"username":login_params.username})
    is_admin = user.get("role") == "admin"
    password=user.get("password")
    print(hash_password(password))
    if user is not None and password==login_params.password:
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
     


# User deletion model
class UserDelete(BaseModel):
    username: str= Field(None, description="Username of the user")
    id: str = Field(None, description="ID of the user")

@app.delete("/delete-user")
def delete_user(user: UserDelete):
    # Build the query filter
    users_collection = app.database["users"]  
    usertodelete= users_collection.find_one({"id":user.id})
    print(usertodelete)
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
class Message(BaseModel):
    send: str = Field(...)
    content: str = Field(...)
    time: datetime = Field(default_factory=datetime.utcnow)

@app.post("/messages/")
def create_message(messages: Message):
    message_dict = messages.dict()
    app.database["messages"].insert_one(message_dict)
    return {"message": "Message created successfully"}

@app.get("/messages/")
def read_messages():
    messages = list( app.database["messages"].find())
    return messages




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