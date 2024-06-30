import os
from fastapi import FastAPI,Body,Request, HTTPException,status,Form
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



def create_jwt_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=30)
        }
    # Your secret key (guard it with your life!)
    secret_key = 'supersecretkey'
    # Algorithm for token generation
    algorithm = 'HS256'
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token


## TODO need to use token to


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

@app.get("/get-users/{user_id}")
async def get_users(user_id: str):
    # Find a single user based on the provided user_id
    users_cursor =app.database["users"].find({}, {"_id": 0})  # Exclude _id field from results if not needed
    users = list(users_cursor)
    return {"users": users}


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


class LoginParams(BaseModel):
    username: str
    password: str

@app.post("/test-login")
def login(login_params: LoginParams):
    user = app.database["users"].find_one({"username":login_params.username})
    is_admin = user.get("role") == "admin"
    password=user.get("password")
    print(user)
    if user is not None and password==login_params.password:
    #and bcrypt.checkpw(login_params.password.encode('utf-8'), user["password"].encode('utf-8')) :
     
        #token=create_jwt_token(user)
        if is_admin:
          return {"status": "success_is_admin", "user_id": str(user["_id"])}
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
    query = {}
    if user.username:
        query["username"] = user.username
    
    if user.id:
        query["id"] = user.id

    # Ensure at least one field is provided
    if not query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least username, or id must be provided"
        )

    # Find and delete the user
    result = app.database["users"].delete_one(query)

    if result.deleted_count == 1:
        return {"status": "success", "message": "User deleted successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    



@app.get("/")
def read_roots():
    
    #token=generate_token("adam")
    #return {generate_token(username='adam')}
    return {"message":"hi"}
    #return {token}

        


if __name__ == "__main__":
    import uvicorn
    #user = app.database["users"].find_one({"username":"adam"})
    usern = UserCreate(
    id="123456",
    username="john_doe",
    password="password123",
    role="admin",
    phone_number="123-456-7890",
    address="123 Main St, City"
)
    create_user(usern)
    print(usern)
    uvicorn.run(app, host="0.0.0.0", port=8000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       