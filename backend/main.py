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
# יצירת אובייקט ליצירה ובדיקת סיסמאות

#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Load environment variables from .env file
load_dotenv(".env")
#frontend_url = "https://app.the-safe-zone.online"
frontend_url = "https://app.the-safe-zone.online"

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

@app.post("/tests-login", response_description="Check user credentials")
def check_user_credentials(request: Request, username: str = Form(...), password: str = Form(...)):
    user = request.app.database["users"].find_one({"username": username})
    if user is not None:
        token=create_jwt_token(username)
        #token = generate_token(username)
       # print("Generated token:", token)  
        #return {"status": "success", "user_id": str(user["_id"]), "token": token}
        return {"status": "sucsses", "user_id": str(user["_id"])}

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
#@app.delete("/users/{id}", response_description="Delete a user")
#def delete_user(id: str, request: Request, response: Response):
    delete_result = request.app.database["users"].delete_one({"_id": id})

    if delete_result.deleted_count == 1:
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"User with ID {id} not found")



class LoginParams(BaseModel):
    username: str
    password: str

@app.post("/test-login")
def read_root(login_params: LoginParams):
    user = app.database["users"].find_one({"username":login_params.username})
    print(user)
    if user is not None:
        token=create_jwt_token(user)
        print(f"{login_params.username} -- {login_params.password}")
        return {"time":datetime.now().isoformat(), "data":"my_name","status":"success","user_id":4, "userdata":f"{login_params.username} -- {login_params.password}"}
    #token=generate_token("adam")
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    

@app.get("/")
def read_roots():
    
    #token=generate_token("adam")
    #return {generate_token(username='adam')}
    return {read_root("adam")}
    #return {token}

        


if __name__ == "__main__":
    import uvicorn
    user = app.database["users"].find_one({"username":"adam"})
    print(user)
    uvicorn.run(app, host="0.0.0.0", port=8000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       