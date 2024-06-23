import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pymongo import MongoClient
from dotenv import load_dotenv
from routes import router as location_router

# Load environment variables from .env file
load_dotenv(".env")

app = FastAPI()

# CORS (Cross-Origin Resource Sharing) middleware
origins = [
    "http://localhost:3000",
    "https://localhost",
    # Add more origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define MongoDB connection setup function
def connect_to_mongo():
    mongo_uri = os.getenv("MONGO_URI")
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
import atexit
atexit.register(close_mongo_connection)

# Include router for location API
app.include_router(location_router, tags=["locations"], prefix="/api/v1/locations")

@app.get("/")
def read_root():
    return {"message": "Welcome to the API"}

# HTTP Basic Authentication
security = HTTPBasic()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = os.getenv("BASIC_AUTH_USERNAME")
    correct_password = os.getenv("BASIC_AUTH_PASSWORD")
    if not (credentials.username == correct_username and credentials.password == correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

@app.get("/secure-data", dependencies=[Depends(authenticate)])
def secure_data():
    return {"message": "This is secure data"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)#, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
