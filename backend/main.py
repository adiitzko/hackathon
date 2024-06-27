import os
from fastapi import FastAPI,Request
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
from routes import router
import atexit


# Load environment variables from .env file
load_dotenv(".env")
frontend_url = "https://app.the-safe-zone.online"

app = FastAPI()

api_base_url = os.getenv("SERVER_NAME")

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
@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = frontend_url
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

# Define MongoDB connection setup function
def connect_to_mongo():
    mongo_uri = os.getenv("MONGO_URI")
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

@app.get("/")
def read_root():
    return {"message": "Welcome to the API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
