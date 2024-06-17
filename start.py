from motor.motor_asyncio import AsyncIOMotorClient
from uuid import uuid4
from datetime import datetime
import asyncio
from pymongo import GEOSPHERE  # Import GEOSPHERE for creating geospatial index

# Replace <password> with your actual password
URI_STRING = "mongodb+srv://adiitzko:<password>@cluster0.is6jut3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
URI_STRING = URI_STRING.replace("<password>", "adiitz2004")

# Connect to MongoDB
client = AsyncIOMotorClient(URI_STRING)
db = client.my_database

# Collections
users_collection = db.users
locations_collection = db.locations

# Function to create a new user document in MongoDB
async def create_user(username, password_hash, role, full_name):
    user = {
        "userId": str(uuid4()),
        "username": username,
        "passwordHash": password_hash,
        "role": role,
        "fullName": full_name,
        "lastLocation": None,
        "lastUpdateTime": None
    }
    # Insert the user document into the 'users' collection
    await users_collection.insert_one(user)
    return user

# Function to update the location of a user in MongoDB
async def update_location(user_id, latitude, longitude):
    location = {
        "locationId": str(uuid4()),
        "userId": user_id,
        "location": {"type": "Point", "coordinates": [longitude, latitude]},  # GeoJSON Point format
        "timestamp": datetime.utcnow()
    }
    # Insert the location document into the 'locations' collection
    await locations_collection.insert_one(location)

    # Update the user document with the new location information
    await users_collection.update_one(
        {"userId": user_id},
        {"$set": {
            "lastLocation": {"latitude": latitude, "longitude": longitude},
            "lastUpdateTime": datetime.utcnow()
        }}
    )
    return location

# Function to retrieve all locations of a specific user from MongoDB
async def get_user_locations(user_id):
    locations = []
    cursor = locations_collection.find({"userId": user_id})
    async for document in cursor:
        locations.append(document)
    return locations

# Function to retrieve the locations of all users with role "warrior" from MongoDB
async def get_all_warrior_locations():
    cursor = users_collection.find(
        {"role": "warrior"}, 
        {"_id": 0, "userId": 1, "lastLocation": 1, "fullName": 1}
    )
    warriors = []
    async for document in cursor:
        warriors.append(document)
    return warriors

# Function to find warriors near a specified event location within a certain distance
async def find_warriors_near_event(event_latitude, event_longitude, max_distance_km=10):
    # Ensure that the geospatial index is created on the 'locations' collection
    await locations_collection.create_index([("location", GEOSPHERE)])

    # Await the result of get_all_warrior_locations() before using it in the query
    warrior_locations = await get_all_warrior_locations()

    # Construct the query to find warriors near the event location within the specified distance
    event_location = {
        "type": "Point",
        "coordinates": [event_longitude, event_latitude]
    }

    # Build a list of warrior user IDs
    warrior_user_ids = [warrior["userId"] for warrior in warrior_locations]

    # Perform a geospatial query to find warriors near the event location within the specified distance
    cursor = locations_collection.find({
        "location": {
            "$nearSphere": {
                "$geometry": event_location,
                "$maxDistance": max_distance_km * 1000  # Convert kilometers to meters
            }
        },
        "userId": {"$in": warrior_user_ids}
    })

    # Collect the warriors near the event location
    warriors_near_event = []
    async for document in cursor:
        warriors_near_event.append(document)

    return warriors_near_event


# Main function to demonstrate usage of the above functions
async def main():
    # Ensure that the geospatial index is created on the 'locations' collection
    await locations_collection.create_index([("location", GEOSPHERE)])

    # Create a new user
    new_user = await create_user("john_doe", "hashed_password", "warrior", "John Doe")
    print("New User:", new_user)

    # Update the location of the new user
    new_location = await update_location(new_user["userId"], 34.052235, -118.243683)
    print("Updated Location:", new_location)

    # Retrieve all locations of the new user
    user_locations = await get_user_locations(new_user["userId"])
    print("User Locations:", user_locations)

    # Retrieve the locations of all warriors
    all_warrior_locations = await get_all_warrior_locations()
    print("All Warrior Locations:", all_warrior_locations)

    # Find warriors near a specified event location
    event_latitude = 34.052235
    event_longitude = -118.243683
    warriors_near_event = await find_warriors_near_event(event_latitude, event_longitude)
    print(f"Warriors near event at ({event_latitude}, {event_longitude}):")
    print(warriors_near_event)

# Run the main function asynchronously
asyncio.run(main())
