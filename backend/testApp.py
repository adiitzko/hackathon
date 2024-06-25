import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient
from bson import ObjectId
from main import app, connect_to_mongo, close_mongo_connection

client = TestClient(app)

# Setup and teardown for MongoDB connection in testing
@pytest.fixture(scope="module", autouse=True)
def setup_teardown():
    connect_to_mongo()
    yield
    close_mongo_connection()

# Sample data for testing
sample_location_id = str(ObjectId())
sample_location_data = {
    "id": sample_location_id,
    "user_id": "user123",
    "latitude": 40.7128,
    "longitude": -74.006,
    "timestamp": "2024-06-21T12:00:00Z"
}

sample_user_id = str(ObjectId())
sample_user_data = {
    "id": sample_user_id,
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "password123",
    "role": "admin",
    "phone_number": "1234567890"
}

# Test cases for locations endpoint
def test_create_location():
    response = client.post("/api/v1/locations", json=sample_location_data)
    assert response.status_code == 201
    created_location = response.json()
    assert created_location["user_id"] == sample_location_data["user_id"]

def test_list_locations():
    response = client.get("/api/v1/locations")
    assert response.status_code == 200
    locations = response.json()
    assert len(locations) > 0

def test_get_location():
    response = client.get(f"/api/v1/locations/{sample_location_id}")
    assert response.status_code == 200
    location = response.json()
    assert location["id"] == sample_location_id

def test_update_location():
    updated_data = {
        "latitude": 45.0,
        "longitude": -75.0,
        "timestamp": "2024-06-21T13:00:00Z"
    }
    response = client.put(f"/api/v1/locations/{sample_location_id}", json=updated_data)
    assert response.status_code == 200
    updated_location = response.json()
    assert updated_location["latitude"] == updated_data["latitude"]

def test_delete_location():
    response = client.delete(f"/api/v1/locations/{sample_location_id}")
    assert response.status_code == 204

# Test cases for users endpoint
def test_create_user():
    response = client.post("/api/v1/users", json=sample_user_data)
    assert response.status_code == 201
    created_user = response.json()
    assert created_user["username"] == sample_user_data["username"]

def test_list_users():
    response = client.get("/api/v1/users")
    assert response.status_code == 200
    users = response.json()
    assert len(users) > 0

def test_get_user():
    response = client.get(f"/api/v1/users/{sample_user_id}")
    assert response.status_code == 200
    user = response.json()
    assert user["id"] == sample_user_id

def test_update_user():
    updated_data = {
        "username": "updateduser",
        "email": "updateduser@example.com"
    }
    response = client.put(f"/api/v1/users/{sample_user_id}", json=updated_data)
    assert response.status_code == 200
    updated_user = response.json()
    assert updated_user["username"] == updated_data["username"]

def test_delete_user():
    response = client.delete(f"/api/v1/users/{sample_user_id}")
    assert response.status_code == 20
