import requests

url = 'http://localhost:8000/api/v1/locations'

# נתוני המיקום שתרצה להוסיף
new_location = {
    "user_id": "user123",
    "latitude": 40.7128,
    "longitude": -74.006,
    "timestamp": "2024-06-21T12:00:00Z"
}

# שליחת בקשת POST ליצירת המיקום
response = requests.post(url, json=new_location)

if response.status_code == 201:
    print("Location added successfully!")
else:
    print("Failed to add location:", response.json())
