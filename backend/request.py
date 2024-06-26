import requests

url = "http://localhost:8000/api/v1/users"

payload = {
    "username": "admin_user",
    "email": "admin@example.com",
    "password": "securepassword",
    "role": "admin",
    "phone_number": "1234567890"
}

headers = {
    'Content-Type': 'application/json'
}

response = requests.post(url, json=payload, headers=headers)

print(response.status_code)
print(response.json())
