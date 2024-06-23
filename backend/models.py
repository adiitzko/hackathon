import uuid
from pydantic import BaseModel, Field
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Location(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    user_id: str = Field(...)
    latitude: float = Field(...)
    longitude: float = Field(...)
    timestamp: str = Field(...)

class LocationUpdate(BaseModel):
    latitude: float = Field(...)
    longitude: float = Field(...)
    timestamp: str = Field(...)

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    username: str = Field(...)
    email: str = Field(...)
    password: str = Field(...)
    role: str = Field(...)
    phone_number: str = Field(...)

    # def hash_password(self):
    #     self.password = pwd_context.hash(self.password)

class UserUpdate(BaseModel):
    username: str = Field(None)
    email: str = Field(None)
    password: str = Field(None)
    role: str = Field(None)
    phone_number: str = Field(None)

# # בשימוש בעת יצירת משתמש
# new_user = User(
#     username="example_user",
#     email="user@example.com",
#     password="password123",
#     role="user",
#     phone_number="123456789"
# )

# new_user.hash_password()
# print(new_user.password)  # ידפיס את הסיסמה המוצפנת
