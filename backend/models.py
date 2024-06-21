import uuid
from pydantic import BaseModel, Field

class Location(BaseModel):
    id: str = Field(default_factory=uuid.uuid4, alias="_id")
    user_id: str = Field(...)
    latitude: float = Field(...)
    longitude: float = Field(...)
    timestamp: str = Field(...)

class LocationUpdate(BaseModel):
    latitude: float = Field(...)
    longitude: float = Field(...)
    timestamp: str = Field(...)

class User(BaseModel):
    id: str = Field(default_factory=uuid.uuid4, alias="_id")
    username: str = Field(...)
    email: str = Field(...)
    password: str = Field(...)
    role: str = Field(...)
    phone_number: str = Field(...)

class UserUpdate(BaseModel):
    username: str = Field(None)
    email: str = Field(None)
    password: str = Field(None)
    role: str = Field(None)
    phone_number: str = Field(None)