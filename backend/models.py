import uuid
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from datetime import datetime, timedelta



# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# class UserCreate(BaseModel):
#     id: str
#     username: str
#     password: str
#     role: str
#     phone_number: str
#     address: str
#     isInDanger: bool = False  # Default value for isInDanger
#     isAdmin:bool=False

# class Message(BaseModel):
#     send: str = Field(...)
#     content: str = Field(...)
#     time: datetime = Field(default_factory=datetime.utcnow)

# class UserDelete(BaseModel):
#     username: str= Field(None, description="Username of the user")
#     id: str = Field(None, description="ID of the user")
    
# class LoginParams(BaseModel):
#     username: str
#     password: str
