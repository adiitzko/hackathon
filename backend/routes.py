# from multiprocessing import get_context
# from fastapi import APIRouter, Body, Request, Response, HTTPException, status
# from fastapi.encoders import jsonable_encoder
# from typing import List
# from passlib.context import CryptContext


# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# from models import Location, LocationUpdate, User, UserUpdate

# router = APIRouter()



# @router.post("/locations", response_description="Create a new location", status_code=status.HTTP_201_CREATED, response_model=Location)
# def create_location(request: Request, location: Location = Body(...)):
#     location = jsonable_encoder(location)
#     new_location = request.app.database["locations"].insert_one(location)
#     created_location = request.app.database["locations"].find_one(
#         {"_id": new_location.inserted_id}
#     )

#     return created_location

# @router.get("/locations", response_description="List all locations", response_model=List[Location])
# def list_locations(request: Request):
#     locations = list(request.app.database["locations"].find(limit=100))
#     return locations

# @router.get("/locations/{id}", response_description="Get a single location by id", response_model=Location)
# def find_location(id: str, request: Request):
#     if (location := request.app.database["locations"].find_one({"_id": id})) is not None:
#         return location

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"Location with ID {id} not found")

# @router.put("/locations/{id}", response_description="Update a location", response_model=Location)
# def update_location(id: str, request: Request, location: LocationUpdate = Body(...)):
#     location = {k: v for k, v in location.dict().items() if v is not None}

#     if len(location) >= 1:
#         update_result = request.app.database["locations"].update_one(
#             {"_id": id}, {"$set": location}
#         )

#         if update_result.modified_count == 0:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND, detail=f"Location with ID {id} not found")

#     if (
#         existing_location := request.app.database["locations"].find_one({"_id": id})
#     ) is not None:
#         return existing_location

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"Location with ID {id} not found")

# @router.delete("/locations/{id}", response_description="Delete a location")
# def delete_location(id: str, request: Request, response: Response):
#     delete_result = request.app.database["locations"].delete_one({"_id": id})

#     if delete_result.deleted_count == 1:
#         response.status_code = status.HTTP_204_NO_CONTENT
#         return response

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"Location with ID {id} not found")

# @router.post("/users", response_description="Create a new user", status_code=status.HTTP_201_CREATED, response_model=User)
# def create_user(request: Request, user: User = Body(...)):
#     user = jsonable_encoder(user)
#     new_user = request.app.database["users"].insert_one(user)
#     created_user = request.app.database["users"].find_one(
#         {"_id": new_user.inserted_id}
#     )

#     return created_user

# @router.get("/users", response_description="List all users", response_model=List[User])
# def list_users(request: Request):
#     users = list(request.app.database["users"].find(limit=100))
#     return users

# @router.get("/users/{id}", response_description="Get a single user by id", response_model=User)
# def find_user(id: str, request: Request):
#     if (user := request.app.database["users"].find_one({"_id": id})) is not None:
#         return user

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"User with ID {id} not found")

# @router.put("/users/{id}", response_description="Update a user", response_model=User)
# def update_user(id: str, request: Request, user: UserUpdate = Body(...)):
#     user = {k: v for k, v in user.dict().items() if v is not None}

#     if len(user) >= 1:
#         update_result = request.app.database["users"].update_one(
#             {"_id": id}, {"$set": user}
#         )

#         if update_result.modified_count == 0:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID {id} not found")

#     if (
#         existing_user := request.app.database["users"].find_one({"_id": id})
#     ) is not None:
#         return existing_user

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"User with ID {id} not found")

# @router.delete("/users/{id}", response_description="Delete a user")
# def delete_user(id: str, request: Request, response: Response):
#     delete_result = request.app.database["users"].delete_one({"_id": id})

#     if delete_result.deleted_count == 1:
#         response.status_code = status.HTTP_204_NO_CONTENT
#         return response

#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                         detail=f"User with ID {id} not found")


# @router.post("/users/check", response_description="Check user credentials")
# def check_user_credentials(request: Request, username: str = Body(...), password: str = Body(...)):
#     user = request.app.database["users"].find_one({"username": username, "password": password})
#     if user is not None:
#         return {"status": "success", "user_id": user["_id"]}
#     else:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid username or password"
#         )
    

# @router.post("/users/check-admin", response_description="Check if user is an admin")
# def check_if_admin(request: Request, username: str = Body(...), password: str = Body(...)):
#     user = request.app.database["users"].find_one({"username": username})
#     if user and pwd_context.verify(password, user["password"]):
#         is_admin = user["role"] == "admin"
#         return {"is_admin": is_admin}
#     else:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid username or password"
#         )

