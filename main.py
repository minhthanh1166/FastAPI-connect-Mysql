import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from typing import Annotated

from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

import auth
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from auth import get_current_active_user
from auth import get_password_hash
from firebase_storage import delete_to_firebase_storage
from firebase_storage import update_to_firebase_storage
from firebase_storage import upload_to_firebase_storage

app = FastAPI()
# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, you might want to specify specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all HTTP headers
)

app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_active_user)]


@app.get("/", status_code=status.HTTP_200_OK)
async def users(user: user_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication failed")
    return {"User": user}


# Get all users
@app.get("/users", status_code=status.HTTP_200_OK)
async def users(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication failed")
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to access this resource")
    data_user = db.query(models.User).all()
    return {"Users": data_user}


# Put user
# @app.put("/user/{id}")
# async def put_user(id: int,
#                    db: db_dependency,
#                    user: user_dependency,
#                    full_name: str | None = None,
#                    email: str = None,
#                    username: str = None,
#                    password: str = None,
#                    is_active: bool = None,
#                    role: str = None,
#                    file: UploadFile = File(None)):
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                             detail="Authentication failed")
#     if user["role"] != "admin":
#         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
#                             detail="You don't have permission to access this resource")
#     user = db.query(models.User).filter(models.User.id == id).first()
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                             detail="User not found")
#     if full_name is not None:
#         user.full_name = full_name
#     if email is not None:
#         user.email = email
#     if username is not None:
#         user.username = username
#     if password is not None:
#         user.hashed_password = get_password_hash(password)
#     if is_active is not None:
#         user.is_active = is_active
#     if role is not None:
#         user.role = role
#     if file is not None:
#         if user.image is not None:
#             user.image = update_to_firebase_storage(file, user.image)
#         else:
#             user.image = upload_to_firebase_storage(file)
#     db.commit()
#     db.refresh(user)
#     return {"message": "User updated successfully"}

class create_form_user(BaseModel):
    id: int
    full_name: str | None = None
    email: str | None = None
    username: str | None = None
    password: str | None = None
    is_active: bool | None = None
    role: str | None = None
    file: UploadFile = File(None)


@app.put("/user/{id}")
async def put_user(db: db_dependency,
                   user: user_dependency,
                   form_data: Annotated[create_form_user, Depends(create_form_user)]):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication failed")
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to access this resource")
    user = db.query(models.User).filter(models.User.id == form_data.id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found")
    if form_data.full_name is not None:
        user.full_name = form_data.full_name
    if form_data.email is not None:
        user.email = form_data.email
    if form_data.username is not None:
        user.username = form_data.username
    if form_data.password is not None:
        user.hashed_password = get_password_hash(form_data.password)
    if form_data.is_active is not None:
        user.is_active = form_data.is_active
    if form_data.role is not None:
        user.role = form_data.role
    if form_data.file is not None:
        if user.image is not None:
            user.image = update_to_firebase_storage(form_data.file, user.image)
        else:
            user.image = upload_to_firebase_storage(form_data.file)
    db.commit()
    db.refresh(user)
    return {"message": "User updated successfully"}


# Delete user
@app.delete("/user/{id}", status_code=status.HTTP_200_OK)
async def delete_user(id: int, user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authentication failed")
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to access this resource")
    user = db.query(models.User).filter(models.User.id == id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found")
    if user.image is not None:
        delete_to_firebase_storage(user.image)

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)
