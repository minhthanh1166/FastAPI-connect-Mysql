from datetime import timedelta, datetime, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from starlette import status
from database import SessionLocal
import models
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


class UserRequest(BaseModel):
    full_name: str
    email: str
    username: str
    password: str
    role: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Token:
    access_token: str
    token_type: str


db_dependency = Annotated[Session, Depends(get_db)]


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(password, hashed_password):
    print("Password:", password)
    print("Stored Hash:", hashed_password)
    try:
        result = pwd_context.verify(password, hashed_password)
        print("Verification Result:", result)
        return result
    except Exception as e:
        print("Error during verification:", e)
        return False


def authenticate_user(username, password, db):
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user:
        return False

    # Verify the password using the existing hash
    if not verify_password(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@router.post("/login")
async def login_for_access_token(db: db_dependency, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={
            'username': user.username,
            'full_name': user.full_name,
            'role': user.role
        },
        expires_delta=access_token_expires)
    return {'access_token': token, 'token_type': 'bearer'}


async def get_current_active_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        role = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

        return {'username': username, 'role': role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")


# Create user with role admin
def create_user_role_admin():
    try:
        # Kiểm tra xem tài khoản đã tồn tại chưa
        db = SessionLocal()
        user = db.execute(models.User.__table__.select().where(models.User.username == 'admin'))
        existing_user = user.fetchone()

        if existing_user:
            return 'User already exists'

        # Tạo mới người dùng
        new_user = models.User(
            full_name='Bui Minh Thanh',
            email='buiminhthanh116@gmal.com',
            username='admin',
            hashed_password=get_password_hash('1234'),
            is_active=True,
            role='admin'
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print('Create user admin successfully')
        return 'Status: 200'
    except Exception as e:
        print(e)
        return 'Status: 500'


create_user_role_admin()


@router.post("/register-user", status_code=status.HTTP_201_CREATED)
async def create_user(
        db: db_dependency,
        create_user_request: UserRequest,
):
    # Kiểm tra xem tài khoản đã tồn tại chưa
    user = db.query(models.User).filter(models.User.username == create_user_request.username).first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    # Tạo mới người dùng
    new_user = models.User(
        full_name=create_user_request.full_name,
        email=create_user_request.email,
        username=create_user_request.username,
        hashed_password=get_password_hash(create_user_request.password),
        is_active=True,
        role='customer'
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}


@router.post("/register-admin", status_code=status.HTTP_201_CREATED)
async def create_user(
        db: db_dependency,
        create_user_request: UserRequest,
        user_dependency: Annotated[dict, Depends(get_current_active_user)]
):
    # Kiểm tra xem tài khoản đã tồn tại chưa
    user = db.query(models.User).filter(models.User.username == create_user_request.username).first()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    if user_dependency["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You don't have permission to access this resource")

    # Tạo mới người dùng
    new_user = models.User(
        full_name=create_user_request.full_name,
        email=create_user_request.email,
        username=create_user_request.username,
        hashed_password=get_password_hash(create_user_request.password),
        is_active=True,
        role=create_user_request.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}
