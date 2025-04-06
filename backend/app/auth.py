from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.database import get_db
from app.models import User
from app.schemas import UserCreate
from datetime import datetime, timedelta

# Налаштування для OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Налаштування для хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Ключ та алгоритм для створення JWT токенів
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

# Функція для хешування паролів
def get_password_hash(password: str):
    return pwd_context.hash(password)

# Функція для перевірки паролів
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Функція для створення JWT токенів
def create_access_token(data: dict, user: User):
    expire = datetime.utcnow() + timedelta(minutes=30)  # Calculate expiration time
    to_encode = data.copy()  # Copy the data to avoid modifying the original
    to_encode.update({"exp": expire, "role": user.role})  # Add expiration and role to the token
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Функція для отримання користувача з бази даних за логіном
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

# Функція для автентифікації користувача
def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# Функція для отримання поточного користувача за допомогою токену
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
      
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user  # Повертаємо користувача з роллю

# Для отримання тільки адміністратора
def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

# Роут для реєстрації користувача
def register_user(user: UserCreate, db: Session):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    new_user = User(username=user.username, hashed_password=get_password_hash(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user