from datetime import datetime , timedelta 
from jose import JWTError, jwt 
from passlib.context import CryptContext
from fastapi import HTTPException,status, Depends
from fastapi.security import OAuth2PasswordBearer 

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8


pwd_context = CryptContext(schemes=["bcrypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

USERS = {
    "admin" : {
        "username" : "admin",
        "password" : "$2b$12$FWIgDkd1IRYlXF7hWZNq8ufOw7J4L3Yh.bM8mCOKdHAnmOqw4hClC"
    }
}

def verify_password(plain, hashed) :
    return pwd_context.verify(plain ,hashed)

def authenticate_user(username, password) :
    user = USERS.get(username)
    if not  user :
        return False
    if not verify_password(password, user["password"]):
        return False
    return user 

def create_access_token(username) :
    expire =datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    encode = {"sub": username, "exp": expire}
    encoded_jwt = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)  
    return encoded_jwt

def verify_token(token = Depends(oauth2_scheme)) :
    try :
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None :
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username 
    except JWTError :
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")   
    
    
    