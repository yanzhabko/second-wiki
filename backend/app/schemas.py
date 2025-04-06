from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    role: Optional[str] = "User"

    class Config:
        orm_mode = True