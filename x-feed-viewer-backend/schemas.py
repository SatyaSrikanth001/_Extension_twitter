from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    is_active: bool

    model_config = {
        "from_attributes": True
    }

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class SharedFeedCreate(BaseModel):
    account_id: str
    name: str
    token: str

class SharedFeedOut(BaseModel):
    id: str
    name: str
    created_at: datetime
    last_accessed: Optional[datetime]

    model_config = {
        "from_attributes": True
    }

from pydantic import BaseModel

class StoreTokenRequest(BaseModel):
    twitter_id: str
    encrypted_tokens: str