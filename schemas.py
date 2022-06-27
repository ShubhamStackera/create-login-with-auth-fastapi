from symtable import Symbol
from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel


        
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str

class query_symbol(BaseModel):
    pass

class create_users(BaseModel):
    username:str
    password:str
    class Config:
        orm_mode=True