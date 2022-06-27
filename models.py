from email.policy import default
from operator import index
from textwrap import indent
from sqlalchemy.sql.expression import null
from database import Base
from sqlalchemy import String,Boolean,Integer,Column,Text, true,ForeignKey, DateTime, TIMESTAMP
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import engine
import datetime

class Users(Base):
    __tablename__='users'
    id=Column(Integer,primary_key=True, index = True)
    username=Column(String(255),nullable=False,unique=True)
    password=Column(String(255))
    datetime = Column(DateTime, default=datetime.datetime.now)
    disabled=Column(Boolean, default = False)