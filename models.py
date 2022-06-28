from email.policy import default
from enum import unique
from locale import currency
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
    unique_customer_id = Column(String, nullable=False)
    accounting_currency = Column(String, nullable=False)
    country = Column(String, nullable=False)
    datetime = Column(DateTime, default=datetime.datetime.now)
    disabled=Column(Boolean, default = False)

class Admin(Base):
    __tablename__='admin'
    id=Column(Integer,primary_key=True, index = True)
    username=Column(String(255),nullable=False,unique=True)
    password=Column(String(255))
    datetime = Column(DateTime, default=datetime.datetime.now)
    disabled=Column(Boolean, default = False)

class Wallets(Base):
    __tablename__ = "wallets" 
    id = Column(Integer,primary_key = True, index = True)
    currency = Column(String,nullable=False)
    xpub = Column(String , nullable=False)
    memonic = Column(String , nullable=False)
    datetime = Column(DateTime, default=datetime.datetime.now)
    admin_id = Column(Integer, ForeignKey('admin.id'))

class Create_account(Base):
    __tablename__ = "users_account" 
    id = Column(Integer,primary_key = True, index = True)
    users_id = Column(Integer, ForeignKey('users.id'))
    externalId = Column(String, nullable=False)
    response_id = Column(String,nullable=False)
    currency = Column(String,nullable=False)
    frozen = Column(Boolean,nullable=False)
    active = Column(Boolean,nullable=False)
    customerId = Column(String,nullable=False)
    accountCode = Column(String,nullable=False)
    accountingCurrency = Column(String,nullable=False)

