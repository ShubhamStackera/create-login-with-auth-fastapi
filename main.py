from datetime import datetime, timedelta
from typing import Union
from venv import create
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from typing import Optional,List
import models
import schemas
import uuid 
from pybit import inverse_perpetual, usdt_perpetual
from sqlalchemy import DateTime, update
import requests

models.Base.metadata.create_all(bind=engine)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

db = SessionLocal()

session_unauth = inverse_perpetual.HTTP(endpoint="https://api-testnet.bybit.com")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="get-token-user")
oauth2_scheme2 = OAuth2PasswordBearer(tokenUrl="get-token-admin")

admin_apikey = "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"

app = FastAPI(title="Blockchain")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session,username: str):
    return db.query(models.Users).filter(models.Users.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
 
def get_admin(db: Session,username: str):
    return db.query(models.Admin).filter(models.Admin.username == username).first()

def authenticate_admin(db, username: str, password: str):
    user = get_admin(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
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
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin(token: str = Depends(oauth2_scheme2)):
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
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_admin(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_active_admin(current_user: schemas.Admin = Depends(get_current_admin)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive admin")
    return current_user

@app.post("/get-token-user", response_model= schemas.Token,tags=["Users"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user=db.query(models.Users).filter(models.Users.username==form_data.username).first()
    # user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        print(form_data.password)
        print(user.password)
        ans = pwd_context.verify(form_data.password, user.password)
        if ans == True:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user.username}, expires_delta=access_token_expires
            )
            return {"access_token": access_token, "token_type": "bearer"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND , detail= "Wrong password")

@app.post('/create-an-user',status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_an_Users(Users:schemas.create_users):
    db_Users=db.query(models.Users).filter(models.Users.username==Users.username).first()
    if db_Users is not None:
        raise HTTPException(status_code=400,detail="Users already exists")
    generate_unique_customer_id = str(uuid.uuid1())[0:6]
    hash_password = pwd_context.hash(Users.password)
    new_Users=models.Users(
        username=Users.username,
        password=hash_password,
        unique_customer_id = generate_unique_customer_id,
        accounting_currency = Users.accounting_currency,
        country = Users.country
    )

    db.add(new_Users)
    db.commit()
    db.refresh(new_Users)
    return new_Users
    
@app.get("/read-user", tags=["Users"])
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user

@app.post("/create-new-account", tags=["Users"])
async def createaccount( createaccount : schemas.createaccount ,current_user: schemas.User = Depends(get_current_user)):
    get_xpub_from_db = db.query(models.Wallets).filter(models.Wallets.admin_id == 1).first()

    url = "https://api-eu1.tatum.io/v3/ledger/account"

    payload = {
    "currency": createaccount.currency,
    "xpub": get_xpub_from_db.xpub,
    "customer": {
        "accountingCurrency": current_user.accounting_currency,
        "customerCountry": current_user.country,
        "externalId": current_user.unique_customer_id,
        "providerCountry": "US"
    },
    "compliant": False,
    "accountCode": "AC_1011_B",
    "accountingCurrency": "USD",
    "accountNumber": "123456"
    }

    headers = {
    "Content-Type": "application/json",
    "x-api-key": "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"
    }

    response = requests.post(url, json=payload, headers=headers)
    data = response.json()

    Create_account=models.Create_account(
        users_id = current_user.id,
        externalId= current_user.unique_customer_id,
        response_id = data["id"],
        currency = createaccount.currency,
        frozen = data["frozen"],
        active = data["active"],
        customerId = data["customerId"],
        accountCode = data["accountCode"],
        accountingCurrency = data["accountingCurrency"]
    )

    db.add(Create_account)
    db.commit()
    db.refresh(Create_account)
    return Create_account

@app.post("/create-new-deposit-address", tags=["Users"])
async def generatedepositaddress(current_user: schemas.User = Depends(get_current_user)):
    get_user_details = db.query(models.Create_account).filter(models.Create_account.users_id == current_user.id).first()
    print(get_user_details)
    id = get_user_details.response_id
    url = "https://api-eu1.tatum.io/v3/offchain/account/" + id + "/address"

    headers = {"x-api-key": "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"}

    response = requests.post(url, headers=headers)

    data = response.json()

    generate_deposit_address = models.GenerateDepositAddress(
        address = data["address"],
        currency = data["currency"],
        derivationkey =  data["derivationKey"],
        xpub = data["xpub"],
        users_id = current_user.id
    )
    db.add(generate_deposit_address)
    db.commit()
    db.refresh(generate_deposit_address)
    
    return(data)

@app.post("/get-account-balance", tags=["Users"])
async def getAccountBalance(get_id : schemas.getaccountbalance):
    id = get_id.id
    print(id)
    url = "https://api-eu1.tatum.io/v3/ledger/account/" + id + "/balance"

    headers = {"x-api-key": "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"}

    response = requests.get(url, headers=headers)

    data = response.json()
    return(data)

@app.post("/send-btc", tags=["Users"])
async def sendbtc(address : schemas.Address , current_user: schemas.User = Depends(get_current_user)):
    get_user_details = db.query(models.Create_account).filter(models.Create_account.users_id == current_user.id).first()
    print(get_user_details)
    id = get_user_details.response_id
    url = "https://api-eu1.tatum.io/v3/offchain/bitcoin/transfer"

    print("------------------------",id,address.address)
    payload = {
    "senderAccountId": id,
    "address": address.address,
    "amount": "0.00001",
    "compliant": False,
    "fee": "0.00001",
    "attr": "string",
    "mnemonic": "witch collapse practice feed shame open despair creek road again ice least",
    "xpub": "tpubDFFwQX2CCeULuLwkJkYwgu9xbzTMYHqmr7YnwkVttYLSPhvLK7cCxu3MYykPFHf7iN38J71VCfcKua8ojipomou2o1rGk6VfLJ1DMoSnaxV",
    "paymentId": "12345",
    "senderNote": "Sender note 2"
    }
    headers = {
    "Content-Type": "application/json",
    "x-api-key": "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"
    }

    response = requests.post(url, json=payload, headers=headers)

    data = response.json()

    # sendingbtc = models.sendingbtc(
    #     txId = data["txId"],
    #     id = data["id"],
    #     completed =  data["completed"]
    # )

    # db.add(sendingbtc)
    # db.commit()
    # db.refresh(sendingbtc)
    return(data)
    
#----------------------------------------------------------------------------------------------------------------------

@app.post('/create-an-admin',response_model=schemas.create_admin,status_code=status.HTTP_201_CREATED, tags=["Admin"])
def create_an_admin(Users:schemas.create_admin):
    db_Users=db.query(models.Admin).filter(models.Admin.username==Users.username).first()

    if db_Users is not None:
        raise HTTPException(status_code=400,detail="Users already exists")

    hash_password = pwd_context.hash(Users.password)
    new_Users=models.Admin(
        username=Users.username,
        password=hash_password,
    )

    db.add(new_Users)
    db.commit()
    db.refresh(new_Users)
    return new_Users

@app.post("/get-token-admin", response_model= schemas.Token,tags=["Admin"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user=db.query(models.Admin).filter(models.Admin.username==form_data.username).first()
    # user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        print(form_data.password)
        print(user.password)
        ans = pwd_context.verify(form_data.password, user.password)
        if ans == True:
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user.username}, expires_delta=access_token_expires
            )
            return {"access_token": access_token, "token_type": "bearer"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND , detail= "Wrong password")

@app.get("/read-admin", tags=["Admin"])
async def read_users_me(current_user: schemas.Admin = Depends(get_current_admin)):
    return current_user


@app.post('/generate-Bitcoin-wallet',tags=["Admin"])
async def BtcGenerateWallet(key : schemas.wallets, current_user: schemas.Admin = Depends(get_current_admin) ):
    url = "https://api-eu1.tatum.io/v3/bitcoin/wallet"
    query = {
    "mnemonic": key.mnemonic
    }

    headers = {"x-api-key": key.xapikey}

    response = requests.get(url, headers=headers, params=query)

    data = response.json()
    print(data) 
    mnemonic = data['mnemonic']
    xpub = data['xpub']
    index = "1"
    url = "https://api-eu1.tatum.io/v3/bitcoin/address/" + xpub + "/" + index

    headers = {"x-api-key": key.xapikey}

    response = requests.get(url, headers=headers)

    data2 = response.json()
    print(data2)

    wallets=models.Wallets(
        currency=key.currency,
        xpub=xpub,
        memonic = mnemonic,
        admin_id = current_user.id
    )

    db.add(wallets)
    db.commit()
    db.refresh(wallets)
    return wallets