from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
import requests

from database import SessionLocal, engine
from models import Base, User, SharedFeed, AccessGrant
from schemas import UserCreate, UserOut, SharedFeedCreate, SharedFeedOut, Token, StoreTokenRequest
from auth import (
    get_current_user,
    create_access_token,
    authenticate_user,
    get_password_hash
)

# ✅ Only ONE FastAPI app instance
app = FastAPI(
    title="X Feed Viewer API",
    description="Backend for the X Feed Viewer browser extension",
    version="1.0",
    debug=True
)

# ✅ CORS Middleware (once)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://dikhijadkhbaicckhieiofniahbfecgo"],  # Or set specific origin for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ DB setup
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- ROUTES ----------




@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to the X Feed Viewer API",
        "endpoints": {
            "documentation": "/docs",
            "openapi_spec": "/openapi.json",
            "authentication": "/token",
            "user_management": "/users/",
            "feed_management": "/feeds/",
            "get_feed": "/get-feed?user_id=jack"
        }
    }

@app.get("/health", tags=["Utilities"])
async def health_check():
    return {"status": "healthy"}

# ---------- AUTH ----------

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ---------- USERS ----------

@app.post("/users/", response_model=UserOut, tags=["Users"])
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# ---------- FEEDS ----------

@app.post("/feeds/", response_model=SharedFeedOut, tags=["Feeds"])
def create_shared_feed(
    feed: SharedFeedCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not feed.token or len(feed.token) < 20:
        raise HTTPException(status_code=400, detail="Invalid token format")

    db_feed = SharedFeed(
        id=feed.account_id,
        owner_id=current_user.id,
        name=feed.name,
        token=feed.token,
        created_at=datetime.utcnow(),
        last_accessed=None
    )
    db.add(db_feed)
    db.commit()
    db.refresh(db_feed)
    return db_feed

@app.get("/feeds/{feed_id}", response_model=SharedFeedOut, tags=["Feeds"])
def get_shared_feed(
    feed_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    feed = db.query(SharedFeed).filter(SharedFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    if feed.owner_id != current_user.id:
        grant = db.query(AccessGrant).filter(
            AccessGrant.feed_id == feed_id,
            AccessGrant.granted_to == current_user.id,
            AccessGrant.expires_at > datetime.utcnow()
        ).first()

        if not grant:
            raise HTTPException(status_code=403, detail="No access to this feed")

    feed.last_accessed = datetime.utcnow()
    db.commit()
    return feed

@app.post("/feeds/{feed_id}/grant-access", tags=["Access Management"])
def grant_feed_access(
    feed_id: str,
    user_email: str,
    expires_hours: int = 24,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    feed = db.query(SharedFeed).filter(
        SharedFeed.id == feed_id,
        SharedFeed.owner_id == current_user.id
    ).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found or not owned by you")

    target_user = db.query(User).filter(User.email == user_email).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    grant = AccessGrant(
        feed_id=feed_id,
        granted_to=target_user.id,
        granted_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=expires_hours)
    )
    db.add(grant)
    db.commit()
    return {"status": "success", "message": f"Access granted to {user_email}"}

@app.post("/store-token", tags=["Feeds"])
def store_token(
    token_data: StoreTokenRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    twitter_id = token_data.twitter_id
    encrypted = token_data.encrypted_tokens

    existing_feed = db.query(SharedFeed).filter(SharedFeed.id == twitter_id).first()

    if existing_feed:
        if existing_feed.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="You do not own this feed.")
        existing_feed.token = encrypted
        existing_feed.last_accessed = datetime.utcnow()
        db.commit()
        return {"status": "updated", "message": f"Token updated for {twitter_id}"}
    else:
        new_feed = SharedFeed(
            id=twitter_id,
            owner_id=current_user.id,
            name=f"{current_user.email}'s Feed",
            token=encrypted,
            created_at=datetime.utcnow(),
            is_active=True
        )
        db.add(new_feed)
        db.commit()
        return {"status": "created", "message": f"Token stored for {twitter_id}"}

# ---------- GET FEED USING TWITTER API ----------

BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAAKph2wEAAAAA4jAo1pYjiafwzEzo6UEWML%2ByzTE%3DC5XEI89p8jAzLT6TmqONwo18S0appi9eBGFDWmfQINRcYdpEJY"  # Replace with actual working token

@app.get("/get-feed", tags=["Feeds"])
async def get_feed(user_id: str):
    if not user_id:
        return {"error": "Missing user_id"}

    try:
        user_resp = requests.get(
            f"https://api.twitter.com/2/users/by/username/{user_id}",
            headers={"Authorization": f"Bearer {BEARER_TOKEN}"}
        )
        user_data = user_resp.json()
        twitter_id = user_data.get("data", {}).get("id")

        if not twitter_id:
            return {"error": "User not found on Twitter"}

        tweets_resp = requests.get(
            f"https://api.twitter.com/2/users/{twitter_id}/tweets",
            headers={"Authorization": f"Bearer {BEARER_TOKEN}"}
        )
        tweets = tweets_resp.json().get("data", [])

        feed_html = "".join([
            f"<div style='border:1px solid #ccc;padding:10px;margin:10px;'><strong>@{user_id}</strong><br>{tweet['text']}</div>"
            for tweet in tweets
        ])

        return feed_html

    except Exception as e:
        return {"error": str(e)}


# ----------------- EXTENSION INFO ----------------------

@app.get("/extension/latest-version", tags=["Extension"])
def get_latest_extension_version():
    return {
        "version": "1.0.0",
        "download_url": "https://yourdomain.com/download/extension",
        "release_notes": "Initial release"
    }

@app.get("/extension/api-endpoints", tags=["Extension"])
def get_current_api_endpoints():
    return {
        "home_timeline": "https://api.x.com/graphql/HomeTimeline",
        "auth_headers": {
            "Authorization": "Bearer {token}",
            "x-csrf-token": "required"
        }
    }
