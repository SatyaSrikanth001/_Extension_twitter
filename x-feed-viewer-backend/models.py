from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

# ------------------------
# User Table
# ------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

    shared_feeds = relationship("SharedFeed", back_populates="owner")


# ------------------------
# Shared Feed Table
# ------------------------
class SharedFeed(Base):
    __tablename__ = "shared_feeds"

    id = Column(String, primary_key=True, index=True)  # e.g., acc_12345
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    token = Column(String, nullable=False)
    created_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    last_accessed = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="shared_feeds")
    access_grants = relationship("AccessGrant", back_populates="feed")


# ------------------------
# Access Grant Table
# ------------------------
class AccessGrant(Base):
    __tablename__ = "access_grants"

    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(String, ForeignKey("shared_feeds.id"), nullable=False)
    granted_to = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime)
    expires_at = Column(DateTime)

    feed = relationship("SharedFeed", back_populates="access_grants")
