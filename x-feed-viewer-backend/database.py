from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# ✅ 1. Update with your actual PostgreSQL credentials:
# Format: postgresql://<username>:<password>@<host>/<database>
# SQLALCHEMY_DATABASE_URL = "postgresql://xfeeduser:twitter@localhost:5432/xfeeddb"
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")
# ✅ 2. Create the engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True
)

# ✅ 3. Create a configured session class
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# ✅ 4. Base class for all SQLAlchemy models
Base = declarative_base()

# ✅ 5. Dependency to be used in FastAPI endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
