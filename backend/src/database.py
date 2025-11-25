from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

# Get DB URL from .env
DATABASE_URL = os.getenv("DATABASE_URL")

# Create Connection
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Define the "scans" table
class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    verdict = Column(String)
    risk_score = Column(Integer)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Store complex data (like heuristics) as JSON
    heuristic_data = Column(JSON)
    external_data = Column(JSON)
    screenshot_path = Column(String, nullable=True)

# Create tables
def init_db():
    Base.metadata.create_all(bind=engine)
