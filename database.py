import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from models import Base

DATA_DIR = "/app/data"
FIRMWARE_DIR = os.path.join(DATA_DIR, "firmware")
os.makedirs(FIRMWARE_DIR, exist_ok=True)

DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'ota.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Apply WAL journal mode so concurrent device check-ins don't block reads.
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

# Any pre-pivot SQLite file will keep old orphaned tables (carrier_boards,
# application_groups, firmware_releases, labels, firmware) alongside the new
# ones since create_all only adds missing tables. This is harmless clutter,
# not a crash risk. An operator who wants a clean slate can delete the old
# data file.


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
