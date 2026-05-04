from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

DATABASE_URL = 'postgresql://postgres:123456@localhost:5432/log_db'
engine = create_engine(DATABASE_URL)

session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)
