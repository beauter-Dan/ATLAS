from functools import lru_cache
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


def enable_sqlite_fk(engine):
    """SQLite: enforce FKs and make SAVEPOINT work (documented pysqlite workaround)."""
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _connect(dbapi_conn, _):
            dbapi_conn.isolation_level = None
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        @event.listens_for(engine, "begin")
        def _begin(conn):
            conn.exec_driver_sql("BEGIN")
    return engine


@lru_cache
def get_engine():
    return enable_sqlite_fk(create_engine(get_settings().database_url, pool_pre_ping=True))


@lru_cache
def get_sessionmaker():
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db():
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()
