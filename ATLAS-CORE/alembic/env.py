from alembic import context
from sqlalchemy import create_engine, pool
from app.core.config import get_settings
from app.db.session import Base
import app.models  # noqa: F401

target_metadata = Base.metadata
url = get_settings().database_url


def run_migrations_offline():
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
