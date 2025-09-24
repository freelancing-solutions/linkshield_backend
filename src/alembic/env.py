import asyncio, os, sys
from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context

# ------------- path & model imports -------------
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# import every model package so SQLModel.metadata is complete
from src.models import user, url_check, report, subscription, ai_analysis  # noqa: F401
from src.config.database import Base   # <- single Base you used in metadata
from src.config.settings import Settings
# ------------- Alembic config -------------

target_metadata = Base.metadata


def get_url() -> str:
    """Same logic you already had."""
    return Settings().DATABASE_URL


# ------------- offline mode (sync) -------------
def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ------------- online mode (async) -------------
def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    conf_dict = {"url": get_url()}
    connectable = async_engine_from_config(
        conf_dict, prefix="", poolclass=pool.NullPool
    )
    async with connectable.connect() as conn:
        await conn.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ------------- entrypoint -------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()