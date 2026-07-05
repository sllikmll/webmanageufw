from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

Base = declarative_base()
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False))
engine = None


def init_db(app):
    global engine
    database_url = app.config['DATABASE_URL']
    if database_url.startswith('sqlite:///'):
        sqlite_path = Path(database_url.removeprefix('sqlite:///'))
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    connect_args = {'check_same_thread': False} if database_url.startswith('sqlite') else {}
    engine = create_engine(database_url, future=True, connect_args=connect_args)
    SessionLocal.configure(bind=engine)

    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_servers_name ON servers (name)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_servers_host ON servers (host)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_servers_auth_type ON servers (auth_type)'))

    @app.teardown_appcontext
    def cleanup(_exc=None):
        SessionLocal.remove()
