from flask import Flask

from .config import Config
from .db import init_db
from .routes import web


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config())
    if overrides:
        app.config.update(overrides)

    init_db(app)
    app.register_blueprint(web)
    return app
