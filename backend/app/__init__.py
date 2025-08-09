from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from app.config import Config
from .models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)


    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app, origins=['http://localhost:3000'])

    with app.app_context():
        db.create_all()

    return app