from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_jwt import JWT

app = Flask(__name__)
app.config['SECRET_KEY'] = "mar"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://mar:mar@localhost/mar"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True # added just to suppress a warning

# UPLOAD FOLDER
UPLOAD_FOLDER = "./app/static/uploads"

db = SQLAlchemy(app)

# Flask-Login login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config.from_object(__name__)
from app import views