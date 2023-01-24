from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, date
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']="mysql+pymysql://pierre:password123@localhost/users"
app.config['SECRET_KEY'] = "hjhjdgjfgjkvgiorugfrkjbgvndfm,k.hdklkhedfjkbdkjgf h HJW FLhjfkd manmfd,kffvkljhdej"
db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True)
    age = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(128))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    posts = db.relationship('Posts', backref='poster')
    
    @property
    def password(self):
        raise AttributeError("Password is not a readable Attribute!")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password=password, method="pbkdf2:sha256")

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


    def __repr__(self):
        return '<Name %r>' % self.name

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    # author = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255))
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Verifier(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
