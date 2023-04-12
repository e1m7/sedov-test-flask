import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

SECRET_KEY = os.urandom(32)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SECRET_KEY'] = SECRET_KEY
db = SQLAlchemy(app)

# --------------------------- CLASSES -------------------------------------------


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50),
                              nullable=False,
                              unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    budget = db.Column(db.Integer(), nullable=False, default=1000)
    items = db.relationship('Item', backref='owned_user', lazy=True)


class Item(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    price = db.Column(db.Integer(), nullable=False)
    barcode = db.Column(db.String(length=12), nullable=False, unique=True)
    description = db.Column(db.String(length=1024),
                            nullable=False,
                            unique=True)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __repr__(self):
        return f'Item {self.name}'


# --------------------------- FORMS -------------------------------------------

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField


class RegisterForm(FlaskForm):
    username = StringField(label='User name:')
    email_address = StringField(label='Email address:')
    password1 = PasswordField(label='Password:')
    password2 = PasswordField(label='Password repeat:')
    submit = SubmitField(label='Create Account')


# --------------------------- ROUTERS -------------------------------------------


@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')


@app.route('/market')
def market_page():
    items = Item.query.all()
    return render_template('market.html', items=items)


@app.route('/register')
def register_page():
    form = RegisterForm()
    return render_template('register.html', form=form)


app.run(host='0.0.0.0', port=81, use_reloader=True)
