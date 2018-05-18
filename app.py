from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
database_file = "sqlite:///{}".format(os.path.join(os.path.dirname(os.path.abspath(__file__)), "flaskkv.db"))
app.config['SQLALCHEMY_DATABASE_URI'] = database_file
db=SQLAlchemy(app)

class DataPair(db.Model):
    __tableName__ = 'DataPair'
    id = db.Column('id', db.Integer, primary_key=True)
    key = db.Column('key', db.String(100), nullable=False)
    value = db.Column('value', db.String(100), nullable=False)
    author = db.Column('author', db.String(50), nullable=False)

    def __init__(self, key, value, author):
        self.key = key
        self.value = value
        self.author = author

class Users(db.Model):
    __tableName__ = 'Users'
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(50), nullable=False)
    email = db.Column('email', db.String(25), nullable=False, unique=True)
    password = db.Column('password', db.String(50), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


@app.route('/init')
def create_database():
    db.create_all()
    flash('Database initialized', 'success')
    return redirect(url_for('index'))


@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('home.html')

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))
        new_user = Users(name, email, password)
        db.session.add(new_user)
        db.session.commit()
        flash('Successfully registered. You can now login using your email and password', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        post_email = request.form['email']
        post_password = request.form['password']

        user_record = Users.query.filter_by(email=post_email).first()
        if user_record is not None:
            if sha256_crypt.verify(post_password, user_record.password):
                session['logged_in'] = True
                session['email'] = post_email
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login credentials'
                return render_template('login.html', error=error)
        else:
            error = 'Email ID does not exits'
            return render_template('login.html', error=error)
    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


class AddKeyValueForm(Form):
    key = StringField('Key', [validators.Length(min=1, max=100)])
    value = TextAreaField('Value', [validators.Length(min=1, max=100)])

@app.route('/set', methods=['GET', 'POST'])
@is_logged_in
def set_new_kv():
    form = AddKeyValueForm(request.form)
    if request.method == 'POST' and form.validate():
        post_key = form.key.data
        post_value = form.value.data
        data_pair = DataPair(key=post_key, value=post_value, author=session['email'])
        db.session.add(data_pair)
        db.session.commit()
        flash('Added new Key-Value', 'success')
        return redirect(url_for('dashboard'))
    return render_template('set.html', form=form)



class GetKeyValueForm(Form):
    key = StringField('Key', [validators.Length(min=1, max=100)])

@app.route('/get', methods=['GET', 'POST'])
@is_logged_in
def get_new_kv():
    form = GetKeyValueForm(request.form)
    if request.method == 'POST' and form.validate():
        post_key = form.key.data
        data_pair = DataPair.query.filter_by(key=post_key, author=session['email']).first()
        if data_pair is not None:
            flash('Key = ' + data_pair.key + ' and the value = ' + data_pair.value, 'success')
        else:
            flash(post_key + ', does not exists.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('get.html', form=form)



if __name__ == '__main__':
    app.secret_key='thisIsTheSecret'
    app.run(debug=True)
