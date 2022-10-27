from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User
from forms import UserForm

def awful_hash(phrase):
    return ''.join(next_char(c) for c in phrase) 
# you should get the same output ALWAYS example 'hello' turns to 'ifmmp' ALWAYS
# this is awful because it is not exactly a "one-way" function

def slightly_better_hash(phrase):
    return ''.join(next_char(c) for c in phrase[0:8:2])
#is one way, but because we limit the amount of characters, larger phrases that have similar first letters as a smaller phrase will give the same output 
#this could make someone login with an INCORRECT password (but similar enough) and still gain access to our website/app/etc

# SALTING HASH
def salting_hash(phrase, salt=None):
    if salt is None:
        salt = str(randint(1000,9999))
        
    hashed = slightly_better_hash(f'{phrase}{salt}')
    return f'{hashed}{salt}'
# this is what bcrypt does

@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registerform()
    
    if form.validate_on_submit():
        name= form.username.data
        pwd = form.password.data

        user = User.register(name,pwd)
        # classmethod
        db.session.add(user)
        db.session.commit()

        sesson['user_id'] = user.id

        return redirect('/secret')
    else:
        return render_template('register.html' form=form)

# another way to register using forms.py
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = Userform()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        new_user = User.register(username, password)

        db.session.add(new_user)
        db.session.commit()

        redirect('/tweets')

    return render_template('register.html', form=form)

# this is how we remember a logged in user
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        name = form.username.data
        pwd = form.password.data

        user = User.authenticate(name,pwd)

        if user:
            flash(f'Welcome back {user.username}')
            session['user_id'] = user.id
            return redirect('/secret')
        else:
            form.username.errors = ['Bad name or password']
    return render_template('login.html', form=form)


@app.route('/secret')
def secret():
    if 'user_id' not in session:
        flash('you must be logged in')
        return redirect('/')
    else:
        return render_template('secret.html')


@app.route('/login', methods=['GET', 'POST'])
def login_user2():
    form = Userform()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            return redirect('/tweets')
        else:
            form.username.errors = ['Invalid Username/Password']

    return render_template('login.html')

@app.route('/tweets')
def show_tweets():
    if 'user_id' not in session:
        flash('please login first')
        return redirect('/')

    return render_template('tweets.html')

@app.route('/logout')
def logout_user():
    session.pop('user_id')
    return redirect('/')
    

