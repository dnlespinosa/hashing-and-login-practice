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