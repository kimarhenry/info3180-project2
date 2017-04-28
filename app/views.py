"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

import os
from app import app, db, login_manager
from flask import render_template, request, redirect, url_for, flash, jsonify, _request_ctx_stack
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from forms import NewItemForm
from forms import ShareForm
from models import UserProfile, WishlistItem
from forms import LoginForm
from forms import RegisterForm


import uuid
import re
from image_getter import getimageurls

## Using JWT
import jwt
from functools import wraps
import base64

###
# Routing for your application.
###

#checks entries
def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    auth = request.headers.get('Authorization', None)
    if not auth:
      return jsonify({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}), 401

    parts = auth.split()

    if parts[0].lower() != 'bearer':
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}), 401
    elif len(parts) == 1:
      return jsonify({'code': 'invalid_header', 'description': 'Token not found'}), 401
    elif len(parts) > 2:
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}), 401

    token = parts[1]
    try:
         payload = jwt.decode(token, 'some-secret')

    except jwt.ExpiredSignature:
        return jsonify({'code': 'token_expired', 'description': 'token is expired'}), 401
    except jwt.DecodeError:
        return jsonify({'code': 'token_invalid_signature', 'description': 'Token signature is invalid'}), 401

    g.current_user = user = payload
    return f(*args, **kwargs)

  return decorated
  
  
@login_manager.user_loader
def load_user(id):
    return UserProfile.query.get(int(id))


@login_manager.unauthorized_handler
def unauthorized_handler():
    flash('Restricted access. Please login to access this page.', 'danger')
    return redirect(url_for('login'))  

#home page
@app.route('/')
def home():
    """Render website's home page."""
    return render_template('home.html', form=None)

#about page
@app.route('/about/')
def about():
    """Render the website's about page."""
    return render_template('about.html')

#directs to login page
@app.route("/api/users/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":

        if form.validate_on_submit():
            # get data from form
            email = form.email.data
            password = form.password.data

            # filter user from the database
            user = UserProfile.query.filter_by(email=email, password=password).first()

            if user is not None:
                # login user
                login_user(user)

                # login was successful
                flash('Logged in as '+current_user.first_name+" "+current_user.last_name, 'success')

                
                token=generate_token()
                #generates token here
                
                return redirect(url_for("wishlist", userid=current_user.get_id(),token1=token))
                # goes to wishlist page
                
            # error in login
            flash('Your email or password is incorrect', 'danger')
            return redirect(url_for("login"))
        else:
            print "NOT VALIDATED"
            print form.errors
            # flash user for incomplete form
            flash('Invalid login data, please try again', 'danger')
    return render_template("login.html", form=form)


#Genarates token
@app.route('/token')
def generate_token():
    load = {'sub': '12345', 'email': current_user.email, 'password': current_user.password}
    token = jwt.encode(load, 'secret123', algorithm='HS256')
    return jsonify(error=None, data={'token': token}, message="Token Generated")


#logs user out
@app.route("/api/users/logout")
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for("login"))


#registers a user
@app.route("/api/users/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            # generate userid
            userid = str(uuid.uuid4().fields[-1])[:8]

            # retrieves all data from the form
            firstname = form.firstname.data
            lastname = form.lastname.data
            email = form.email.data
            password = form.password.data

            # gets a user from the database
            user = UserProfile.query.filter_by(email=email, password=password).first()

            # error if use already registered
            if user is not None:
                flash('This email already exists in the database', 'warning')
                return redirect(url_for('register'))

            # create user
            user = UserProfile(id=userid,
                               first_name=firstname,
                               last_name=lastname,
                               email=email,
                               password=password)

            # insert user into UserProfile
            db.session.add(user)
            db.session.commit()
            # logout old user
            logout_user()

            # login new user
            login_user(user)
            flash('Successful, Welcome '+current_user.first_name, 'success')
            # place user on their wishlist
            return redirect(url_for("wishlist", userid=current_user.get_id()))

        else:
            print "NOT VALIDATED"
            print form.errors
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('register'))

    return render_template("register.html", form=form)
    
@app.route("/api/users/<int:userid>/wishlist/<int:itemid>", methods=["GET", "DELETE"])
def removeitem(userid, itemid):
    if request.method == "DELETE":
        # flash user for successful delete
        flash('Item deleted', 'success')

        # remove item from wishlist
        db.session.delete(WishlistItem.query.filter_by(id=itemid).first())
        db.session.commit()

        # redirect user to their wishlist page
        return redirect(url_for("wishlist", userid=current_user.get_id()))
    else:
        # flash user for successful delete
        flash('Item deleted', 'success')

        # remove item from wishlist
        db.session.delete(WishlistItem.query.filter_by(id=itemid).first())
        db.session.commit()

        return redirect(url_for("wishlist", userid=current_user.get_id()))    


@app.route("/api/users/<int:userid>/wishlist", methods=["GET", "POST"])
def wishlist(userid):
    form = NewItemForm()
    form2 = ShareForm()
    form3 = LoginForm()

    if request.method == "POST":
        if form.validate_on_submit():
            #item id
            id = str(uuid.uuid4().fields[-1])[:8]

            # retrieve data from form
            title = form.title.data
            description = form.description.data
            webaddress = form.webaddress.data
            thumbnail = request.form['thumbnail']

            # gets item form database
            item = WishlistItem.query.filter_by(title=title, owner=current_user.get_id()).first()

            if item is not None:
                flash(''+title+' already exists in your wishlist', 'warning')
                return redirect(url_for('wishlist', userid=current_user.get_id()))

            # create wishlist
            item = WishlistItem(id=id,
                                owner=current_user.get_id(),
                                title=title,
                                description=description,
                                webaddress=webaddress,
                                thumbnail=thumbnail)

            # insert item into WishlistItem
            db.session.add(item)
            db.session.commit()

            flash(''+title+' was added to your wishlist', 'success')

            # redirect user to their wishlist page
            return redirect(url_for("wishlist", userid=current_user.get_id()))
        else:
            # flash message for failed item addition
            flash('Invalid item data, please try again', 'danger')

            # redirect user to their wishlist page
            return redirect(url_for("wishlist", userid=current_user.get_id()))
    else:
        # retrieve user wishlist items from database
        items = WishlistItem.query.filter_by(owner=current_user.get_id()).all()
    return render_template("wishlist.html", userid=current_user.get_id(), form=form, form2=form2, form3=form3, items=items)

@app.route("/api/users/<int:userid>/wishlist/share", methods=["GET","POST"])
def sharewishlist(userid):
    import smtplib
    form = ShareForm()
    form2 = LoginForm()

    if request.method == "POST":
        if form.validate_on_submit() and form2.validate_on_submit():
            from_addr = current_user.email
            to_addr = form.recipientemail.data
            from_name = current_user.first_name+' '+current_user.last_name
            to_name = form.name.data
            subject = 'My Wishlist!'
            message = """
            From: {} <{}>
            To: {} <{}>
            Subject: {}

            {}
            """
            # gets item form database
            items = WishlistItem.query.filter_by(owner=current_user.get_id()).all()

            message_body = 'This is my wishlist'
            for item in items:
                message_body += "\n-->"+item.title

            message_to_send = message.format(from_name, from_addr, to_name, to_addr, subject, message_body)
            # Credentials (if needed)
            username = form2.email.data
            password = form2.password.data

            # The actual mail send
            server = smtplib.SMTP('smtp.gmail.com:587')
            server.starttls()
            server.login(username, password)
            server.sendmail(from_addr, to_addr, message_to_send)
            server.quit()

            flash('Wishlist was Shared to '+to_name, 'success')
        else:
            flash('Invalid sharing data, please try again', 'danger')
        return redirect(url_for("wishlist", userid=current_user.get_id()))
    return redirect(url_for("wishlist", userid=current_user.get_id()))



@app.route('/api/thumbnails', methods=['GET'])
def thumbnails():
    # get url from form
    url = request.args.get('url')

    # establish expression for url
    pattern = re.compile("(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9]\.[^\s]{2,})")

    if pattern.match(url):
        # get and return thumbnails
        return jsonify({'error': None, 'message': 'Success', 'thumbnails': getimageurls(url)})

    # otherwise display default image
    return jsonify({'error': None, 'message': 'Success', 'thumbnails': [url_for('static', filename="uploads/placeholder.png")]})



###
# The functions below should be applicable to all Flask apps.
###


@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port="8080")
