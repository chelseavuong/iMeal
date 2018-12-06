from __future__ import print_function
import os
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_oauth import OAuth
from cs50 import SQL
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

from helpers import apology, login_required, lookup, usd

# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = "381946469623-11uc8v2g8leu6mhr5s4830s3u270kvbm.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "3b-K6STKZLueq4bmKpxbo5bl"
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console



SECRET_KEY = 'development key'
DEBUG = True

app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///iMeal.db")

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

# Source: (https://pythonspot.com/login-to-flask-app-with-google/)
@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))
    if 'google_token' in session:
        me = google.get('userinfo')
    return redirect(url_for('login'))


@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)



@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    print(session['access_token'])

    return render_template('register.html')


@google.tokengetter
def get_access_token():
    return session.get('access_token')

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Forget any user_id
        session.clear()

        """Return true if username available, else false, in JSON format"""

        # Check if username and password are valid
        if not request.form.get("username"):
            return apology("Missing Email!")

        elif not request.form.get("password"):
            return apology("Missing Password!")

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Your passwords do not match!")

        # Store password securely (Source: http://blog.tecladocode.com/learn-python-encrypting-passwords-python-flask-and-passlib/)
        hash = generate_password_hash(request.form.get("password"))

        # Check if username is duplicate
        name = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        if name:
            return apology("Username already exists")

        # Store info in SQL users table
        result = db.execute("INSERT INTO users (username, hash, phone) VALUES (:username, :hash, :phone)",
                            username=request.form.get("username"), hash=hash, phone = request.form.get("phone"))

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return render_template("events.html")

    else:
        return render_template("register.html")

@app.route("/getin", methods=["GET", "POST"])
def getin():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide gmail", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["Hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect ("/events")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("getin.html")


@app.route("/events")
def events():
    events = db.execute(
        "SELECT month as month, day as day, year as year, duration as duration, timezone as timezone FROM meals WHERE id = :id", id=session["user_id"])

    return render_template("events.html", events = events)

@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        name = request.form.get("name")
        print(name)
        if not name:
            return apology("Please enter a valid user!")
        portfolio = db.execute(
                    "SELECT month as month, day as day, year as year, duration as duration, timezone as timezone FROM meals WHERE username = :username", username = name)
        return render_template("results.html", portfolio=portfolio)

    else:
        return render_template('search.html')

@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "POST":
        username = db.execute("SELECT username as username FROM users WHERE id = :id", id = session["user_id"])

        db.execute("INSERT INTO meals (id, month, day, year, duration, timezone, username) VALUES (:id, :month, :day, :year, :duration, :timezone, :username)",
                   id=session["user_id"], month=request.form.get("month"), day=request.form.get("date"), year=request.form.get("year"), duration=request.form.get("time"), timezone=request.form.get("timezone"), username = username[0]["username"])

        # Alert user of success (source: http://flask.pocoo.org/docs/0.12/patterns/flashing/)
        flash("Well done!")

        events = db.execute("SELECT * FROM meals WHERE id = :id GROUP BY id", id=session["user_id"])

        return render_template("events.html", events=events)

    else:

        return render_template("add.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")

# def main():
#     app.run()


# if __name__ == '__main__':
#     main()



# # Configure application
# app = Flask(__name__)
# app.config['GOOGLE_ID'] = "381946469623-11uc8v2g8leu6mhr5s4830s3u270kvbm.apps.googleusercontent.com"
# app.config['GOOGLE_SECRET'] = "3b-K6STKZLueq4bmKpxbo5bl"
# app.debug = True
# app.secret_key = 'development'
# oauth = OAuth()

# # Ensure templates are auto-reloaded
# app.config["TEMPLATES_AUTO_RELOAD"] = True

# # Ensure responses aren't cached


# @app.after_request
# def after_request(response):
#     response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#     response.headers["Expires"] = 0
#     response.headers["Pragma"] = "no-cache"
#     return response


# # Custom filter
# app.jinja_env.filters["usd"] = usd

# # Configure session to use filesystem (instead of signed cookies)
# app.config["SESSION_FILE_DIR"] = mkdtemp()
# app.config["SESSION_PERMANENT"] = False
# app.config["SESSION_TYPE"] = "filesystem"
# Session(app)

# # Configure CS50 Library to use SQLite database
# db = SQL("sqlite:///iMeal.db")




# @app.route("/buy", methods=["GET", "POST"])
# @login_required
# def buy():
#     """Buy shares of stock"""
#     if request.method == "POST":

#         # Check for valid stock
#         stocks = lookup(request.form.get("symbol"))
#         if not stocks:
#             return apology("Please enter a valid stock")

#         # Check for valid amount of shares
#         shares = request.form.get("shares")

#         if not shares:
#             return apology("Please enter an amount of shares")
#         if not shares.isdigit():
#             return apology("Please enter an integer amount of shares")

#         shares = int(request.form.get("shares"))

#         if shares < 0:
#             return apology("Please enter a positive amount of shares")

#         # Check if user has enough cash
#         amount = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

#         if amount[0]['cash'] < shares * stocks["price"]:
#             return apology("You do not have enough to purchase this stock")

#         total = shares * stocks["price"]

#         # Update SQL tables: history and portfolio (source: https://www.w3schools.com/sql/sql_update.asp)
#         db.execute("UPDATE users SET cash = cash - :cost where id = :id", id=session["user_id"], cost=total)

#         db.execute("INSERT INTO history (id, stock, share, price, total) VALUES (:id, :stock, :share, :price, :total)",
#                   id=session["user_id"], stock=request.form.get("symbol"), share=shares, price=stocks["price"], total=total)

#         bought_share = db.execute("SELECT shares FROM portfolio WHERE id = :id AND stock = :stock",
#                                   id=session["user_id"], stock=request.form.get("symbol"))

#         if not bought_share:
#             db.execute("INSERT INTO portfolio (id, stock, shares, price, total) VALUES (:id, :stock, :shares, :price, :total)",
#                       id=session["user_id"], stock=request.form.get("symbol"), shares=shares, price=stocks["price"], total=total)

#         else:
#             db.execute("UPDATE portfolio SET shares = :shares WHERE id = :id AND stock = :stock",
#                       id=session["user_id"], stock=request.form.get("symbol"), shares=int(bought_share[0]["Shares"]) + shares)

#         # Alert user of success (source: http://flask.pocoo.org/docs/0.12/patterns/flashing/)
#         flash("Well done!")

#         return redirect("/")

#     else:
#         return render_template("buy.html")


# @app.route("/check", methods=["GET"])
# def check():
#     if request.method == "GET":

#         # Retrieve username from register.html
#         username = request.args.get("username")

#         # Check if username is valid (source: https://api.jquery.com/jquery.get/)
#         rows = db.execute("SELECT 1 FROM users WHERE username = :username", username=username)

#         if (not len(username)) or rows:
#             return jsonify(False)
#         else:
#             return jsonify(True)


# @app.route("/history")
# @login_required
# def history():
#     """Show history of transactions"""

#     # Select info from history to display in table
#     history = db.execute("SELECT stock as stock, share as share, total as total, timestamp as timestamp FROM history")
#     return render_template("history.html", history=history)



# @app.route("/logout")
# def logout():
#     """Log user out"""

#     # Forget any user_id
#     session.clear()

#     # Redirect user to login form
#     return redirect("/")


# @app.route("/quote", methods=["GET", "POST"])
# @login_required
# def quote():
#     """Get stock quote."""
#     if request.method == "POST":

#         # Check if quote is valid
#         quote = lookup(request.form.get("symbol"))

#         if not quote:
#             return apology("Please enter a valid stock!")

#         # Return info in stock.html
#         return render_template("stock.html", quote=quote)

#     else:
#         return render_template("quote.html")


# @app.route("/password", methods=["GET", "POST"])
# def password():

#     if request.method == "POST":

#         # Check if current username and password is valid
#         rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

#         if rows[0]["username"] != request.form.get("username"):
#             return apology("Wrong username!")

#         if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
#             return apology("Wrong password!")

#         # Check if both passwords match
#         if request.form.get("new_password") != request.form.get("new_password_confirm"):
#             return apology("Your new password does not match!")

#         hash_new = generate_password_hash(request.form.get("new_password"))

#         # Update password if valid (source: https://www.w3schools.com/sql/sql_update.asp)
#         result = db.execute("UPDATE users SET hash = :hash_new WHERE username = :username",
#                             hash_new=hash_new, username=request.form.get("username"))

#         if not result:
#             return apology("Sorry we could not update it!")
#         else:
#             session["user_id"] = rows[0]["id"]
#             return redirect("/")

#     else:
#         return render_template("password.html")


# @app.route("/sell", methods=["GET", "POST"])
# @login_required
# def sell():
#     """Sell shares of stock"""

#     if request.method == "POST":

#         # Check if valid stock
#         stocks = lookup(request.form.get("symbol"))

#         if not stocks:
#             return apology("Sorry this is not a valid stock")

#         # Check if positive amount of shares
#         shares = int(request.form.get("shares"))

#         if shares < 0:
#             return apology("Sorry this must be a positive integer")

#         # Check if enough shares (source: https://www.w3schools.com/sql/func_mysql_timestamp.asp)
#         stocks_bought = db.execute("SELECT SUM(shares) as shares FROM portfolio WHERE id = :id and stock = :stock GROUP by stock",
#                                   id=session["user_id"], stock=request.form.get("symbol"))

#         if not stocks_bought or int(stocks_bought[0]["shares"]) < shares:
#             return apology("Sorry you do not have enough shares")

#         # Price sold
#         selling_price = (stocks["price"]) * shares

#         # Result of selling shares
#         new_shares = db.execute("SELECT shares FROM portfolio WHERE id = :id and stock = :stock",
#                                 id=session["user_id"], stock=request.form.get("symbol"))
#         new_shares = new_shares[0]['Shares']

#         remaining_shares = int(new_shares - shares)

#         # Result of cash on selling shares
#         new_total = db.execute("SELECT total FROM portfolio WHERE id = :id and stock = :stock",
#                               id=session["user_id"], stock=request.form.get("symbol"))
#         new_total = new_total[0]['Total']

#         total = (stocks["price"]*shares)
#         remaining_total = int(new_total - total)

#         # Updates SQL tables: users, history, portfolio
#         if remaining_shares == 0:
#             db.execute("DELETE FROM portfolio WHERE id = :id AND stock = :stock", id=session["user_id"],
#                       stock=request.form.get("symbol"))

#         db.execute("UPDATE portfolio SET shares = :remaining_shares WHERE id = :id and stock = :stock",
#                   id=session["user_id"], stock=request.form.get("symbol"), remaining_shares=remaining_shares)

#         db.execute("UPDATE portfolio SET total = :remaining_total WHERE id = :id and stock = :stock",
#                   id=session["user_id"], stock=request.form.get("symbol"), remaining_total=remaining_total)

#         db.execute("UPDATE users SET cash = cash + :selling_price WHERE id = :id", id=session["user_id"],
#                   selling_price=selling_price)

#         db.execute("INSERT INTO history (id, stock, share, price, total) VALUES (:id, :stock, :share, :price, :total)",
#                   id=session["user_id"], stock=request.form.get("symbol"), share=shares, price=stocks["price"], total=total)

#         # Alert user of success (source: http://flask.pocoo.org/docs/0.12/patterns/flashing/)
#         flash("Well done!")

#         return redirect("/")

#     else:
#         stocks = db.execute("SELECT stock as stock FROM portfolio WHERE id = :id GROUP BY stock", id=session["user_id"])

#         return render_template("sell.html", stocks=stocks)


# def errorhandler(e):
#     """Handle error"""
#     return apology(e.name, e.code)


# # listen for errors
# for code in default_exceptions:
#     app.errorhandler(code)(errorhandler)
