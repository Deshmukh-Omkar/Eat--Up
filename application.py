import os
import requests
import urllib.parse
import csv

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from functools import wraps
from prettytable import PrettyTable
from prettytable import from_csv

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("postgres://kowjwyvquuoddp:2f54d8693b80834ca9156a3f2b460ed02a4a2e70ae79ca9ad3b007c05d8d481f@ec2-34-200-72-77.compute-1.amazonaws.com:5432/deptn5m0vdbnu7")

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@login_required
def index():
    rows = db.execute("SELECT username FROM users WHERE id = :id", id=session["user_id"])
    name = rows[0]["username"]
    return render_template("index.html", name=name)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    """POST operation for registration"""
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("apology.html", info="Please enter a username!")

        elif not request.form.get("user_role"):
            return render_template("apology.html", info="Please enter your role!")

        elif not request.form.get("password"):
            return render_template("apology.html", info="Please enter a password!")

        elif not request.form.get("confirmation"):
            return render_template("apology.html", info="Please confirm your password!")

        values = ["YES", "NO", "Y", "N"]
        valuesY =  ["YES", "Y"]
        valuesN =  ["NO", "N"]
        if request.form.get("user_role") not in values:
            return render_template("apology.html", info="Please enter Yes or No!")
        elif request.form.get("user_role") in valuesY:
            user_role = "messc"
        elif request.form.get("user_role") in valuesN:
            user_role = "mess"

        """Data for checking existing usernames"""
        u_rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(u_rows) == 1:
            message = "Username already exists!"
            return render_template("apology.html", info=message)

        """Password confirmation"""
        if not request.form.get("password") == request.form.get("confirmation"):
            message = "Passwords don't match!"
            return render_template("apology.html", info=message)

        uname = request.form.get("username")
        pwd = request.form.get("password")
        """Hash storage"""
        hash_pwd = generate_password_hash(pwd, method='pbkdf2:sha256', salt_length=8)

        """Entry successful"""
        db.execute("INSERT INTO users (username, hash, role) VALUES (:username, :password, :role)", username = uname, password = hash_pwd, role = user_role)

        return redirect("/login")

    else:
        """GET method"""
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", info="Please provide username!")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("apology.html", info="Please provide password!")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("apology.html", info="Invalid username and/or password!")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_role"] = rows[0]["role"]

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/tmenu")
@login_required
def tmenu():
    # Loading today's menu
    csv_File = open("mon.csv", "r")
    csv_file = csv_File.readlines()

    # Single row of Headers
    columns = csv_file[0]
    columns = columns.split(",")
    for column in columns:
        column.replace("\n", "")

    rows = []
    for num in range(1, len(csv_file)):
        data = csv_file[num]
        data = data.split(",")
        for row in data:
            row.replace("\n", "")
        rows.append(data)

    csv_File.close()

    return render_template("tmenu.html", columns=columns, rows=rows)


@app.route("/wmenu")
@login_required
def wmenu():
    # Loading the weekly menu
    csv_File = open("may2020.csv", "r")
    csv_file = csv_File.readlines()

    # Single row of Headers
    columns = csv_file[0]
    columns = columns.split(",")
    for column in columns:
        column.replace("\n", "")

    rows = []
    for num in range(1, len(csv_file)):
        data = csv_file[num]
        data = data.split(",")
        for row in data:
            row.replace("\n", "")
        rows.append(data)

    csv_File.close()

    return render_template("wmenu.html", columns=columns, rows=rows)


@app.route("/archive")
@login_required
def archive():
    return render_template("archive.html")


@app.route("/messc")
@login_required
def messc():
    return render_template("messc.html")


@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        if not request.form.get("name"):
            return render_template("apology.html", message="Please enter your name!")
        elif not request.form.get("email"):
            return render_template("apology.html", message="Please enter your E-Mail ID!")
        elif not request.form.get("category"):
            return render_template("apology.html", message="Please select a category!")
        elif not request.form.get("comment"):
            return render_template("apology.html", message="Please share your valuable feedback!")

        name = request.form.get("name")
        email = request.form.get("email")
        comment = request.form.get("comment")
        category = request.form.get("category")

        db.execute("INSERT INTO feedback VALUES (:name, :category, :email, :comment)",
            name=name, category=category, email=email, comment=comment)

        return redirect("/")
    else:
        return render_template("fb.html", message="We are sorry for the incovenience!")

@app.route("/change_pwd", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        password = request.form.get("password")

        if password == "":
            return render_template("apology.html", info="Please enter the new password!")
        elif len(password) < 8:
            return render_template("apology.html", info="Atleast eight characters are required minimum.")

        pass_hash = generate_password_hash(password)

        db.execute("UPDATE users SET hash = :pw WHERE id = :id",
                   pw=pass_hash, id=session["user_id"])

        return render_template("/", message="Password changed!")
    else:
        return render_template("pwd.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template("apology.html", message=e)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)