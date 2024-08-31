from secrets import token_bytes
from uuid import uuid4
import json
import time

import flask
from flask import request, redirect, make_response
from markupsafe import escape

import db
import auth
import session
import nickname

LOG_FILE = "requests.log"

## insecure practice: CWE-798: Use of Hard-coded Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"
USER_USERNAME = "user"
USER_PASSWORD = "user"

app = flask.Flask(__name__)
app.secret_key = token_bytes(16)

@app.before_request
def log_request():
    data = {
        "time": time.time(),
        "method": request.method,
        "path": request.path,
        "form": dict(request.form),
    }
    ## SECURITY FLAW 5: CWE-532 - Insertion of Sensitive Information into Log File
    ## PROBLEM: sensitive information is logged.
    ## SOLUTION: remove sensitive information before logging.
    # if data["path"] == "/login" and "password" in data["form"]:
    #     data["form"]["password"] = "CENSORED"
    with open(LOG_FILE, "a") as file:
        file.write(json.dumps(data) + "\n")

@app.route("/")
def index():
    content = "<h1>The Web Application</h1><br>"
    username = read_user()
    if username:
        content += f"""Hello, {username}!<br>
        <a href='/profile'>Profile</a><br>
        <a href='/admin'>Admin Panel</a><br>
        <a href='/logout'>Logout</a>"""
    else:
        content += "Not logged in. <a href='/login'>Login</a>."
    return content

def set_user(username):
    response = make_response(redirect("/"))
    response.set_cookie("logged_in_as", username)
    session.create_session(username)
    session_id = str(session.get_session_id(username))
    response.set_cookie("session_id", session_id)
    return response

def read_user():

    ## SECURITY FLAW 4: CWE-287 - Improper Authentication
    ## PROBLEM: user-provided identity claim is not validated before using.
    username = request.cookies.get("logged_in_as")
    ## SOLUTION: user should present a valid session id that is associated with the username.
    ##           The session id is only set after a successful authentication.
    # session_id = request.cookies.get("session_id")
    # if not username or not session_id:
    #     return None
    # stored_session_id = session.get_session_id(username)
    # if not stored_session_id:
    #     return None
    # if session_id != str(stored_session_id):
    #     return None
    return username

def check_csrf():
    session_id = request.cookies.get("session_id")
    username = request.cookies.get("logged_in_as")
    if not username or not session_id:
        return False
    csrf_token = request.form.get("csrf_token")
    stored_token = session.get_csrf(session_id, username)
    result = stored_token == csrf_token if stored_token else False
    if result:
        session.delete_csrf(session_id, username)
    return result

def new_csrf():
    username = request.cookies.get("logged_in_as")
    session_id = request.cookies.get("session_id")
    csrf_token = uuid4().hex
    session.save_csrf(session_id, username, csrf_token)
    return csrf_token

@app.route("/profile", methods=["GET", "POST"])
def profile():
    username = read_user()
    if not username:
        return "Not logged in. <a href='/login'>Login</a>."
    if request.method == "GET":
        existing_nickname = nickname.get_nickname(username)
        csrf_token = new_csrf()
        return f"""
            <h1>Profile of {username}</h1>
            Current nickname: {escape(existing_nickname)}<br>
            <form method="post">
                <input type="text" name="nickname" placeholder="Nickname">
                <input type="submit" value="Save">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
            </form>
            <a href='/'>Go back</a>.
        """
    
    ## SECURITY FLAW 1: CWE-352 - Cross-Site Request Forgery
    ## PROBLEM: csrf token is not validated before saving submitted data.
    ## SOLUTION: validate csrf token before saving submitted data.
    # if not check_csrf():
    #     return "CSRF token is invalid. <a href='/'>Go back</a>."
    nick = request.form["nickname"]
    nickname.save_nickname(username, nick)
    return f"Saved. <a href='/'>Go back</a>."

@app.route("/admin")
def admin():
    username = read_user()
    if not username:
        return "Not logged in. <a href='/login'>Login</a>."
    if username != ADMIN_USERNAME:
        return "Not authorized. <a href='/'>Go back</a>."
    
    ## SECURITY FLAW 3: CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    ## PROBLEM: user-provided untrusted data is not escaped before rendering.
    nicknames = ", ".join(nickname.get_all_nicknames())
    ## SOLUTION: escape user-provided data before rendering.
    # nicknames = escape(nicknames)
    return "<h1>Admin panel</h1>List of profiles:<br>" + nicknames + "<br><a href='/'>Go back</a>."

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
            <form method="post">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <input type="submit" value="Login">
            </form>
        """
    name = request.form["username"]
    password = request.form["password"]
    if auth.check_user(name, password):
        return set_user(name)
    return "Login failed. <a href='/'>Go back</a>."

@app.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("logged_in_as")
    response.delete_cookie("session_id")
    return response

if __name__ == "__main__":
    db.create_db()
    auth.create_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    auth.create_user(USER_USERNAME, USER_PASSWORD)
    app.run()