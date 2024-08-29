import flask
from flask import request, redirect, session, make_response
import db
import auth
from secrets import token_bytes

# insecure practice: CWE-798: Use of Hard-coded Credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

app = flask.Flask(__name__)
app.secret_key = token_bytes(16)

@app.route("/")
def index():
    content = "<h1>The Web Application</h1><br>"
    username = read_user()
    if username:
        content += f"Hello, {username}!"
    else:
        content += "Not logged in. <a href='/login'>Login</a>."
    return content

def set_user(username):
    response = make_response(redirect("/"))

    # security flaw: CWE-287: Improper Authentication
    response.set_cookie("logged_in_as", username)

    return response

def read_user():

    # security flaw: CWE-287: Improper Authentication
    return request.cookies.get("logged_in_as")

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


if __name__ == "__main__":
    db.create_db()
    auth.create_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    app.run()