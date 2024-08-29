import flask
import db
import auth

# insecure practice: CWE-798: Use of Hard-coded Credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

app = flask.Flask(__name__)

@app.route("/")
def index():
    return ""

if __name__ == "__main__":
    db.create_db()
    auth.create_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    app.run()