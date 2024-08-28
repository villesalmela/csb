import flask
import db

app = flask.Flask(__name__)

@app.route("/")
def index():
    return ""

if __name__ == "__main__":
    db.create_db()
    app.run()