from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import subprocess

app = Flask(__name__)

# Mot de passe haché (sécurisé)
ADMIN_PASSWORD_HASH = generate_password_hash("123456")

def hash_password(password):
    return check_password_hash(ADMIN_PASSWORD_HASH, password)

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    if username == "admin" and hash_password(password):
        return "Logged in"
    return "Invalid credentials"

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    try:
        # Subprocess sécurisé
        result = subprocess.check_output(["ping", "-c", "1", host])
        return result
    except subprocess.CalledProcessError:
        return "Ping failed"

@app.route("/hello")
def hello():
    name = request.args.get("name", "user")
    return f"<h1>Hello {escape(name)}</h1>"

if __name__ == "__main__":
    app.run(debug=False)
