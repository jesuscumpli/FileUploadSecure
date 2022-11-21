from flask import Flask
from routes import *
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.register_blueprint(routes)
app.secret_key = '6ee9a71761572d9f91dc2067da170889'
csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
