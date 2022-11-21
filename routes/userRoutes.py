import hashlib
from flask import render_template, session, redirect, request, flash
from repositories.permissions import find_permissions_by_role
from repositories.users import *
from utils import is_logged
from . import routes
import os
import re

'''
FILE WITH ROUTES ABOUT LOGIN, REGISTER AND LOGOUT USERS FROM WEB PAGE
'''


@routes.route('/')
def index():
    if not is_logged():
        return redirect("/login")
    return redirect("/home")


@routes.route('/logout', methods=["GET"])
def logout():
    session["username"] = None
    session["role"] = None
    session["access"] = None
    session["remove"] = None
    session["read"] = None
    session["write"] = None
    return redirect("/login")

def is_valid_username(username):
    if username == "":
        return False
    pattern = '^\w+$'
    valid_chars = re.compile(pattern)
    return valid_chars.match(username)

@routes.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        form = request.form
        username = form.get("username")
        password = form.get("password")
        # Check data
        if username is None:
            flash("Nombre de usuario no definido")
        elif not is_valid_username(username):
            flash("Nombre de usuario no valido")
        elif password is None:
            flash("Contraseña no definida")
        else:
            result = find_user(username)
            if result:
                username, role, salt, password_hashed_correct = result
                password_salted = password + str(salt)
                password_hashed = hashlib.sha256(password_salted.encode()).hexdigest()
                if password_hashed == password_hashed_correct:
                    # Get user info
                    permissions = find_permissions_by_role(role)
                    session["username"] = username
                    session["role"] = role
                    session["access"] = permissions["access"]
                    session["read"] = permissions["read"]
                    session["write"] = permissions["write"]
                    session["remove"] = permissions["remove"]
                    return redirect("/home")
                else:
                    flash("Los datos introducidos son incorrectos.")
            else:
                flash("Los datos introducidos son incorrectos.")
    return render_template("login.html")


@routes.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        form = request.form
        username = form.get("username")
        password1 = form.get("password1")
        password2 = form.get("password2")
        role = form.get("role")
        # Check data
        if username is None:
            flash("Nombre de usuario no definido")
        elif not is_valid_username(username):
            flash("Nombre de usuario no valido")
        elif password1 is None or password2 is None:
            flash("Contraseña no definida")
        elif role is None:
            flash("Rol no definido")
        elif password1 != password2:
            flash("Las contraseñas no coinciden")
        elif check_user_exists(username):
            flash("Usuario ya existe")
        else:
            # Create user
            size = 16
            salt_generated_bytes = os.urandom(size)
            salt_generated = str(salt_generated_bytes)
            password_salted = password1 + str(salt_generated)
            password_hashed = hashlib.sha256(password_salted.encode()).hexdigest()
            inserted = create_new_user(username, password_hashed, role, salt_generated)
            # Register Success
            if inserted:
                permissions = find_permissions_by_role(role)
                session["username"] = username
                session["role"] = role
                session["role"] = role
                session["access"] = permissions["access"]
                session["read"] = permissions["read"]
                session["write"] = permissions["write"]
                session["remove"] = permissions["remove"]
                return redirect("/home")
            # Error inserting the values
            else:
                flash("Error interno: No se ha podido crear el usuario. Por favor, vuelve a intentarlo.")
    return render_template("register.html")
