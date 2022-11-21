import os
from flask import render_template, redirect, make_response, jsonify
from werkzeug.utils import secure_filename
from repositories.files import *
from utils import *
from . import routes

'''
FILE WITH ROUTES ABOUT READ, REMOVE AND DOWNLOAD FILES FROM SERVER
'''

UPLOADS_DIR = get_dir_by_os()  # Directory path to save the files


@routes.route('/home')
def home():
    '''
    Main page view, where lists all the files. Only available for logged users.
    '''
    if not is_logged():
        return redirect("/login")
    files = get_all_files()
    return render_template("home.html", files=files)


@routes.route('/download/<filename>', methods=["GET"])
def download_file(filename):
    '''
    Route to download a file by a logged user with read permission.
    :param filename: name of the file
    :return: response with the file attached in the body
    '''
    if not is_logged():
        return redirect("/login")
    if not read_permission():
        return redirect("/home")
    full_filename = os.path.join(UPLOADS_DIR, secure_filename(filename))
    with open(full_filename, "rb") as file:
        body = file.read()
    response = make_response(body)
    response.headers.set(
        'Content-Disposition', 'attachment', filename=filename)
    return response


@routes.route('/remove/<filename>', methods=["POST"])
def remove_file(filename):
    '''
    Route to remove a file from the server. It is only callable for logged users with remove permission.
    This route is called through an ajax function.
    :param filename: name of the file
    :return: json response
    '''
    if not is_logged():
        return redirect("/login")
    if not remove_permission():
        return redirect("/home")
    result = delete_file(filename)
    if not result:
        return make_response(jsonify("Error al eliminar el fichero"), 400)
    else:
        return make_response(jsonify("Fichero eliminado con éxito"), 200)
