import datetime
import os
from flask import render_template, redirect, request, Response, session
from werkzeug.utils import secure_filename
from repositories.files import *
from utils import *
from . import routes

'''
FILE WITH ROUTES ABOUT UPLOAD FILES TO THE SERVER
'''

UPLOADS_DIR = get_dir_by_os()  # Directory path to save the files
if not os.path.exists(UPLOADS_DIR):  # Create directory if not exists
    os.makedirs(UPLOADS_DIR)


@routes.route('/upload', methods=["GET", "POST"])
def upload():
    '''
    Upload view and post functionality, where users with write permission can upload a file to the server.
    :return: upload view
    '''
    if not is_logged():
        return redirect("/login")

    if not write_permission():
        return redirect("/home")

    if request.method == "POST":
        files = request.files
        file = files.get("file")
        if file is None:
            return Response("Fichero no encontrado", status=400)

        description = request.form.get("description", "")

        filename = file.filename
        user = session["username"]
        date = datetime.datetime.utcnow()
        # Save File
        full_filename = os.path.join(UPLOADS_DIR, secure_filename(file.filename))
        file.save(full_filename)
        hash = hash_file(full_filename)
        size = os.path.getsize(full_filename)
        if check_file_exists(filename):  # Update File
            result = update_file(filename, user, date, hash, size, description)
        else:  # Insert File
            result = insert_file(filename, user, date, hash, size, description)

        if not result:
            return render_template("upload.html")
        else:
            return redirect("/home")

    return render_template("upload.html")
