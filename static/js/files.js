//Remove files using Ajax
function remove_file(filename) {
    $.ajax({
        url: "/remove/" + filename,
        dataType: "json",
        type: "Post",
        async: true,
        success: function (response, textStatus, jqXHR) {
            document.getElementById(filename).remove();
            var messageDiv = document.getElementById("message");
            messageDiv.className = "alert alert-success";
            messageDiv.textContent = "Fichero " + filename + " eliminado del servidor.";
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log(textStatus)
            var messageDiv = document.getElementById("message");
            messageDiv.className = "alert alert-danger";
            messageDiv.textContent = "Error: no se ha podido eliminar el fichero del servidor.";
        }
    });
}