//Upload files using a simple plugin with Drag and Drop
$(document).ready(function () {
    $('#uploadFiles').simpleUpload({
        url: '/upload',
        method: 'post',
        dropZone: '#drop_zone',
        progress: '#progress',
    });
});