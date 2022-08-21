function send_it(form) {
    let url = form.url.value;
    start();
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "backend/scanurl");
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("Content-Type", "application/json");
    let data = JSON.stringify({"url": url});
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                // Print received data from server
                let response = JSON.parse(this.responseText);
                $.each(response['warnings'], function (_, item) {
                    $("#results").append("<div class=\"alert alert-warning my-2\">" + escapeHTML(item) + "</div>")
                });
                $.each(response['errors'], function (_, item) {
                    $("#results").append("<div class=\"alert alert-danger my-2\">" + escapeHTML(item) + "</div>")
                });
                $.each(response['notices'], function (_, item) {
                    $("#results").append("<div class=\"alert alert-secondary my-2\">" + escapeHTML(item) + "</div>")
                });
            } else {
                $("#results").append("<div class=\"alert alert-danger my-2\">Unable to communicate with server: HTTP error " + xhr.status + " " + xhr.statusText + "</div>")
            }
            end();
        }
    };
    xhr.send(data);
}

function start() {
    $("#results").empty();
    $("#submit").prop("disabled", true);
    $("#spinner").prop("hidden", false);
}

function end() {
    $("#submit").prop("disabled", false);
    $("#spinner").prop("hidden", true);
}

function escapeHTML(unsafeText) {
    let div = document.createElement('tmp');
    div.innerText = unsafeText;
    return div.innerHTML;
}
