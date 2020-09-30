import uuid
import sys
import requests
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session  # https://pythonhosted.org/Flask-Session
from flask_socketio import SocketIO, emit, send
import msal
import json
from main import OneDriveRestore
from datetime import datetime
import yaml


class Struct:
    def __init__(self, **entries):
        self.__dict__.update(entries)


with open("config.yaml", "r") as f:
    app_config = Struct(**yaml.safe_load(f))

app = Flask(__name__, static_folder="./web/dist/static", template_folder="./web/dist")
app.config.from_object(app_config)
Session(app)
socketio = SocketIO(app, manage_session=False)


from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


@socketio.on("connect")
def handle_json():
    if not session.get("user"):
        print(f"unauthorized connection attempted")
        send({"message": "unauthorized"}, json=True)

    print(f"user connected: {session['user'].get('preferred_username')}")
    send(
        {"message": f"{session['user'].get('preferred_username')} has connected"},
        json=True,
    )


@socketio.on("restore_drive", namespace="/restore")
def handle_my_custom_namespace_event(data):
    start_time = datetime.now()
    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    if not token:
        return redirect(url_for("login"))

    if data["encrypted_file_extension"] != "" and data[
        "encrypted_file_extension"
    ].startswith("."):
        service = OneDriveRestore(
            config_file="config.yaml",
            token=_get_token_from_cache(app_config.DELEGATED_PERMISSONS),
            username=session["user"].get("preferred_username"),
        )

        service.encrypted_file_extension = data["encrypted_file_extension"]
        service.MODE = data["mode"]
        emit("restore_response", json.dumps(data), json=True)
        try:
            service.run()
        except KeyboardInterrupt:
            print(f"status: exiting program...")
            print(
                f"status: repaired {service.q_fixed_files.unfinished_tasks + 1} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}"
            )
            sys.exit(0)

        emit(
            "restore_response",
            f"status: repaired {service.q_fixed_files.unfinished_tasks + 1} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}",
        )
    emit("restore_response", "no extension defined", json=True)


@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))

    return render_template("index.html", user=session["user"], version=msal.__version__)


@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())

    auth_url = _build_auth_url(
        scopes=app_config.DELEGATED_PERMISSONS, state=session["state"]
    )

    return render_template("login.html", auth_url=auth_url, version=msal.__version__)


@app.route(
    app_config.REDIRECT_PATH
)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args.get("state") != session.get("state"):
        return redirect(url_for("index"))  # No-OP. Goes back to Index page
    if "error" in request.args:  # Authentication/Authorization failure
        return render_template("auth_error.html", result=request.args)
    if request.args.get("code"):
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args["code"],
            scopes=app_config.DELEGATED_PERMISSONS,  # Misspelled scope would cause an HTTP 400 error here
            redirect_uri=url_for("authorized", _external=True),
        )
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY
        + "/oauth2/v2.0/logout"
        + "?post_logout_redirect_uri="
        + url_for("index", _external=True)
    )


@app.route("/show_token")
def show_token():
    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    if not token:
        return redirect(url_for("login"))

    return render_template("display.html", result=token)


@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    if not token:
        return redirect(url_for("login"))

    graph_data = requests.get(  # Use token to call downstream service
        app_config.GRAPH_ENDPOINT,
        headers={"Authorization": "Bearer " + token["access_token"]},
    ).json()
    return render_template("display.html", result=graph_data)


@app.route("/restore_page")
def restore_page():
    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    if not token:
        return redirect(url_for("login"))

    with open("config.yaml", "r") as f:
        data = yaml.safe_load(f.read())

    return render_template("restore.html", data=data, user=session["user"])


@app.route("/restore", methods=["POST"])
def restore():
    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    if not token:
        return redirect(url_for("login"))

    # TODO: Parse form data here
    data = json.loads(request.data)  # a multidict containing POST data

    start_time = datetime.now()

    if data["encrypted_file_extension"] != "" and data[
        "encrypted_file_extension"
    ].startswith("."):
        service = OneDriveRestore(
            config_file="config.yaml",
            token=_get_token_from_cache(app_config.DELEGATED_PERMISSONS),
            username=session["user"].get("preferred_username"),
        )
        service.token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
        service.encrypted_file_extension = data["encrypted_file_extension"]
        service.MODE = data["mode"]

        try:
            service.run()
        except KeyboardInterrupt:
            print(f"status: exiting program...")
            print(
                f"status: repaired {service.q_fixed_files.unfinished_tasks + 1} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}"
            )
            sys.exit(0)

        print(
            f"status: repaired {service.q_fixed_files.unfinished_tasks + 1} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}"
        )
        return {"message": "job submitted successfully", "mode": data["mode"]}

    return {
        "error": {"mode": data["mode"]},
        "message": "file extension is empty or does not start with a '.'",
    }


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID,
        authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET,
        token_cache=cache,
    )


def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for("authorized", _external=True),
    )


def _get_token_from_cache(scope):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


app.jinja_env.globals.update(_build_auth_url=_build_auth_url)  # Used in template

if __name__ == "__main__":
    socketio.run(app, host="localhost")
    # app.run(host="localhost")
