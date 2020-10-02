import uuid
import sys
import requests
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session  # https://pythonhosted.org/Flask-Session
from flask_socketio import SocketIO, emit, send
import msal
import yaml
from logging import Logger
import os
import json
import re
import sys
from datetime import datetime
from queue import Queue
import signal
from threading import currentThread
from multiprocessing import set_start_method
from multiprocessing import freeze_support, Lock
from multiprocessing.pool import ThreadPool
from urllib3.util import Retry
from dateutil.parser import parse
import logging
from logging import FileHandler
from rich.logging import RichHandler
from rich import print


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


##################################################
cpu_count = os.cpu_count()
thread_count = os.cpu_count() * 5
print(f"CPU COUNT:     {cpu_count}")
print(f"THREAD COUNT:  {thread_count}")
print(f"=" * 17)

# create the thread pool and make it interruptable
# set_start_method("spawn")
# freeze_support()
# original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
# pool = ThreadPool(thread_count)
# signal.signal(signal.SIGINT, original_sigint_handler)


class OneDriveRestore:
    def __init__(
        self,
        config_file,
        token=None,
        encrypted_file_extension=None,
        username=None,
        MODE="DEV",
        emit=emit,
    ):
        self.q_files = 0
        self.q_folders = 0
        self.q_fixed_files = Queue()
        self.q_unfixed_files = Queue()
        self.queue = Queue()
        self.emit = emit

        # load config file
        with open(config_file, "r") as f:
            self.config = yaml.safe_load(f)

        self.token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)

        self.username = username
        self.encrypted_file_extension = encrypted_file_extension
        self.restore_date = self.config.get("restore_date")
        self.bogus_file = self.get_bogus_filename()
        self.MODE = MODE
        self.log = self.init_logger()
        self.log.info(f"starting in {self.MODE} mode...")
        # initialize requests session pools to be a multiple of threadcount
        self.retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1,
        )
        self.sess = requests.Session()
        self.adapter = requests.adapters.HTTPAdapter(
            pool_connections=thread_count * 6,
            pool_maxsize=thread_count * 6,
            max_retries=self.retry_strategy,
            pool_block=False,
        )

        self.sess.mount("http://", self.adapter)
        self.sess.mount("https://", self.adapter)
        self.base_url = "https://graph.microsoft.com/v1.0/"
        self.header = self.refresh_header()

        self.user_drive_url = f"{self.base_url}users/{self.username}/drives"
        self.drive = self.get_drive()
        self.drive_id = self.get_drive_id(self.drive)

    def token_from_cache(self):
        for item in self.token_cache["AccessToken"].values():
            return item["secret"]

    # def refresh_access_token(self):
    #     url = f"{self.config.get('AUTHORITY')}/oauth2/v2.0/token"
    #     payload = {
    #         "grant_type": "refresh_token",
    #         "refresh_token": self.refresh_token,
    #         "client_id": self.config.get("CLIENT_ID"),
    #         "client_secret": self.config.get("CLIENT_SECRET"),
    #         "scope": self.config.get("APPLICATION_PERMISSIONS"),
    #         "redirect_uri": (f"http://localhost{self.config.get('REDIRECT_PATH')}"),
    #     }
    #     token_data = requests.post(
    #         url=url, data=payload, headers={"Contant-Type": "application/json"}
    #     )
    #     print(token_data)
    #     return token_data

    def refresh_header(self):
        access_token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
        header = {
            "authorization": f"bearer {access_token['access_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return header

    def init_logger(self):
        FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s"
        logging.basicConfig(
            level="INFO",
            format=FORMAT,
            datefmt="%d %b %Y %H:%M:%S",
            handlers=[
                RichHandler(),
                FileHandler(filename=self.username + ".log"),
            ],
        )

        self.log = logging.getLogger("rich")
        self.log.info("initializing")
        return self.log

    def get_me(self):
        try:
            response = self.sess.get(
                url="https://graph.microsoft.com/v1.0/me/",
                headers=self.refresh_header(),
            )
            return response
        except Exception as e:
            self.log.error(e)
            sys.exit(0)

    def get_drive(self):
        try:
            mydrive = self.sess.get(
                url=self.user_drive_url, headers=self.refresh_header()
            ).json()
            if "error" in mydrive.keys():
                self.log.error(mydrive["error"]["message"])
                sys.exit(0)
            return mydrive
        except Exception as e:
            self.log.error(e)
            sys.exit(0)

    def get_drive_id(self, drives):
        try:
            # TODO: Is it possible to have more than one drive for a user?  We will default to the first one we find (index 0)
            mydrive_id = drives["value"][0]["id"]
            print(f"status: found drive with id of {mydrive_id}")
            return mydrive_id
        except Exception as e:
            self.log.error(f"status: could not fetch drive_id")
            self.log.error(e)
            sys.exit(0)

    def get_paginated_items(self, nextlink):
        try:
            data = self.sess.get(url=nextlink, headers=self.refresh_header())
            json_data = data.json()
            return json_data
        except Exception as e:
            self.log.error(e)

    def get_root_folder_items(self):
        items = []
        try:
            root_folder_url = f"{self.base_url}drives/{self.drive_id}/root/children"
            data = self.sess.get(url=root_folder_url, headers=self.refresh_header())
            json_data = data.json()

            items = items + json_data["value"]
            if "@odata.nextLink" in json_data:
                next_link = json_data["@odata.nextLink"]
                while next_link:
                    self.log.info(
                        f"{self.drive_id} paginating - {len(items)} items - root folder"
                    )
                    json_data = self.get_paginated_items(next_link)
                    items = items + json_data["value"]
                    if "@odata.nextLink" in json_data:
                        next_link = json_data["@odata.nextLink"]
                    else:
                        next_link = None
            return items

        except Exception as e:
            self.log.error(e)

    def get_child_items(self, item_id):
        items = []
        try:
            child_url = (
                f"{self.base_url}drives/{self.drive_id}/items/{item_id}/children"
            )
            data = self.sess.get(url=child_url, headers=self.refresh_header())
            json_data = data.json()
            items = items + json_data["value"]
            if "@odata.nextLink" in json_data:
                next_link = json_data["@odata.nextLink"]
                while next_link:
                    self.log.info(f"{item_id} paginating - {len(items)} items")
                    json_data = self.get_paginated_items(next_link)
                    items = items + json_data["value"]
                    if "@odata.nextLink" in json_data:
                        next_link = json_data["@odata.nextLink"]
                    else:
                        next_link = None

            return items
        except Exception as e:
            self.log.error(e)

    def check_version_history(self, item):
        try:
            item_url = (
                f"{self.base_url}drives/{self.drive_id}/items/{item['id']}/versions"
            )
            versions = self.sess.get(url=item_url, headers=self.refresh_header()).json()
            return versions["value"]
        except Exception as e:
            self.log.error(e)

    def retrieve_good_version(self, version_list):
        history_len = len(version_list)
        typed_versions = []

        for version in version_list:
            typed_version = {}
            typed_version["id"] = version_id = float(version["id"])
            typed_version["lastModifiedDateTime"] = version_date = parse(
                version["lastModifiedDateTime"]
            )
            typed_versions.append(typed_version)

            self.log.info(f"parsed date: {typed_version}")

        good_version = {"id": 0, "lastModifiedDateTime": None}
        for version in typed_versions:
            if (
                version["lastModifiedDateTime"] < self.restore_date
                and version["id"] >= good_version["id"]
            ):
                self.log.info(
                    f"version {version['id']} is the good version candidate..."
                )
                good_version["id"] = version["id"]
                good_version["lastModifiedDateTime"] = version["lastModifiedDateTime"]
        if good_version["id"] == 0 and good_version["lastModifiedDateTime"] is None:
            # TODO: add these file items to a csv output file for manual review
            self.log.info(
                f"no version candidates found older than {self.restore_date} with id greater than 0"
            )
            return good_version

        return good_version

    def restore_version(self, item, version_id):
        try:
            version_url = f"{self.base_url}drives/{self.drive_id}/items/{item['id']}/versions/{version_id}/restoreVersion"
            payload = {}
            response = self.sess.post(
                url=version_url, headers=self.refresh_header(), json=payload
            )
            if response.status_code == 204:
                return response.status_code
            elif response.status_code == 400:
                return response.json()["error"]["message"]
        except Exception as e:
            self.log.error(e)

    def remove_file_ext(self, item):
        try:
            item_url = f"{self.base_url}drives/{self.drive_id}/items/{item['id']}"
            new_name = re.sub(f"\{self.encrypted_file_extension}$", "", item["name"])
            item_data = {"name": new_name}
            if self.MODE == "PROD":
                response = self.sess.patch(
                    url=item_url,
                    headers=self.refresh_header(),
                    json=item_data,
                ).json()
                self.log.info(f"rename file: {item['name']} ----> {new_name}")
                return response
            else:
                self.log.info(
                    f"rename file: <DEV-MODE-SIMULATION> {item['name']} ----> {new_name}"
                )

        except Exception as e:
            self.log.error(e)

    def get_bogus_filename(self):
        ext = self.encrypted_file_extension.split(".")[1]
        bogus_filename = f"{ext}-readme.txt"
        return bogus_filename

    def remove_bogus_file(self, item):
        item_url = f"{self.base_url}drives/{self.drive_id}/items/{item['id']}"
        if self.MODE == "PROD":
            try:
                response = self.sess.delete(url=item_url, headers=self.refresh_header())
                self.log.info(
                    f"remove bogus file: {item['name']} -- {response.status_code}"
                )
            except Exception as e:
                self.log.error(e)
        else:
            self.log.info(f"remove bogus file: <DEV-MODE-SIMULATION> {item['name']}")

        print(item_url)

    def fix_file(self, item):
        version_history = self.check_version_history(item=item)
        self.log.info(f"status: checking versions...")
        good_version = self.retrieve_good_version(version_history)

        if good_version["id"] > 0:
            if self.MODE == "PROD":
                restore_result = self.restore_version(
                    item=item, version_id=good_version["id"]
                )
                self.log.info(
                    f"restore version status-code: {restore_result} {item['name']}"
                )

                updated_item = self.remove_file_ext(item=item)
                self.q_fixed_files.put(item)
            else:
                self.log.info(
                    f"restore version status-code: <DEV-MODE-SIMULATION> {item['name']}"
                )
                updated_item = self.remove_file_ext(item=item)

        self.q_unfixed_files.put(item)

    def mprocess_items(self, item: list):

        if "folder" in item.keys():
            self.q_folders = self.q_folders + 1
            self.log.info(f"{item['id']} folder {self.q_folders} - {item['name']}")
            subfolder_items = self.get_child_items(item_id=item["id"])
            for subfolder_item in subfolder_items:
                self.mprocess_items(subfolder_item)
            # try:
            #     pool.map(
            #         self.mprocess_items,
            #         subfolder_items,
            #         chunksize=thread_count * 3,
            #     )
            # except Exception as e:
            #     self.log.error(e)
            # self.process_items(data)
        elif "file":
            self.q_files = self.q_files + 1
            if item["name"].endswith(self.encrypted_file_extension):
                self.log.info(f"############## AFFECTED FILE ################")
                self.log.info(f"{item['id']} file {self.q_files} - {item['name']}")
                self.fix_file(item=item)
                self.log.info(f"#############################################\n")
            else:
                self.log.info(f"{item['id']} file {self.q_files}  - {item['name']}")
                if item["name"] == self.bogus_file:
                    self.remove_bogus_file(item)

    def process_items(self, items):

        for item in items:
            if "folder" in item.keys():
                self.q_folders = self.q_folders + 1
                self.log.info(f"{item['id']} folder {self.q_folders} - {item['name']}")
                subfolder_items = self.get_child_items(item_id=item["id"])
                for subfolder_item in subfolder_items:
                    self.mprocess_items(subfolder_item)
                # try:
                #     pool.map(
                #         self.mprocess_items,
                #         subfolder_items,
                #         chunksize=thread_count * 3,
                #     )
                # except Exception as e:
                #     self.log.error(e)
                # self.process_items(data)
            elif "file":
                self.q_files = self.q_files + 1
                if item["name"].endswith(self.encrypted_file_extension):
                    self.log.info(f"\n############## AFFECTED FILE ################")
                    self.log.info(f"{item['id']} file {self.q_files} - {item['name']}")
                    self.fix_file(item=item)
                    self.log.info(f"#############################################\n")
                else:
                    self.log.info(f"{item['id']} file {self.q_files}  - {item['name']}")
                    if item["name"] == self.bogus_file:
                        self.remove_bogus_file(item)

    def run(self):
        self.start_time = datetime.now()
        self.log.info(f"status: starting restore")
        root_folder_items = self.get_root_folder_items()

        try:
            self.process_items(root_folder_items)
        except KeyboardInterrupt:
            self.log.info(f"status: Keyboard Interrupt.  Exiting program...")
            self.log.error(
                f"status: repaired {self.q_fixed_files.unfinished_tasks} of {self.q_files} files and {self.q_folders} folders in {datetime.now() - self.start_time}"
            )
            sys.exit(0)
        except Exception as e:
            self.log.error(e)


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
        emit("restore_response", json.dumps(data), json=True)
        cache = _load_cache()
        service = OneDriveRestore(
            config_file="config.yaml",
            encrypted_file_extension=data["encrypted_file_extension"],
            username=session["user"].get("preferred_username"),
            MODE=data["mode"],
            # emit=emit,
        )

        try:
            service.run()
        except KeyboardInterrupt:
            print(f"status: exiting program...")
            print(
                f"status: repaired {service.q_fixed_files.unfinished_tasks} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}"
            )
            sys.exit(0)
        service.log.info(
            f"status: repaired {service.q_fixed_files.unfinished_tasks} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}"
        )
        emit(
            "restore_response",
            f"status: repaired {service.q_fixed_files.unfinished_tasks} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - start_time}",
        )
    emit("restore_response", "no extension defined", json=True)


@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))

    token = _get_token_from_cache(app_config.DELEGATED_PERMISSONS)
    user_data = requests.get(  # Use token to call downstream service
        url="https://graph.microsoft.com/v1.0/me/",
        headers={"Authorization": "Bearer " + token["access_token"]},
    ).json()

    return render_template("index.html", user=user_data, version=msal.__version__)


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

    return render_template(
        "restore.html",
        restore_date=data["restore_date"],
        user=session["user"],
    )


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
    socketio.run(app, host="localhost", port=app_config.PORT)
    # app.run(host="localhost")
