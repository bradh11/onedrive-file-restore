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
import yaml
import requests
from urllib3.util import Retry
from dateutil.parser import parse
import logging
from logging import FileHandler
from rich.logging import RichHandler
from rich import print


cpu_count = os.cpu_count()
thread_count = os.cpu_count() * 5
print(f"CPU COUNT:     {cpu_count}")
print(f"THREAD COUNT:  {thread_count}")
print(f"=" * 17)

# create the thread pool and make it interruptable
set_start_method("spawn")
freeze_support()
original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
pool = ThreadPool(thread_count)
signal.signal(signal.SIGINT, original_sigint_handler)


class OneDriveRestore:
    def __init__(self, config_file, token=None, username=None):
        self.q_files = 0
        self.q_folders = 0
        self.q_fixed_files = Queue()
        self.q_unfixed_files = Queue()
        self.queue = Queue()

        # load config file
        with open(config_file, "r") as f:
            self.config = yaml.safe_load(f)

        if not token:
            self.token = self.config.get("token")
        else:
            # set token when instantiating the class
            self.token = token
        if not username:
            self.username = self.config.get("username")
        else:
            # set username when instantiating the class
            self.username = username

        self.encrypted_file_extension = self.config.get("encrypted_file_extension")
        self.restore_date = self.config.get("restore_date")

        self.MODE = self.config.get("MODE", "DEV")
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
        self.header = self.refresh_header(token)

        self.user_drive_url = f"{self.base_url}users/{self.username}/drives"
        self.drive = self.get_drive()
        self.drive_id = self.get_drive_id(self.drive)

    def refresh_header(self, token):
        access_token = token["access_token"]
        header = {
            "authorization": f"bearer {access_token}",
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
                headers=self.refresh_header(self.token),
            )
            return response
        except Exception as e:
            self.log.error(e)
            sys.exit(0)

    def get_drive(self):
        try:
            mydrive = self.sess.get(
                url=self.user_drive_url, headers=self.refresh_header(self.token)
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

    def get_root_folder_items(self):
        try:
            root_folder_url = f"{self.base_url}drives/{self.drive_id}/root/children"
            data = self.sess.get(
                url=root_folder_url, headers=self.refresh_header(self.token)
            ).json()
            return data
        except Exception as e:
            self.log.error(e)

    def get_child_items(self, item_id):
        try:
            child_url = (
                f"{self.base_url}drives/{self.drive_id}/items/{item_id}/children"
            )
            child_items = self.sess.get(
                url=child_url, headers=self.refresh_header(self.token)
            )
            return child_items.json()
        except Exception as e:
            self.log.error(e)

    def check_version_history(self, item):
        try:
            item_url = (
                f"{self.base_url}drives/{self.drive_id}/items/{item['id']}/versions"
            )
            versions = self.sess.get(
                url=item_url, headers=self.refresh_header(self.token)
            ).json()
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
                url=version_url, headers=self.refresh_header(self.token), json=payload
            )
            return response
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
                    headers=self.refresh_header(self.token),
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

    def fix_file(self, item):
        version_history = self.check_version_history(item=item)
        self.log.info(f"status: checking versions...")
        good_version = self.retrieve_good_version(version_history)

        # TODO: restore the good version here
        if good_version["id"] > 0:
            if self.MODE == "PROD":
                restore_result = self.restore_version(
                    item=item, version_id=good_version["id"]
                )
                self.log.info(
                    f"restore version status-code: {restore_result} {item['name']}"
                )
                # TODO: update the filename - uncomment line below...
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
            subfolder_data = {}
            subfolder_data["drive_id"] = self.drive_id
            subfolder_data["items"] = subfolder_items
            try:
                pool.map(
                    self.mprocess_items,
                    subfolder_data["items"]["value"],
                    chunksize=thread_count * 3,
                )
            except Exception as e:
                self.log.error(e)
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

    def process_items(self, data):
        drive_id = data["drive_id"]
        items = data["items"]
        for item in items["value"]:
            if "folder" in item.keys():
                self.q_folders = self.q_folders + 1
                self.log.info(f"{item['id']} folder {self.q_folders} - {item['name']}")
                subfolder_items = self.get_child_items(item_id=item["id"])
                subfolder_data = {}
                subfolder_data["drive_id"] = drive_id
                subfolder_data["items"] = subfolder_items
                # pool.imap_unordered(process_items, data)
                try:
                    pool.map(
                        self.mprocess_items,
                        subfolder_data["items"]["value"],
                        chunksize=thread_count * 3,
                    )
                except Exception as e:
                    self.log.error(e)
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

    def run(self):
        self.start_time = datetime.now()
        self.log.info(f"status: starting restore")
        mydrive = self.get_drive()
        mydrive_id = self.get_drive_id(mydrive)
        folder_items = self.get_root_folder_items()
        data = {}
        data["drive_id"] = mydrive_id
        data["items"] = folder_items
        try:
            self.process_items(data)
        except KeyboardInterrupt:
            self.log.info(f"status: exiting program...")
            self.log.error(
                f"status: repaired {self.q_fixed_files.unfinished_tasks + 1} of {self.q_files} files and {self.q_folders} folders in {datetime.now() - self.start_time}"
            )
            sys.exit(0)
        except Exception as e:
            self.log.error(e)


if __name__ == "__main__":
    service = OneDriveRestore("config.yaml")
    service.run()
    print(
        f"status: repaired {service.q_fixed_files.unfinished_tasks + 1} of {service.q_files} files and {service.q_folders} folders in {datetime.now() - service.start_time}"
    )
