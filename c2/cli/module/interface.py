import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
from module.interface_messages import Messages
import subprocess
import importlib
import os

class Interface:
    def __init__(self, webserver, agent_uuid=""):
        self._webserver = webserver
        self._agent_uuid = agent_uuid

    @property
    def webserver(self):
        return self._webserver

    @property
    def agent_uuid(self):
        return self._agent_uuid

    def agent_uuid_required(func):
        @functools.wraps(func)  # Preserve metadata, namely the doc string
        def wrapper(self, *args, **kwargs):
            if not self._agent_uuid:
                return Messages.AGENT_UUID_REQUIRED
            return func(self, *args, **kwargs)
        return wrapper

    def api_get_req(self, endpoint: str, agent_uuid: str=""):
        """
        endpoint: /example
        uuid: agent_uuid
        """
        response_raw = requests.get(self._webserver + endpoint + agent_uuid).text
        response_json = json.loads(response_raw)
        return response_json

    def api_post_req(self, endpoint: str, post_data, agent_uuid: str=""):
        """
        endpoint: /example
        post_data: json data
        uuid: agent_uuid
        """
        print(self._webserver+''.join(endpoint))
        response_raw = requests.post(self._webserver + ''.join(endpoint) + agent_uuid, json=post_data).text
        return(response_raw)

    @agent_uuid_required
    def do_get_task_output(self):
        """return the output of the last task\n\tUsage: <command>\n"""
        endpoint = "/get_task_output/"
        response_raw = requests.get(self._webserver + endpoint + self._agent_uuid).text
        response_json = json.loads(response_raw)
        if not response_json:
            return "No output"
        return b64decode(response_json[-1][-1]).decode()     # last result_text

