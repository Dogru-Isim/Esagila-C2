import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
from module.interface_messages import InterfaceMessages
from module.task import Task
from module.agent import Agent
import subprocess
import importlib
import os

class Interface:
    def __init__(self, webserver, agent:Agent = None):
        self._webserver = webserver
        self._agent = agent

    @property
    def webserver(self):
        return self._webserver

    @property
    def agent(self):
        return self._agent

    @agent.setter
    def agent(self, agent:Agent):
        self._agent = agent

    def agent_uuid_required(func):
        @functools.wraps(func)  # Preserve metadata, namely the doc string
        def wrapper(self, *args, **kwargs):
            if not self.agent.uuid:
                return InterfaceMessages.AgentUUIDRequired
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
        Parameters:
            endpoint: /example
            post_data: json data
            uuid: agent_uuid
        """
        print(self._webserver+''.join(endpoint))
        response_raw = requests.post(self._webserver + ''.join(endpoint) + agent_uuid, json=post_data).text
        return response_raw

    def create_task(self, task: Task):
        """
        General function for creating tasks

        Parameters:
            task (Task): task to create
        Returns:
            response (str): Return value from the server
        """
        endpoint = "/create_task/"
        task_json = task.jsonify()
        response = self.api_post_req(endpoint, task_json, self.agent.uuid)
        return response

    @agent_uuid_required
    def cmd(self, args):
        """
        Create a new cmd task

        Returns:
            str: Return value from the server
            InterfaceMessages.AgentUUIDRequired: Return value if fail
        """
        b64_task_params = b64encode(args.encode())
        task: Task = Task(task_params=b64_task_params.decode(), task_type=InputType.Cmd.value, agent_uuid=self.agent.uuid)

        return self.create_task(task) + '\n'

    @agent_uuid_required
    def get_task_output(self):
        """
        Return the output of the last task

        Returns:
            str: The return value, empty string if an output doesn't exist
            InterfaceMessages.AgentUUIDRequired: Return value if fail
        """
        endpoint = "/get_task_output/"
        response_raw = requests.get(self._webserver + endpoint + self.agent.uuid).text
        response_json = json.loads(response_raw)
        if not response_json:
            return ""
        return b64decode(response_json[-1][-1]).decode()     # last result_text

    @agent_uuid_required
    def get_tasks(self):
        """
        Get all the tasks belonging to the current agent

        Returns:
            list[Task]: The return value if successful
            InterfaceMessages.TaskQueueEmpty: The enum value if no task is present
            InterfaceMessages.AgentUUIDRequired: The enum value if no agent is chosen
        """
        endpoint = "/tasks/"
        response = self.api_get_req(endpoint, agent_uuid=self.agent.uuid)
        tasks: list[Task] = []

        if len(response) == 0:
            return InterfaceMessages.TaskQueueEmpty

        for task in response:
            task[1] = b64decode(task[1]).decode()    # decode task_params

        for task in response:
            tasks.append(Task(id=task[0], task_params=task[1], task_type=task[2], agent_uuid=task[3]))

        return tasks

    @agent_uuid_required
    def whoami(self):
        """
        Get user info through GetUserName

        Returns:
            str: Response from the web server
            InterfaceMessages.AgentUUIDRequired: Return value if fail
        """
        task = Task(task_type=InputType.Whoami.value, agent_uuid=self.agent.uuid)

        return self.create_task(task) + '\n'

    @agent_uuid_required
    def shutdown_agent(self):
        """
        Send shutdown signal to the agent
        Agent UUID required

        Returns:
            response (str): Response from the web server if success
            InterfaceMessages.AgentUUIDRequired: Return value if fail
        """
        task: Task = Task(task_type=InputType.AgentShutdown.value, agent_uuid=self.agent.uuid)
        return self.create_task(task) + '\n'

    def get_agents(self) -> list[Agent] | InterfaceMessages:
        """
        Fetch every agent from the server

        Returns:
            agents (list[Agent]): list of agents if success
            message (InterfaceMessages.NoAgentPresent): return value if failure
        """
        endpoint = "/agents/"
        output = ""
        response = self.api_get_req(endpoint)

        if len(response) == 0:
            return InterfaceMessages.NoAgentPresent

        agents:list[Agent] = []
        for agent in response:
            agents.append(Agent(id=agent[0], uuid=agent[1], name=agent[2], server=agent[3], port=agent[4]))

        return agents

    def create_agent(self, agent:Agent):
        """
        Create a new agent

        Parameters:
            agent (Agent): instance of Agent with name (optional), server and port
        """
        endpoint = "/create_agent/"
        agent_json = agent.jsonify()

        uuid = self.interface.api_post_req(endpoint, post_data=agent_json)

        self._compile_agent(name, server, port, uuid)

        return uuid

    def _compile_agent(self, name, server, port, uuid):
        """modify agent server and port then compiler"""
        pi_server = ''
        pi_uuid = ''
        for char in server:
            pi_server += "'" + char + "'" + ','
        for char in uuid:
            pi_uuid += "'" + char + "'" + ','
            
        pi_server += '0'  # null terminator
        pi_uuid += '0'    # null terminator

        command = ["make", f'SERVER_M="{pi_server}"', f'PORT_M="{port}"', f'UUID_M="{pi_uuid}"']
        print(command[0] + ' ' + command[1] + ' ' + command[2] + ' ' + command[3])
        process = subprocess.Popen(command, cwd="../agent/", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            # Read a line from the output
            output = process.stdout.readline()
            
            # If the output is empty and the process has finished, break the loop
            if output == '' and process.poll() is not None:
                break
            
            # If there is output, print it
            if output:
                print(output.strip())

        # Wait for the process to complete and get the return code
        return_code = process.wait()
