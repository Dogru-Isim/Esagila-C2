import requests
import json
import sys
import time
from input_type import InputType
from input_description import InputDescription
from input_error import InputError

class Cli():
    _prompt = "Imhullu> "
    _webserver = "http://127.0.0.1:5001"
    _agent_uuid = ""

    def help(self):
        frmt = "{cmd}: {desc}"
        print("\nHelp: \n")
        for task, desc in zip(InputType, InputDescription):
            print(frmt.format(cmd=task.value, desc=desc.value))
        print() # newline

    def change_agent_uuid(self, agent_uuid: str):
        self._agent_uuid = agent_uuid

    def api_get_req(self, endpoint: str, agent_uuid: str=""):
        response_raw = requests.get(self._webserver + endpoint + agent_uuid).text
        response_json = json.loads(response_raw)
        return response_json

    def api_post_req(self, endpoint: str, post_data, agent_uuid: str=""):
        print(self._webserver+''.join(endpoint))
        response_raw = requests.post(self._webserver + ''.join(endpoint) + agent_uuid, json=post_data).text
        return(response_raw)

    def create_agent(self, create_agent_payload=""):
        endpoint = "/create_agent/"
        create_agent_payload_json = json.dumps(create_agent_payload)
        agent_uuid = self.api_post_req(endpoint, post_data=create_agent_payload_json)
        return agent_uuid

    def list_agents(self):
        endpoint = "/agents/"
        output = ""
        agents = self.api_get_req(endpoint)
        for agent in agents:
            output += ' || '.join([str(e) for e in agent])
            output += '\n'
        return output

    def create_task(self, task):
        endpoint = "/create_task/"
        task_json = json.dumps(task)
        response = self.api_post_req(endpoint, task_json, self._agent_uuid)
        return response

    def list_tasks(self):
        endpoint = "/tasks/"
        output = ""
        tasks = self.api_get_req(endpoint, agent_uuid=self._agent_uuid)
        for task in tasks:
            output += ' || '.join([str(e) for e in task])
            output += '\n'
        return output

    def get_task_output(self, agent_uuid: str):
        """
        Return the output of the last task of the agent with the `agent_uuid`
        """
        endpoint = "/get_task_output/"
        response_raw = requests.get(self._webserver + endpoint + agent_uuid).text
        response_json = json.loads(response_raw)
        return response_json[-1][-1]     # last result_text

    def get_input(self) -> (list[str], list[InputError]):
        errors: list[InputError] = list()
        print(f"({self._agent_uuid})")
        tokens = input(self._prompt).split()
        if tokens[0] not in [e.value for e in InputType]:
            errors.append(InputError.TaskTypeNotFound)
        if tokens[0] == InputType.CreateAgent.value and len(tokens) > 2:
            errors.append(InputError.IncoherentParameterCount)
        return (tokens, errors)

    def process_input(self, input_token: list[str]) -> None | list[InputError]:
        errors: list[InputError] = list()
        match input_token[0]:                           # task type (->cmd<- ls -la)
            case InputType.Exit.value:
                sys.exit(0)

            case InputType.Help.value:
                self.help()

            case InputType.Cmd.value:
                task = {
                    "task":' '.join(input_token[1:]),   # ls -la
                    "task_type": InputType.Cmd.value,    # cmd
                    "agent_uuid": self._agent_uuid
                }
                print(self.create_task(task))
                print("Created task")

            case InputType.ListTasks.value: 
                print("\nTasks:\n")
                print(self.list_tasks())

            case InputType.GetTaskOutput.value:
                print("\nOutput:\n")
                print(self.get_task_output(self._agent_uuid))

            case InputType.CreateAgent.value:    # create-agent
                create_agent_payload = {
                    "name": input_token[1]      # agent1
                }
                print("Created agent uuid: ", self.create_agent(create_agent_payload))

            case InputType.ListAgents.value:
                print(self.list_agents())
