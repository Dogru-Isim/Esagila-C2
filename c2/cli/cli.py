import cmd
import requests
import json
from base64 import b64decode, b64encode
from input_usage import InputUsage
from input_error import InputError
from input_type import InputType
import tableprint

class ImhulluCLI(cmd.Cmd):
    intro = "Welcome!"
    _webserver = "http://127.0.0.1:5001"
    _agent_uuid = ""
    prompt = f"Imhullu> "

    def default(self, line):
        """Override the default behavior for unrecognized commands."""
        if line.strip() == "":
            # do nothing if the input is empty
            # it runs the last command otherwise
            return
        else:
            print(f"Unrecognized command: {line}")
            self.do_help('')

    # Command to exit the tool
    def do_exit(self, arg):
        """exit the program\n\tUsage: <command>\n"""
        print('Goodbye!')
        return True

    # Command to list available commands
    def do_help(self, arg):
        """list available commands\n\tUsage: <command>\n"""
        if arg == 'all':
            for name, method in self.__class__.__dict__.items():
                if callable(method) and name.startswith('do_'):
                    print(f"{name.removeprefix('do_')}: {method.__doc__}")
            print()
            return

        print("Type `help all` to view every command description")
        super().do_help(arg)
        print()

    def do_change_agent_uuid(self, agent_uuid: str):
        """change current agent uuid\n\tUsage: <command> <agent_uuid>\n"""
        if not agent_uuid:
            print("Usage: " + InputUsage.ChangeAgentUUID.value)
            return

        self._agent_uuid = agent_uuid
        self.prompt = f"{agent_uuid}\nImhullu> ";

    def do_create_agent(self, name):
        """create a new agent\n\tWIP\n"""
        if not name:
            print("Usage: " + InputUsage.Name.value)
            return

        create_agent_payload = {
            "name": name
        }
        endpoint = "/create_agent/"
        create_agent_payload_json = json.dumps(create_agent_payload)
        agent_uuid = self._api_post_req(endpoint, post_data=create_agent_payload_json)
        print(agent_uuid)

    def do_list_agents(self, args):
        """list every agents\n\tUsage: <command>\n"""
        headers = ['Agent ID', 'Agent UUID', 'Agent Name']
        endpoint = "/agents/"
        output = ""
        agents = self._api_get_req(endpoint)
        tableprint.table(agents, headers)

    def do_cmd(self, args):
        """create a new cmd task\n\tUsage: <command> <arg1> <arg2> ...\n"""
        if not args:
            print("Usage: " + InputUsage.Cmd.value)
            return
        if not _agent_uuid:
            print("Choose an agent")
            return

        task = args
        b64EncodedTask = b64encode(task.encode())
        task = {
            "task": b64EncodedTask.decode(),
            "task_type": InputType.Cmd.value,    # cmd
            "agent_uuid": self._agent_uuid
        }

        endpoint = "/create_task/"
        task_json = json.dumps(task)
        response = self._api_post_req(endpoint, task_json, self._agent_uuid)
        print(response)

    def do_list_tasks(self, args):
        """show a list of all the agents\n\tUsage: <command>\n"""
        if not _agent_uuid:
            print("Choose an agent")
            return

        headers = ['Task ID', 'Command Args', 'Command Type', 'Agent UUID']
        endpoint = "/tasks/"
        output = ""
        tasks = self._api_get_req(endpoint, agent_uuid=self._agent_uuid)
        for task in tasks:
            task[1] = b64decode(task[1]).decode()    # decode command stored in b64
            output += '\n'

        tableprint.table(tasks, headers)

    def do_get_task_output(self, args):
        """return the output of the last task\n\tUsage: <command>\n"""
        if not args:
            print("Usage: " + InputUsage.GetTaskOutput.value)
            return
        if not _agent_uuid:
            print("Choose an agent")
            return

        endpoint = "/get_task_output/"
        response_raw = requests.get(self._webserver + endpoint + self._agent_uuid).text
        response_json = json.loads(response_raw)
        print(b64decode(response_json[-1][-1]).decode())     # last result_text

    def _api_get_req(self, endpoint: str, agent_uuid: str=""):
        """
        endpoint: /example
        uuid: agent_uuid
        """
        response_raw = requests.get(self._webserver + endpoint + agent_uuid).text
        response_json = json.loads(response_raw)
        return response_json

    def _api_post_req(self, endpoint: str, post_data, agent_uuid: str=""):
        """
        endpoint: /example
        post_data: json data
        uuid: agent_uuid
        """
        print(self._webserver+''.join(endpoint))
        response_raw = requests.post(self._webserver + ''.join(endpoint) + agent_uuid, json=post_data).text
        return(response_raw)


if __name__ == '__main__':
    ImhulluCLI().cmdloop()

