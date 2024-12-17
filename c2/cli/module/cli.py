import cmd
import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
import tableprint

UNDERLINE = "\033[4m"
RESET = "\033[0m"

class ImhulluCLI(cmd.Cmd):
    running = 1
    _webserver = "http://127.0.0.1:5001"
    _agent_uuid = ""
    prompt = f"{UNDERLINE}Imhullu>{RESET} "
    
    def agent_uuid_required(func):
        @functools.wraps(func)  # Preserve metadata, namely the doc string
        def wrapper(self, *args, **kwargs):
            if not self._agent_uuid:
                print("Choose an agent")
                return
            return func(self, *args, **kwargs)
        return wrapper

    # override the default functionality
    # https://docs.python.org/3/library/cmd.html#cmd.Cmd.emptyline
    def emptyline(self):
        print()
        return

    def default(self, line):
        """override the default behavior for unrecognized commands."""
        print(f"Unrecognized command: {line}")
        self.do_help('')

    def do_reload(self, arg):
        """reload ImhulluCLI"""
        raise ImhulluCLIReloadedException

    # Command to exit the tool
    def do_exit(self, arg):
        """exit the program\n\tUsage: <command>\n"""
        print('Goodbye!')
        self.running = 0
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

    def complete_help(self, text, line, begidx, endidx):
        """Provide tab completion for the 'greet' command."""
        params = [method.removeprefix("do_") for method in self.__class__.__dict__.keys() if method.startswith("do_")]
        params.append('all')
        if not text:
            # If no text is entered, return all names
            completions = params[:]
        else:
            # Filter names based on the text entered
            completions = [param for param in params if param.startswith(text)]
        return completions

    def do_change_agent_uuid(self, agent_uuid: str):
        """change current agent uuid\n\tUsage: <command> <agent_uuid>\n"""
        if not agent_uuid:
            print("Usage: " + InputUsage.ChangeAgentUUID.value + '\n')
            return

        self._agent_uuid = agent_uuid
        self.prompt = f"{agent_uuid}\n{UNDERLINE}Imhullu>{RESET} ";

    def do_create_agent(self, name):
        """create a new agent\n\tWIP\n"""
        if not name:
            print("Usage: " + InputUsage.CreateAgent.value + '\n')
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

        if len(agents) == 0:
            print("No agent present")
            return

        tableprint.table(agents, headers)

    def _create_task(self, task):
        """general function for creating tasks\nevery task creation function calls this"""
        endpoint = "/create_task/"
        task_json = json.dumps(task)
        response = self._api_post_req(endpoint, task_json, self._agent_uuid)
        return response

    @agent_uuid_required
    def do_cmd(self, args):
        """create a new cmd task\n\tUsage: <command> <arg1> <arg2> ...\n"""
        if not args:
            print("Usage: " + InputUsage.Cmd.value + '\n')
            return

        task = args
        b64EncodedTask = b64encode(task.encode())
        task = {
            "task": b64EncodedTask.decode(),
            "task_type": InputType.Cmd.value,    # cmd
            "agent_uuid": self._agent_uuid
        }

        print(self._create_task(task)) + '\n'

    @agent_uuid_required
    def do_whoami(self, line):
        """get user info through GetUserName\nUsage: <command>\n"""
        task = {
            "task": "",
            "task_type": InputType.Whoami.value,
            "agent_uuid": self._agent_uuid
        }

        print(self._create_task(task)) + '\n'

    @agent_uuid_required
    def do_list_tasks(self, args):
        """show a list of all the agents\n\tUsage: <command>\n"""
        headers = ['Task ID', 'Command Args', 'Command Type', 'Agent UUID']
        endpoint = "/tasks/"
        output = ""
        tasks = self._api_get_req(endpoint, agent_uuid=self._agent_uuid)
        for task in tasks:
            task[1] = b64decode(task[1]).decode()    # decode command stored in b64
            output += '\n'

        if len(tasks) == 0:
            print("Task queue empty\n")
            return

        tableprint.table(tasks, headers)

    @agent_uuid_required
    def do_get_task_output(self, args):
        """return the output of the last task\n\tUsage: <command>\n"""
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
    cli = ImhulluCLI()
    cli.cmdloop()
