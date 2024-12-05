from enum import Enum

class InputType(Enum):
    Exit = "exit"
    Help = "help"
    Cmd = "cmd"
    Whoami = "whoami"
    ListAgents = "list-agents"
    CreateAgent = "create-agent"
    ListTasks = "list-tasks"
    GetTaskOutput = "get-task-output"
