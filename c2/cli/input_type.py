from enum import Enum

class InputType(Enum):
    Cmd = "cmd"
    Exit = "exit"
    Help = "help"
    ListAgents = "list-agents"
    CreateAgent = "create-agent"
    ListTasks = "list-tasks"
    GetTaskOutput = "get-task-output"
