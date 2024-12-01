from enum import Enum

class InputDescription(Enum):
    Cmd = "Run CMD commands on the target machine"
    Exit = "Exit the program"
    Help = "Show this menu"
    ListAgents = "Show a list of all the agents"
    CreateAgent = "Create a new agent"
    ListTasks = "Show a list of all the pendings tasks of the agent"
    GetTaskOutput = "Get the output of the last task"
