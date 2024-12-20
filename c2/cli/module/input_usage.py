from enum import Enum
from module.input_type import InputType

class InputUsage(Enum):
    Exit = InputType.Exit.value
    Help = InputType.Help.value
    Cmd = InputType.Cmd.value + ' ' + "whoami /all"
    Whoami = InputType.Whoami.value
    ListAgents = InputType.ListAgents.value
    CreateAgent = InputType.CreateAgent.value + ' ' + "agent_name" + ' ' + "127.0.0.1" + ' ' + "8080"
    RemoveAgent = InputType.RemoveAgent.value + ' ' + "758dcd88-b131-4d86-880a-2ee2edb8b656"
    ListTasks = InputType.ListTasks.value
    GetTaskOutput = InputType.GetTaskOutput.value
    ChangeAgent = InputType.ChangeAgent.value + ' ' + "758dcd88-b131-4d86-880a-2ee2edb8b656"
