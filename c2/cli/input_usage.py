from enum import Enum
from input_type import InputType

class InputUsage(Enum):
    Exit = InputType.Exit.value
    Help = InputType.Help.value
    Cmd = InputType.Cmd.value + ' ' + "whoami /all"
    Whoami = InputType.Whoami.value
    ListAgents = InputType.ListAgents.value
    CreateAgent = InputType.CreateAgent.value + ' ' + "agent_name"
    ListTasks = InputType.ListTasks.value
    GetTaskOutput = InputType.GetTaskOutput.value
    ChangeAgentUUID = InputType.ChangeAgentUUID.value + ' ' + "758dcd88-b131-4d86-880a-2ee2edb8b656"
