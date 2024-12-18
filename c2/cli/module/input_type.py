from enum import Enum

class InputType(Enum):
    Exit = "exit"
    Help = "help"
    Cmd = "cmd"
    Whoami = "whoami"
    ListAgents = "list_agents"
    CreateAgent = "create_agent"
    RemoveAgent = "remove_agent"
    ListTasks = "list_tasks"
    GetTaskOutput = "get_task_output"
    ChangeAgentUUID = "change_agent_uuid"
    #
    AgentShutdown = "shutdown"
