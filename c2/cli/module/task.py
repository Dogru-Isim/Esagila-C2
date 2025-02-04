import json

class Task:
    def __init__(self, id:int = -1, task_params:str = '', task_type:str = '', agent_uuid:str = ''):
        self._id = id
        self._task_params = task_params
        self._task_type = task_type
        self._agent_uuid = agent_uuid

    @property
    def id(self):
        return self._id

    @property
    def task_params(self):
        return self._task_params

    @property
    def task_type(self):
        return self._task_type

    @property
    def agent_uuid(self):
        return self._agent_uuid

    def jsonify(self):
        task = {
            "id": self._id,
            "task": self._task_params,
            "task_type": self._task_type,    # cmd
            "agent_uuid": self._agent_uuid
        }
        return json.dumps(task)

