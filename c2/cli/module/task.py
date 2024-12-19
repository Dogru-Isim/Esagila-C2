class Task:
    def __init__(self, id, task_params, task_type, agent_uuid):
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

