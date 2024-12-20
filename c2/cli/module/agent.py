class Agent:
    def __init__(self, id:int = -1, uuid:str = "", name:str = "", server:str = "", port:str = ""):
        self._id = id
        self._uuid = uuid
        self._name = name
        self._server = server
        self._port = port

    @property
    def id(self):
        return self._id

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def name(self):
        return self._name

    @property
    def server(self):
        return self._server

    @property
    def port(self):
        return self._port

