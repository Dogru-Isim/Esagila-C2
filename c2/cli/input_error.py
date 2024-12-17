from enum import Enum

class InputError(Enum):
    TaskTypeNotFound = "Task type not found"
    IncoherentParameterAmount = "Number of parameters isn't correct"

