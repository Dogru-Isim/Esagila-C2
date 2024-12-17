class ImhulluModuleReloadException(BaseException):
    """Custom base exception class for reloading modules"""
    pass
    
class ImhulluCLIReloadedException(ImhulluModuleReloadException):
    """Custom exception class for reloading ImhulluCLI"""
    pass

