import sys
import asyncio
from module import cli
from tokenize import tokenize
import importlib
import requests
from module.module_exception import *

def main():
    intro = "Welcome!\n"
    imhullu = cli.ImhulluCLI()
    while (imhullu.running):
        try:
            imhullu.cmdloop(intro)
        except requests.exceptions.ConnectionError:
            intro = "\n"
            print("Can't connect to server")
        except KeyboardInterrupt:
            intro = "\n"
        except ImhulluModuleReloadException as e:
            match e:
                case ImhulluCLIReloadedException():
                    importlib.reload(cli)
                    imhullu = cli.ImhulluCLI()
                    intro = "ImhulluCLI reloaded\n"
                case _:
                    print("Unknown exception: ", e)

if __name__ == "__main__":
    main()

