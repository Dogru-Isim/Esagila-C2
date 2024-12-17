import sys
import asyncio
from module import cli
from tokenize import tokenize
import importlib
from module.module_exception import *

def main():
    intro = "Welcome!\n"
    imhullu = cli.ImhulluCLI()
    while (imhullu.running):
        try:
            imhullu.do_change_agent_uuid("11e3b27c-a1e7-4224-b4d9-3af36fa2f0d0")
            imhullu.cmdloop(intro)
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

