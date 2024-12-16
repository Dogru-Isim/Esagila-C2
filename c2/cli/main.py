import asyncio
from cli import ImhulluCLI
from tokenize import tokenize

def main():
    cli = ImhulluCLI()
    cli.do_change_agent_uuid("11e3b27c-a1e7-4224-b4d9-3af36fa2f0d0")
    cli.cmdloop()

if __name__ == "__main__":
    main()

