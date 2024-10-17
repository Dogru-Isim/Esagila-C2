import asyncio
from cli import Cli
from tokenize import tokenize

def main():
    cli = Cli()
    while True:
        cli.change_agent_uuid("agent_uuid1")
        cmd_tokens, errors = cli.get_input()
        if len(errors) != 0:
            for e in errors:
                print("Error:", e.value)
            continue

        cli.process_input(cmd_tokens)

if __name__ == "__main__":
    main()
