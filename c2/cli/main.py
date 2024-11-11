import asyncio
from cli import Cli
from tokenize import tokenize

def main():
    cli = Cli()
    while True:
        cli.change_agent_uuid("11e3b27c-a1e7-4224-b4d9-3af36fa2f0d0")
        cmd_tokens, errors = cli.get_input()
        if len(errors) != 0:
            for e in errors:
                print("Error:", e.value)
            print()
            continue

        cli.process_input(cmd_tokens)

if __name__ == "__main__":
    main()
