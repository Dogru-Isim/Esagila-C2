# Esagila-C2
C2 framework for school project

The implementation of the `agent`, the `server`, and the `cli` is in the `c2` directory

## Usage

**Run the Server**

Go to the `server` directory in `c2` and run `main.py`\
View README.md under `server`

**Run the CLI**

Go to the `cli` directory in `c2` and run `main.py`\
View README.md under `cli`

**Esagila Agent**

View README.md under `agent`



## Notes For Developers

### Agent

#### Entry Point

The main function is in `agent/src/loader.c`, it's called `myMain`

`myMain` is loaded by an assembly stub from `agent/src/adjuststack.asm`

The first thing it does it locate the address of `kernel32.dll`
after defining the names of the functions and DLLs we need, it goes on to extracting the address of `LoadLibraryA`
this is achieved by using `GetProcAddress` defined in `addresshunter.c`.

We can now load any Windows DLL using `LoadLibraryA` and use their functions (e.g. user32dll->MessageBoxA)

After loading the necessary DLLs, pointers to functions we need are exported and assigned to their respective fields in the function API using `GetSymbolAddress`.

Now that the function has all of the Win32 functions it needs, it can perform the steps to download the initial reflective DLL a.k.a. [Std Esagila DLL](#standard-esagila-dll)

After downloading the Std Esagila DLL, the entry point runs the reflective loader in the downloaded DLL to align the DLLs sections, resolve the import table, perform base reallocations etc.

Now that we have the standard DLL, we can start sending callbacks to the webserver. We start querying `/tasks/<agent_uuid>` for any [task](#what-is-a-task) to run.

When a task is found, the agent parses the response and extracts the task ID, task paramaters, and task type. A series of if else statements are used to
determine what function to run from the standard DLL.

After running the task, the following data is populated:
1. the task id (obtained from the first json, used for deleting the task from the database)
2. the current agent's uuid (to identify the agent for updating the result table in the database) 
3. the output of the task base64 encoded (if the task doesn't have an output, a return value hardcoded per task is sent to the server)

The format of the json is defined as follows
```C
{
'{', '"', 't', 'a', 's', 'k', '_', 'i', 'd', '"', ':', ' ', '"', '%', 's', '"', ',',
' ', '"', 'a', 'g', 'e', 'n', 't', '_', 'u', 'u', 'i', 'd', '"', ':', ' ', '"',
'%', 's', '"', ',', ' ', '"', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p',
'u', 't', '"', ':', ' ', '"', '%', 's', '"', '}'
};
```

----

#### Function API

The function API is defined as:
```C
typedef struct API_
{
    UINT64 LoadLibraryA;
    UINT64 CloseHandle;
    UINT64 Sleep;
    ...
} API, *PAPI;
```
Because of the way the project implements PIC, we can't have global variables so the functions that
were loaded in the entry point cannot be used by other functions unless they are passed as parameters.

This is where the API comes into play. It keeps all the functions in one place which allows us to pass
only one pointer (the API) and use every Win32 function we need.

`NOTE: It could be a good idea to use a static variable to hold the API.`

----

#### Standard Esagila DLL

This is the initial reflective DLL that the entry point downloads. Currently, it contains the whole
functionality of the program - execute assembly, run cmd, reflective loader...

It's made to be extendable and separable. The main idea is that different types functionality can be
implemented in different DLLs such as `adcs.dll` for ADCS exploitation.

However, this is a decision that should be left to the user as they might prefer to load one
reflective DLL that has all the functionality they need to reduce network traffic.

the Standard Esagila DLL sits at the endpoint `/stage/` on the web server.

#### What is a Task

A task has the following structure:
```
1. Task Id
2. Task Parameters
3. Task Type
4. Agent UUID to run the task
```

In the code, task parameters is often referred to as just "task". This is caused by deprecated functionality and should be changed.

**Task Id**: Task id is used to inform the web server that a task has been run by the agent and that it can now be removed. 

**Task Parameters**: Task parameters are used for telling the agent how to run the task specified by the Task Type. A task type
is stored and transferred in base64 encoded format.

**Task Type**: Task type is used to inform the agent what task to run

**Agent UUID**: Agent UUID is used for filtering. When an agent makes a callback to `/tasks/` the web server shows only the tasks that belongs to that agent.
The agent UUID is set by the interface upon the creation of a task.

A task is transferred from the web server to the agent in JSON. An example task would be:
```json
[
    [
        284,                                            -> task ID
        "d2hvYW1p",                                     -> task parameters (often referred to as "task" which needs to be changed)
        "cmd",                                          -> task type
        "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"          -> agent UUID
    ],
    [
        285,
        "ZGly",
        "cmd",
        "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"
    ]
]
```
