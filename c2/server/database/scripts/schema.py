from enum import Enum

"""
ct_TABLENAME = create table TABLENAME
iit_TABLENAME = insert into TABLENAME
df_TABLENAME = delete from TABLENAME
"""

class TableName(Enum):
    TASK_TABLE = "task"
    AGENT_TABLE = "agent"
    TASK_AGENT_INTER_TABLE = "task_agent_inter"
    RESULT_TABLE = "result"

ct_task =           f"""
                    CREATE TABLE IF NOT EXISTS {TableName.TASK_TABLE.value} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task TEXT NOT NULL,
                        task_type TEXT NOT NULL,
                        agent_uuid TEXT NOT NULL
                    );
                    """

ct_agent =          f"""
                    CREATE TABLE IF NOT EXISTS {TableName.AGENT_TABLE.value} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        uuid TEXT NOT NULL,
                        name TEXT
                        server TEXT NOT NULL,
                        port TEXT NOT NULL
                    );
                    """

ct_result =         f"""
                    CREATE TABLE IF NOT EXISTS {TableName.RESULT_TABLE.value} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_uuid TEXT NOT NULL,
                        task_id INTEGER NOT NULL,
                        result_text TEXT
                    );
                    """

sf_task =           f"""
                    SELECT * FROM {TableName.TASK_TABLE.value}
                    WHERE agent_uuid = (?);
                    """

sf_agent =          f"""
                    SELECT * FROM {TableName.AGENT_TABLE.value}
                    WHERE uuid LIKE (?);
                    """

sf_result =         f"""
                    SELECT * FROM {TableName.RESULT_TABLE.value}
                    WHERE agent_uuid = (?)
                    """

iit_task =          f"""
                    INSERT INTO {TableName.TASK_TABLE.value}(task, task_type, agent_uuid)
                    VALUES(?, ?, ?);
                    """

iit_agent =         f"""
                    INSERT INTO {TableName.AGENT_TABLE.value}(uuid, name, server, port)
                    VALUES (?, ?);
                    """

iit_result =        f"""
                    INSERT INTO {TableName.RESULT_TABLE.value}(agent_uuid, task_id, result_text)
                    VALUES (?, ?, ?)
                    """

df_task =           f"""
                    DELETE FROM {TableName.TASK_TABLE.value}
                    WHERE id = (?) AND agent_uuid = (?);
                    """

df_agent =          f"""
                    DELETE FROM {TableName.AGENT_TABLE.value}
                    WHERE uuid = (?);
                    """

