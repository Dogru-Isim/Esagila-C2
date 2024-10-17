import sqlite3
import database.scripts.schema as db_schema
from database.scripts.database_error import DatabaseError

class DBServer:
    def __enter__(self):
        """Compatibility with the `with` functionality"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Compatibility with the `with` functionality"""
        return

    def create_db(self):
        conn = sqlite3.connect('database/database.db')
        cursor = conn.cursor()
        cursor.execute(db_schema.ct_task)
        cursor.execute(db_schema.ct_agent)
        cursor.execute(db_schema.ct_result)
        conn.commit()
        cursor.close()
        conn.close()

    def read_rows(self, table_name: db_schema.TableName, p_key: tuple) -> list[tuple]:
        conn = sqlite3.connect('database/database.db')
        cursor = conn.cursor()
        match table_name:
            case db_schema.TableName.TASK_TABLE.value:
                cursor.execute(db_schema.sf_task, p_key)
            case db_schema.TableName.AGENT_TABLE.value:
                cursor.execute(db_schema.sf_agent, p_key)
            case db_schema.TableName.RESULT_TABLE.value:
                cursor.execute(db_schema.sf_result, p_key)
            case _:
                if table_name not in [e.value for e in db_schema.TableName]:
                    raise DatabaseError(f"Tablename {table_name} not found")

        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows

    def insert_row(self, table_name: db_schema.TableName, values: tuple):
        """
        Raise DatabaseError if tablename is not found
        """
        conn = sqlite3.connect('database/database.db')
        cursor = conn.cursor()
        match table_name:
            case db_schema.TableName.TASK_TABLE.value:
                cursor.execute(db_schema.iit_task, values)
            case db_schema.TableName.AGENT_TABLE.value:
                cursor.execute(db_schema.iit_agent, values)
            case db_schema.TableName.RESULT_TABLE.value:
                cursor.execute(db_schema.iit_result, values)
            case _:
                if table_name not in [e.value for e in db_schema.TableName]:
                    raise DatabaseError(f"Tablename {table_name} not found")
        cursor.close()
        conn.commit()
        conn.close()

    def delete_row(self, table_name: db_schema.TableName, p_key: tuple):
        conn = sqlite3.connect('database/database.db')
        cursor = conn.cursor()
        match table_name:
            case db_schema.TableName.TASK_TABLE.value:
                cursor.execute(db_schema.df_task, p_key)
            case db_schema.TableName.AGENT_TABLE.value:
                cursor.execute(db_schema.df_agent, p_key)
            case _:
                if table_name not in [e.value for e in db_schema.TableName]:
                    raise DatabaseError(f"Tablename {table_name} not found")
        cursor.close()
        conn.commit()
        conn.close()

