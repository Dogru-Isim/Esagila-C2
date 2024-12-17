from database.scripts.server import DBServer
from listening_post.webserver import WebServer

with DBServer() as db:
    db.create_db()

WebServer.run()

