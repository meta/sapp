# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.


import hmac
import logging
import os
from threading import get_ident
from typing import Optional

import sqlalchemy
from flask import Flask, request, send_from_directory
from flask.wrappers import Response
from flask_cors import CORS
from flask_graphql import GraphQLView
from pyre_extensions import none_throws
from sqlalchemy.orm import scoped_session, Session, sessionmaker

from .. import models
from ..db import DB
from .filters import ServeExportFilter
from .schema import schema

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.DEBUG
)
LOG: logging.Logger = logging.getLogger(__name__)


application = Flask(
    __name__, static_folder=os.path.join(os.path.dirname(__file__), "frontend", "build")
)

session: Optional[Session] = None

# Host names accepted in the Host header when the server is bound to a
# loopback address; anything else is rejected to blunt DNS-rebinding attacks
# (a malicious web page rebinding its origin to localhost:13337).
LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def bind_host() -> str:
    """Address the server listens on. SAPP_SERVER_HOST overrides the default
    localhost bind for hosted deployments (put auth in front when you do:
    set SAPP_AUTH_TOKEN)."""
    return os.environ.get("SAPP_SERVER_HOST") or "localhost"


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1")


@application.before_request
def _enforce_auth_and_host() -> Optional[Response]:
    # Optional bearer auth: when SAPP_AUTH_TOKEN is set, every request must
    # carry it. Comparison is constant-time. Unset means open (previous
    # behavior, fine for a localhost-only tool).
    token = os.environ.get("SAPP_AUTH_TOKEN")
    if token:
        authorization = request.headers.get("Authorization", "")
        if not hmac.compare_digest(authorization, "Bearer " + token):
            return Response("Unauthorized", status=401)
    if _is_loopback(bind_host()):
        host = request.host
        if host.startswith("["):  # IPv6 literal, e.g. [::1]:13337
            host = host[1 : host.index("]")]
        else:
            host = host.split(":")[0]
        if host.lower() not in LOCAL_HOSTNAMES:
            LOG.warning(f"Rejected request with non-local Host header: {request.host}")
            return Response("Bad Host header", status=403)
    return None


@application.after_request
def _security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@application.teardown_request
def shutdown_session(exception: Optional[BaseException] = None) -> None:
    if session is not None:
        # pyre-fixme[16]: `Session` has no attribute `remove`.
        session.remove()


@application.route("/", defaults={"path": ""})
@application.route("/<path:path>")
def serve(path: str) -> Response:
    LOG.info(f"Serving `{path}`...")
    static_folder = none_throws(application.static_folder)
    if path != "" and os.path.exists(static_folder + "/" + path):
        LOG.info("Found static resource.")
        return send_from_directory(static_folder, path)
    else:
        LOG.info("Resource not found. Falling back to `index.html`")
        return send_from_directory(static_folder, "index.html")


def start_server(
    database: DB,
    debug: bool,
    static_resources: Optional[str],
    source_directory: str,
    editor_schema: Optional[str],
) -> None:
    engine = sqlalchemy.create_engine(
        sqlalchemy.engine.url.URL("sqlite", database=database.dbname),
        echo=False,
        poolclass=None,
    )
    session = scoped_session(
        sessionmaker(bind=engine),
        scopefunc=get_ident,
    )
    models.Base.query = session.query_property()
    # We have additional tables for the UI that need to be created.
    models.create(database)

    application.add_url_rule(
        "/graphql",
        view_func=GraphQLView.as_view(
            "graphql",
            schema=schema,
            graphiql=True,
            get_context=lambda: {
                "session": session,
                "source_directory": os.path.expanduser(source_directory),
                "editor_schema": editor_schema,
            },
        ),
    )
    application.add_url_rule(
        "/export_filter/<string:filter_name>",
        view_func=ServeExportFilter.as_view("filter_export_view", session=session),
    )
    default_backend_port = int(os.environ.get("SAPP_SERVER_PORT") or 13337)
    if static_resources:
        application.static_folder = static_resources
    if debug:
        default_frontend_port = os.environ.get("PORT") or 3000
        host = os.environ.get("HOST") or "localhost"
        CORS(
            application,
            resources={
                r"/graphql": {
                    "origins": "http://{hostname}:{port}".format(
                        hostname=host, port=default_frontend_port
                    )
                }
            },
        )
    host = bind_host()
    LOG.info(
        f"SAPP UI on http://{host}:{default_backend_port} "
        f"(auth: {'token' if os.environ.get('SAPP_AUTH_TOKEN') else 'off'})"
    )
    application.run(debug=debug, host=host, port=default_backend_port)
