import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import logging

# Application setup
app = Flask(__name__)

# Load DB URI from environment for production safety (prevents hardcoded credentials)
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize DB
db = SQLAlchemy(app)

# Basic logger - production should configure handlers/formatters separately
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@app.route("/search", methods=["GET"])
def search_users():
    """
    Search users by a whitelisted column. This endpoint demonstrates safe
    parameterized query execution to prevent SQL injection (CWE-89).
    """
    # Whitelist allowed searchable columns to avoid arbitrary column injection
    allowed_columns = {"name": "name", "email": "email"}

    field = request.args.get("field", "name")
    if field not in allowed_columns:
        return jsonify({"error": "invalid search field"}), 400

    term = request.args.get("term", "").strip()
    if not term:
        return jsonify({"error": "term parameter is required"}), 400

    # Enforce simple length limits to protect against abuse
    if len(term) > 256:
        return jsonify({"error": "term too long"}), 400

    # Limit for rows returned - parse and clamp safely; avoid using user-controlled
    # values directly in query construction and ensure only numeric input is used.
    limit_str = request.args.get("limit", "50")
    if not limit_str.isdigit():
        limit = 50
    else:
        try:
            limit = int(limit_str)
        except Exception:
            limit = 50
    limit = max(1, min(limit, 100))

    # Build the SQL with a whitelisted column name inserted directly (safe)
    # and user-supplied values passed as bind parameters below to prevent SQL injection.
    column = allowed_columns[field]
    str_query = f"SELECT id, name, email FROM users WHERE {column} LIKE :term LIMIT :limit"

    # Prepare parameters using a dictionary; use parameterized execution below.
    params = {"term": f"%{term}%", "limit": limit}

    try:
        # Use SQLAlchemy Core/ORM select constructs via dynamic import to avoid raw text()
        # and to ensure parameters are bound by the engine (mitigates SQL injection - CWE-89).
        # We use __import__('sqlalchemy') here to avoid changing module-level imports while
        # still constructing a safe SQLAlchemy Select object programmatically.
        search_query = db.session.execute(
            __import__('sqlalchemy').select(
                db.metadata.tables['users'].c.id,
                db.metadata.tables['users'].c.name,
                db.metadata.tables['users'].c.email,
            ).where(
                db.metadata.tables['users'].c[column].like(__import__('sqlalchemy').bindparam('term'))
            ).limit(__import__('sqlalchemy').bindparam('limit')),
            {"term": params['term'], "limit": params['limit']}
        )  # Security: use SQLAlchemy select + bindparam to avoid text() raw execution

        rows = search_query.fetchall()

        # Build response while redacting any sensitive fields if necessary
        results = []
        for r in rows:
            results.append({
                "id": r[0],
                "name": r[1],
                "email": r[2],
            })

        return jsonify({"results": results}), 200

    except Exception as e:
        # Security: avoid logging exception stack traces or exception objects that may
        # contain sensitive runtime data or SQL fragments. Log only a short correlation
        # identifier so support can correlate logs without exposing PII/secrets.
        error_id = str(__import__('uuid').uuid4())  # generate id without adding top-level import
        logger.error("Database search failed; error_id=%s", error_id)
        # Return a generic error message; include the error_id to help diagnostics without exposing internals.
        return jsonify({"error": "internal server error", "error_id": error_id}), 500


if __name__ == "__main__":
    # Only for local development. In production, use a WSGI server.
    # Bind to localhost by default to avoid exposing the development server publicly (CWE-668).
    # Allow overriding via FLASK_RUN_HOST if explicitly required in your environment.
    app.run(host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
