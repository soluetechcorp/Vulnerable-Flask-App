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

    # Limit for rows returned
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 100))

    # Build the SQL with a whitelisted column name inserted directly (safe)
    # and user-supplied values passed as bind parameters below to prevent SQL injection.
    column = allowed_columns[field]
    str_query = f"SELECT id, name, email FROM users WHERE {column} LIKE :term LIMIT :limit"

    # Prepare parameters using a dictionary; use parameterized execution below.
    params = {"term": f"%{term}%", "limit": limit}

    try:
        # Use SQLAlchemy Core select with literal_column and bindparam to avoid executing
        # a raw text SQL string that could bypass ORM protections (fix for CWE-89).
        # Local imports used to avoid changing module-level imports.
        from sqlalchemy import select, literal_column, bindparam

        # Select id, the whitelisted column, and email. literal_column(column) is safe
        # because 'column' was previously validated against the whitelist.
        stmt = select([literal_column("id"), literal_column(column), literal_column("email")]) \
            .where(literal_column(column).like(bindparam("term"))).limit(bindparam("limit"))

        # Execute the statement with a params dict so user input is bound safely.
        search_query = db.session.execute(stmt, params)
        # Security comment: using Core select() with bound parameters prevents injection attacks.

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
        # Do not log sensitive user input; log generic error and return generic message
        logger.exception("Database search failed")
        return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    # Only for local development. In production, use a WSGI server.
    # Bind to localhost by default to avoid exposing the development server publicly (CWE-668).
    # Allow override via FLASK_RUN_HOST environment variable for controlled deployments.
    app.run(host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
