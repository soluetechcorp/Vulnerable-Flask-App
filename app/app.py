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
        # Build a safe SQLAlchemy Core statement using reflected table and bound parameters
        # Local imports here avoid touching top-level import order while enabling use of
        # SQLAlchemy Core constructs (select, Table, bindparam) to prevent SQL injection.
        from sqlalchemy import Table, select, bindparam

        # Reflect the 'users' table from the database metadata to build a safe expression
        users = Table("users", db.metadata, autoload_with=db.engine)

        # Use SQLAlchemy operators (select / where / like) with bind parameters instead of text()
        stmt = (
            select(users.c.id, users.c.name, users.c.email)
            .where(users.c[column].like(bindparam("term")))
            .limit(bindparam("limit"))
        )

        # Execute the constructed statement with the params mapping to bind values safely.
        # Security: using SQLAlchemy Core select() with bind parameters avoids SQL injection (CWE-89).
        search_query = db.session.execute(stmt, params)

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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
