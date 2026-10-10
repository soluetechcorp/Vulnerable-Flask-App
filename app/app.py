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
    str_query = f"SELECT id, name, email FROM users WHERE {{column}} LIKE :term LIMIT :limit"

    # Prepare parameters using a dictionary; use parameterized execution below.
    params = {"term": f"%{term}%", "limit": limit}

    try:
        # Safely substitute the whitelisted column placeholder into the SQL string.
        # Security: only the validated whitelist column name is inserted into the SQL text
        # to prevent SQL injection. User data remains bound via parameters.
        safe_query = str_query.replace("{column}", column)
        search_query = db.session.execute(text(safe_query), params)

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

    except Exception:
        # Do not log exception details or sensitive inputs; log a generic message only.
        # Security: avoid writing stack traces or sensitive params to logs (CWE-532).
        logger.error("Database search failed")
        return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    # Only for local development. In production, use a WSGI server and bind via configuration.
    # Security: bind to localhost by default to avoid exposing development server (CWE-668).
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))
