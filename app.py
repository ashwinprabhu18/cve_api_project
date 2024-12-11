from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
import psycopg2
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database connection details
DB_NAME = "cve_data"
DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_HOST = "localhost"
DB_PORT = "5432"


def get_db_connection():
    """Establish a connection to the PostgreSQL database."""
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )


@app.route("/")
def root():
    """Redirect root to /cves."""
    return redirect("/cves/list", code=302)


@app.route("/cves/list", methods=["GET"])
def get_cves():
    """Fetch CVEs with pagination and optional filters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve query parameters
    cve_id = request.args.get("cve_id")  # Filter by CVE ID
    year = request.args.get("year")  # Filter by year
    score = request.args.get("score")  # Filter by CVSS score
    days = request.args.get("days")  # Filter by last modified in N days
    limit = int(request.args.get("limit", 10))  # Default: 10 records per page
    offset = int(request.args.get("offset", 0))  # Default: start from the first record

    query = """
        SELECT cve_id, source_identifier, published, last_modified, status, 
               description, cvss_v2_score, cvss_v2_vector, cvss_v2_severity,
               cvss_v31_score, cvss_v31_vector, cvss_v31_severity
        FROM cve
        WHERE 1 = 1
    """
    params = []

    # Apply filters based on query parameters
    if cve_id:
        query += " AND cve_id = %s"
        params.append(cve_id)

    if year:
        query += " AND EXTRACT(YEAR FROM published) = %s"
        params.append(year)

    if score:
        query += """
            AND (
                cvss_v2_score >= %s OR cvss_v31_score >= %s
            )
        """
        params.append(score)
        params.append(score)

    if days:
        n_days_ago = datetime.utcnow() - timedelta(days=int(days))
        query += " AND last_modified >= %s"
        params.append(n_days_ago)

    # Add pagination
    query += " ORDER BY last_modified DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    cursor.execute(query, params)
    results = cursor.fetchall()

    # Format the results as a list of dictionaries
    cves = [
        {
            "cve_id": row[0],
            "source_identifier": row[1],
            "published": row[2],
            "last_modified": row[3],
            "status": row[4],
            "description": row[5],
            "cvss_v2_score": row[6],
            "cvss_v2_vector": row[7],
            "cvss_v2_severity": row[8],
            "cvss_v31_score": row[9],
            "cvss_v31_vector": row[10],
            "cvss_v31_severity": row[11],
        }
        for row in results
    ]

    # Get total count for filtered results (same filters as above)
    count_query = """
        SELECT COUNT(*) FROM cve
        WHERE 1 = 1
    """
    count_params = []

    if cve_id:
        count_query += " AND cve_id = %s"
        count_params.append(cve_id)

    if year:
        count_query += " AND EXTRACT(YEAR FROM published) = %s"
        count_params.append(year)

    if score:
        count_query += """
            AND (
                cvss_v2_score >= %s OR cvss_v31_score >= %s
            )
        """
        count_params.append(score)
        count_params.append(score)

    if days:
        n_days_ago = datetime.utcnow() - timedelta(days=int(days))
        count_query += " AND last_modified >= %s"
        count_params.append(n_days_ago)

    cursor.execute(count_query, count_params)
    total_count = cursor.fetchone()[0]

    conn.close()

    return jsonify(
        {"data": cves, "total": total_count, "limit": limit, "offset": offset}
    )


if __name__ == "__main__":
    app.run(debug=True)
