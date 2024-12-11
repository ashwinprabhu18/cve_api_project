import psycopg2
import json
import os

# Database connection details
DB_NAME = "cve_data"
DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_HOST = "localhost"
DB_PORT = "5432"
DATA_DIR = "cve_data"  # Folder where your JSON files are stored


def create_connection():
    """Establish a connection to the PostgreSQL database."""
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )


def load_json_files():
    """Load JSON data into PostgreSQL."""
    conn = create_connection()
    cursor = conn.cursor()

    for file_name in sorted(os.listdir(DATA_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(DATA_DIR, file_name)
            print(f"Processing {file_path}...")
            with open(file_path, "r") as file:
                data = json.load(file)

                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    source_identifier = cve.get("sourceIdentifier", None)
                    published_date = cve.get("published", None)
                    last_modified_date = cve.get("lastModified", None)
                    status = cve.get("vulnStatus", None)

                    # Description (first available in English)
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d.get("value") for d in descriptions if d.get("lang") == "en"),
                        "",
                    )

                    # Extract CVSS v2 metrics
                    cvss_v2 = (
                        cve.get("metrics", {})
                        .get("cvssMetricV2", [{}])[0]
                        .get("cvssData", {})
                    )
                    cvss_v2_score = cvss_v2.get("baseScore")
                    cvss_v2_vector = cvss_v2.get("vectorString")
                    cvss_v2_severity = (
                        cve.get("metrics", {})
                        .get("cvssMetricV2", [{}])[0]
                        .get("baseSeverity")
                    )

                    # Extract CVSS v3.1 metrics
                    cvss_v31 = (
                        cve.get("metrics", {})
                        .get("cvssMetricV31", [{}])[0]
                        .get("cvssData", {})
                    )
                    cvss_v31_score = cvss_v31.get("baseScore")
                    cvss_v31_vector = cvss_v31.get("vectorString")
                    cvss_v31_severity = cvss_v31.get("baseSeverity")

                    # Insert into database
                    cursor.execute(
                        """
                        INSERT INTO cve (
                            cve_id, source_identifier, published, last_modified, status, 
                            description, cvss_v2_score, cvss_v2_vector, cvss_v2_severity,
                            cvss_v31_score, cvss_v31_vector, cvss_v31_severity
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cve_id) DO NOTHING;
                        """,
                        (
                            cve_id,
                            source_identifier,
                            published_date,
                            last_modified_date,
                            status,
                            description,
                            cvss_v2_score,
                            cvss_v2_vector,
                            cvss_v2_severity,
                            cvss_v31_score,
                            cvss_v31_vector,
                            cvss_v31_severity,
                        ),
                    )

    conn.commit()
    cursor.close()
    conn.close()
    print("Data successfully loaded.")


if __name__ == "__main__":
    load_json_files()
