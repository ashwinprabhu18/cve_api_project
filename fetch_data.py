import requests
import json
import os

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = "cve_data"
CHUNK_SIZE = 2000  # Max allowed by API

os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_total_records():
    response = requests.get(API_URL, params={"startIndex": 0, "resultsPerPage": 1})
    if response.status_code == 200:
        data = response.json()
        return data.get("totalResults", 0)
    else:
        raise Exception(f"Error: {response.status_code} - {response.text}")


def fetch_data():
    total_records = get_total_records()
    start_index = 0

    while start_index < total_records:
        params = {"startIndex": start_index, "resultsPerPage": CHUNK_SIZE}
        response = requests.get(API_URL, params=params)
        response.raise_for_status()

        data = response.json()
        file_name = f"{OUTPUT_DIR}/cve_{start_index}.json"
        with open(file_name, "w") as f:
            json.dump(data, f, indent=4)

        start_index += CHUNK_SIZE


if __name__ == "__main__":
    fetch_data()
