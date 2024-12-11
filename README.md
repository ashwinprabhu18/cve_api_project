# CVE Vulnerability Dashboard

## Overview

The CVE Vulnerability Dashboard is a web-based application designed to help users view and filter CVE (Common Vulnerabilities and Exposures) records. It provides a clean and interactive interface to search, filter, and display CVE data, allowing users to track vulnerabilities based on various attributes such as CVE ID, year, CVSS score, and modification date. Additionally, users can view detailed CVE information through a modal interface.

### Features:

- **Filter CVE records**: Filter by CVE ID, publication year, CVSS score, and number of days since last modification.
- **Pagination**: Navigate large datasets with the ability to view 10, 50, or 100 records per page.
- **Detailed View**: View detailed information about a CVE in a modal, including CVSS scores, vulnerability description, affected software, and more.

## Prerequisites

This project uses basic web technologies (HTML, CSS, JavaScript) and requires no server-side dependencies or databases. It can be run locally using just a browser.

- A modern web browser (e.g., Google Chrome, Mozilla Firefox) to view the dashboard.
- Local server (optional) if you want to run a backend for dynamic CVE data fetching.


## Challenges

- **CORS**: Since the app.py runs the flask in 5000 port number and html page runs in a different port, I couldn't connect those two until I used CORS
- **Filters**: In the frontend side of things I had to figure out how to work out the design and the filter system which took a lot of time.
- **Total Records**: To get the total records from the nvd api was also really challenging because the data is huge and getting through timeouts every now and then while the fetch_data.py was very challenging and time consuming as well