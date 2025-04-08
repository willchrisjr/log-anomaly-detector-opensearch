# End-to-End Security Automation & Incident Response Framework (Proof of Concept)

This project is a proof-of-concept implementation of a framework designed to ingest security logs, detect anomalies, and trigger basic alerts. It currently focuses on ingesting mock SSH logs into a local OpenSearch instance and detecting multiple failed login attempts from the same IP address.

## Project Structure

```
.
├── docker-compose.yml    # Docker configuration for OpenSearch & Dashboards
├── requirements.txt      # Python dependencies
├── data/                 # Sample data files
│   └── mock_ssh.log      # Mock SSH log data
├── src/                  # Source code
│   ├── ingest_logs.py    # Script to ingest logs into OpenSearch
│   └── detect_anomalies.py # Script to detect failed login anomalies
├── config/               # (Placeholder) Configuration files
├── logs/                 # (Placeholder) Log output from scripts
└── scripts/              # (Placeholder) Utility or helper scripts
```

## Prerequisites

*   **Docker & Docker Compose:** Required to run the local OpenSearch instance. Install Docker Desktop from [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/).
*   **Python 3:** Required to run the ingestion and detection scripts. Ensure `python3` and `pip3` (or `pip`) are available in your PATH.

## Setup

1.  **Clone the Repository (if applicable):**
    ```bash
    # git clone <repository-url>
    # cd opensearchproject 
    ```

2.  **Start OpenSearch:**
    Open a terminal in the project root directory and run:
    ```bash
    docker compose up -d
    ```
    This will download the necessary images (if not already present) and start the OpenSearch and OpenSearch Dashboards containers in the background.
    *   OpenSearch API will be available at `http://localhost:9200`
    *   OpenSearch Dashboards UI will be available at `http://localhost:5601`

3.  **Install Python Dependencies:**
    ```bash
    pip3 install -r requirements.txt 
    # or use 'pip' if 'pip3' is not available
    # pip install -r requirements.txt
    ```

## Usage

1.  **Ingest Logs:**
    Run the ingestion script to parse the mock data and send it to OpenSearch. This script will also create the `ssh-logs` index if it doesn't exist.
    ```bash
    python3 src/ingest_logs.py
    ```
    *Note: If you run this multiple times, it will add duplicate log entries unless you delete the index first.*

2.  **Detect Anomalies:**
    Run the detection script to query OpenSearch for the defined anomaly (>= 3 failed logins from the same IP in the last 24 hours).
    ```bash
    python3 src/detect_anomalies.py
    ```
    The script will print any detected suspicious IPs as "ALERT" messages to the console.

## Components

*   **`docker-compose.yml`:** Defines the `opensearch-node1` and `opensearch-dashboards` services for local development. Security is disabled for ease of use (do not use this configuration in production).
*   **`data/mock_ssh.log`:** Contains sample SSH log lines, including successful logins, failed logins, and disconnects.
*   **`src/ingest_logs.py`:**
    *   Connects to OpenSearch.
    *   Parses log lines using regex.
    *   Extracts timestamp, hostname, process, PID, message, and source IP address.
    *   Creates the `ssh-logs` index with a basic mapping if it doesn't exist.
    *   Uses the OpenSearch bulk API to index log entries efficiently.
*   **`src/detect_anomalies.py`:**
    *   Connects to OpenSearch.
    *   Queries the `ssh-logs` index for documents matching "Failed password" within a configurable time window (currently 24 hours for demo purposes).
    *   Uses OpenSearch aggregations to group failures by `ip_address`.
    *   Filters the results using a `bucket_selector` to find IPs meeting the failure threshold.
    *   Prints basic "ALERT" messages to the console for detected IPs.

## Future Enhancements

*   **More Log Sources:** Add parsers and ingestion logic for other log types (firewall, application, OS).
*   **Improved Parsing:** Use more robust parsing libraries or techniques instead of basic regex.
*   **Configuration Management:** Move settings (OpenSearch host, index names, thresholds) to configuration files (e.g., in the `config/` directory).
*   **Real-time Ingestion:** Modify ingestion to tail log files or listen to log streams (e.g., Syslog, Beats).
*   **Advanced Anomaly Detection:** Implement more sophisticated rules, statistical methods, or machine learning models for detection.
*   **Real Alerting:** Integrate with actual notification systems (Slack, Teams, PagerDuty) via APIs.
*   **Incident Logging:** Integrate with ticketing systems (JIRA, ServiceNow) to automatically create incident tickets.
*   **Error Handling & Logging:** Add more robust error handling and structured logging (e.g., to files in the `logs/` directory).
*   **Scheduling:** Use a scheduler (like `cron` or a Python library like `APScheduler`) to run the detection script periodically.
*   **Security:** Enable and configure OpenSearch security features for production use.
