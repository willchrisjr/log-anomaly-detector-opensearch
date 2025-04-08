s# End-to-End Security Automation & Incident Response Framework (Proof of Concept)

This project is a proof-of-concept implementation of a framework designed to ingest security logs, detect anomalies, and trigger basic alerts. It currently focuses on ingesting mock SSH logs into a local OpenSearch instance and detecting multiple failed login attempts from the same IP address.

## Project Structure

```
.
├── docker-compose.yml    # Docker configuration for OpenSearch & Dashboards
├── requirements.txt      # Python dependencies
├── data/                 # Sample data files
│   └── mock_ssh.log      # Mock SSH log data
├── src/                  # Source code
│   ├── ingest_logs.py    # Script to ingest logs (SSH, Apache Web) into OpenSearch
│   ├── detect_anomalies.py # Script to detect anomalies (failed logins, high 404s) and dispatch alerts (runs scheduled)
│   ├── config_loader.py  # Utility to load YAML configuration
│   └── api.py            # Flask API server to serve alerts and raw logs
├── frontend/             # React frontend application (Vite build tool)
│   ├── public/           # Static assets
│   ├── src/              # React source code (components, etc.)
│   │   ├── App.jsx       # Main application component
│   │   └── App.css       # Main application styles
│   ├── index.html        # Entry point HTML
│   ├── package.json      # Frontend dependencies and scripts
│   └── vite.config.js    # Vite configuration (if using Vite)
├── config/               # Configuration files
│   └── config.yaml       # Main configuration file (YAML)
├── logs/                 # Log output from scripts
│   └── alerts.log        # Log file specifically for dispatched alerts
└── scripts/              # (Placeholder) Utility or helper scripts
```

## Prerequisites

*   **Docker & Docker Compose:** Required to run the local OpenSearch instance. Install Docker Desktop from [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/).
*   **Python 3:** Required to run the backend scripts. Ensure `python3` and `pip3` (or `pip`) are available in your PATH.
*   **Node.js & npm:** Required for the React frontend development and build process. Install from [https://nodejs.org/](https://nodejs.org/).

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
    *Note: It is highly recommended to use a Python virtual environment (`python3 -m venv venv`, `source venv/bin/activate` or `venv\Scripts\activate`, then `pip install -r requirements.txt`).*

4.  **Install Frontend Dependencies:**
    Navigate into the frontend directory and install its dependencies:
    ```bash
    cd frontend
    npm install
    cd .. 
    ```

## Usage

1.  **Ingest Logs:**
    Run the ingestion script, optionally specifying the log file and type. By default, it ingests `data/mock_access.log` as 'web'.
    ```bash
    # Ingest web logs (default)
    venv/bin/python3 src/ingest_logs.py 
    
    # Ingest SSH logs (specify file and type)
    # venv/bin/python3 src/ingest_logs.py data/mock_ssh.log ssh 
    ```
    *Note: The script creates the index with a combined mapping. If you re-run ingestion for a different log type, ensure the index exists or delete it first if mappings conflict.*

2.  **Run Anomaly Detection Scheduler:**
    Run the detection script. It will run enabled detection rules (failed logins, high 404s) immediately and then schedule them periodically.
    ```bash
    # This script now runs continuously using APScheduler
    python3 src/detect_anomalies.py 
    ```
    to run periodically based on the `scheduler.interval_minutes` setting in 
    `config/config.yaml`. Alerts are dispatched based on the `alerting` 
    configuration (e.g., written to `logs/alerts.log`). Press Ctrl+C to stop 
    the scheduler. *(Note: Use `venv/bin/python3 src/detect_anomalies.py` if using a virtual environment).*

3.  **Run the API Server:**
    In a separate terminal, start the Flask API server (using the venv):
    ```bash
    venv/bin/python3 src/api.py
    ```
    The API will be available at `http://localhost:5001`. It serves data from the `security-alerts-details` index and raw logs from the `ssh-logs` index.

4.  **Run the Frontend Development Server:**
    In another separate terminal, navigate to the frontend directory and start the Vite development server:
    ```bash
    cd frontend
    npm run dev
    ```
    This will typically open the application in your browser automatically (usually at `http://localhost:5173` or similar - check the terminal output). This development server provides hot reloading.

## Testing

Basic unit tests for the log parsing logic are located in the `tests/` directory and can be run using `pytest`.

1.  **Ensure Dependencies are Installed:** Make sure you have run `venv/bin/pip3 install -r requirements.txt`.
2.  **Run Tests:** From the project root directory, run:
    ```bash
    PYTHONPATH=. venv/bin/pytest
    ```
    *(The `PYTHONPATH=.` part ensures that Python can find the `src` module).*

## Components

*   **`docker-compose.yml`:** Defines the `opensearch-node1` and `opensearch-dashboards` services for local development. Security is disabled for ease of use (do not use this configuration in production).
*   **`data/mock_ssh.log`:** Contains sample SSH log lines, including successful logins, failed logins, and disconnects.
*   **`src/ingest_logs.py`:** Parses and ingests SSH or Apache web logs based on arguments. Creates index with combined mapping.
*   **`src/config_loader.py`:** Utility to load `config.yaml`.
*   **`src/detect_anomalies.py`:** Loads config, connects to OpenSearch, contains detection logic for failed logins and high 404s, dispatches alerts (log file, webhook, alert index), uses APScheduler to run enabled detection jobs periodically.
*   **`src/api.py`:** Flask API server providing `/api/alerts` (queries the alert index) and `/api/raw_logs` (queries the log index) endpoints. Includes `/health` check.
*   **`frontend/`:** React frontend application built with Vite. Displays alerts and recent raw logs fetched from the API.
*   **`config/config.yaml`:** Central configuration for OpenSearch connection, index names, detection rules (with enable flags), alerting methods, and scheduler interval.
*   **`logs/alerts.log`:** Default file where alerts are logged when file logging is enabled.

## Future Enhancements

*   **More Log Sources & Parsers:** Add support for other log types (e.g., firewall logs, application logs) and improve parsing robustness.
*   **More Detection Rules:** Implement detection logic for different types of anomalies (e.g., unusual user agent, port scanning).
*   **Real-time Ingestion:** Modify ingestion to tail log files or listen to log streams (e.g., Syslog, Beats).
*   **API Enhancements:** Add filtering/searching/pagination capabilities to the API endpoints. Add endpoints for managing rules or configuration.
*   **Frontend Enhancements:** Add filtering controls, pagination, better visualization of alert details, potentially charts.
*   **Webhook Alert Testing:** Configure and test the generic webhook alerting with a service like webhook.site.
*   **Specific Alert Integrations:** Add dedicated functions/modules for specific services like Slack, Teams, PagerDuty.
*   **Incident Logging:** Integrate with ticketing systems (e.g., JIRA, ServiceNow) to automatically create incident tickets.
*   **Improved Error Handling & Logging:** Enhance robustness and provide more detailed, structured logging across all components.
*   **More Unit & Integration Tests:** Expand test coverage for detection logic, API endpoints, configuration loading, etc.
*   **Production Deployment:** Containerize the Python applications (scheduler, API) for deployment (e.g., using Docker beyond the local OpenSearch setup).
*   **Security:** Enable and configure OpenSearch security features; secure the API endpoints.
