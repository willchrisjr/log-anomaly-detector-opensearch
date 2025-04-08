"""
Detects anomalies in SSH log data stored in OpenSearch.

Specifically, this script queries an OpenSearch index for multiple failed
SSH login attempts originating from the same IP address within a defined
time window. It prints basic alerts to the console if the failure count
for an IP exceeds a set threshold.
"""
"""
Detects anomalies in SSH log data stored in OpenSearch.

Specifically, this script queries an OpenSearch index for multiple failed
SSH login attempts originating from the same IP address within a defined
time window. It dispatches alerts via configured methods (log file, webhook)
if the failure count for an IP exceeds a set threshold.
"""
import re
import datetime
import logging
import sys
import os
import json
import time # For sleep in main loop
import signal # For graceful shutdown
import requests # For sending webhooks
from opensearchpy import OpenSearch, RequestsHttpConnection
from apscheduler.schedulers.blocking import BlockingScheduler 
from .config_loader import load_config # Use relative import

# Setup basic logging for script operation messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration Loading ---
config = load_config()
if not config:
    logging.error("Failed to load configuration. Exiting.")
    sys.exit(1)

# --- OpenSearch Settings ---
try:
    OPENSEARCH_HOST = config['opensearch']['host']
    OPENSEARCH_PORT = config['opensearch']['port']
    OPENSEARCH_INDEX_NAME = config['opensearch']['index_name']
    # Optional auth - add later if needed
except KeyError as e:
    logging.error(f"Missing required opensearch configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Detection Settings ---
try:
    DETECTION_RULE = config['detection']['failed_login_rule']
    TIME_WINDOW_MINUTES = DETECTION_RULE['time_window_minutes']
    FAILURE_THRESHOLD = DETECTION_RULE['failure_threshold']
except KeyError as e:
    logging.error(f"Missing required detection configuration key: {e}. Exiting.")
    sys.exit(1)

# --- High 404 Rule Settings ---
try:
    HIGH_404_RULE = config['detection'].get('high_404_rule', {}) # Use .get for optional rule
    HIGH_404_ENABLED = HIGH_404_RULE.get('enabled', False)
    HIGH_404_TIME_WINDOW = HIGH_404_RULE.get('time_window_minutes', 60)
    HIGH_404_THRESHOLD = HIGH_404_RULE.get('threshold', 10)
except Exception as e: # Catch broader errors during config access
    logging.warning(f"Issue reading high_404_rule configuration: {e}. Rule will be disabled.")
    HIGH_404_ENABLED = False


# --- Alerting Settings ---
try:
    ALERT_CONFIG = config['alerting']
    LOG_ALERT_ENABLED = ALERT_CONFIG.get('log_file', {}).get('enabled', False)
    LOG_ALERT_PATH = ALERT_CONFIG.get('log_file', {}).get('path', 'logs/alerts.log')
    WEBHOOK_ALERT_ENABLED = ALERT_CONFIG.get('generic_webhook', {}).get('enabled', False)
    WEBHOOK_URL = ALERT_CONFIG.get('generic_webhook', {}).get('url')
    # WEBHOOK_HEADERS = ALERT_CONFIG.get('generic_webhook', {}).get('headers', {}) # Optional
except KeyError as e:
    logging.error(f"Missing required alerting configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Scheduler Settings ---
try:
    SCHEDULER_INTERVAL_MINUTES = config['scheduler']['interval_minutes']
except KeyError as e:
    logging.error(f"Missing required scheduler configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Alert Logger Setup ---
alert_logger = None
if LOG_ALERT_ENABLED:
    try:
        # Ensure logs directory exists
        log_dir = os.path.dirname(LOG_ALERT_PATH)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            logging.info(f"Created log directory: {log_dir}")

        alert_logger = logging.getLogger('AlertLogger')
        alert_logger.setLevel(logging.WARNING) # Log alerts as warnings or higher
        # Prevent alert logs from propagating to the root logger (which prints to console)
        alert_logger.propagate = False 
        # Use a simple format for the alert file
        formatter = logging.Formatter('%(asctime)s - ALERT - %(message)s') 
        file_handler = logging.FileHandler(LOG_ALERT_PATH)
        file_handler.setFormatter(formatter)
        alert_logger.addHandler(file_handler)
        logging.info(f"Alert logging enabled. Alerts will be written to: {LOG_ALERT_PATH}")
    except Exception as e:
        logging.error(f"Failed to set up alert file logger at {LOG_ALERT_PATH}: {e}")
        alert_logger = None # Disable if setup fails


# Regex to extract IP address from failed password messages
# Example: Failed password for user1 from 192.168.1.10 port 54322 ssh2
# Example: Failed password for invalid user admin from 10.0.0.5 port 12345 ssh2
# Unused code removed: ip_pattern regex

def create_opensearch_client():
    """
    Creates and returns an OpenSearch client instance.

    Connects to the configured OpenSearch host and port.
    Verifies the connection before returning the client.

    Returns:
        OpenSearch: An instance of the OpenSearch client.
    
    Raises:
        ValueError: If the connection to OpenSearch fails.
    """
    # TODO: Add support for SSL and authentication based on config
    client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}], # Use constants derived from config
        http_conn_options={'timeout': 10},
        use_ssl=False, # Replace with config value if added
        verify_certs=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection
    )
    if not client.ping():
        logging.error("Connection to OpenSearch failed")
        raise ValueError("Connection to OpenSearch failed")
    logging.info("Successfully connected to OpenSearch.")
    return client

# --- Alerting Functions ---

def send_webhook_alert(alert_type, alert_details):
    """Sends alert data (including type) to the configured generic webhook."""
    if not WEBHOOK_URL:
        logging.warning("Webhook URL is not configured or webhook alerting is disabled.")
        return

    headers = {'Content-Type': 'application/json'}
    # TODO: Add custom headers from config if needed
    
    # Structure the alert data as JSON payload
    payload = {
        "alert_type": alert_type, # Use the passed alert type
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "details": alert_details # Pass the list of suspicious items
    }
    
    try:
        response = requests.post(WEBHOOK_URL, headers=headers, json=payload, timeout=15)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        logging.info(f"Successfully sent alert to webhook: {WEBHOOK_URL}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending alert to webhook {WEBHOOK_URL}: {e}")

def dispatch_alert(alert_type, alert_details_list):
    """Dispatches alerts based on configuration (log file, webhook)."""
    if not alert_details_list: return # No alerts to dispatch

    count = len(alert_details_list)
    # Customize summary based on type
    if alert_type == "failed_logins":
        alert_summary = f"[{alert_type.upper()}] Found {count} IPs meeting failed login threshold ({FAILURE_THRESHOLD})."
    elif alert_type == "high_404s":
         alert_summary = f"[{alert_type.upper()}] Found {count} IPs meeting high 404 threshold ({HIGH_404_THRESHOLD})."
    else:
         alert_summary = f"[{alert_type.upper()}] Found {count} suspicious entries."

    # Log to file if enabled
    if alert_logger:
        alert_logger.warning(alert_summary)
        for item in alert_details_list:
             # Log different fields based on alert type
             if alert_type == "failed_logins":
                 alert_logger.warning(f"  IP: {item.get('ip', 'N/A')}, Failures: {item.get('count', 'N/A')}")
             elif alert_type == "high_404s":
                  alert_logger.warning(f"  Client IP: {item.get('client_ip', 'N/A')}, 404 Count: {item.get('count', 'N/A')}")
             else:
                 alert_logger.warning(f"  Item: {item}") # Fallback
    
    # Send to webhook if enabled
    if WEBHOOK_ALERT_ENABLED:
        send_webhook_alert(alert_type, alert_details_list)


# --- Detection Logic ---

def detect_failed_logins(client, index_name, time_window_minutes, failure_threshold):
    """
    Queries OpenSearch for multiple failed logins from the same IP within a specified time window.

    Uses an aggregation query to count failed logins per IP address and filters
    based on the failure threshold. Prints alerts for suspicious IPs found.

    Args:
        client (OpenSearch): The OpenSearch client instance.
        index_name (str): The name of the index to query.
        time_window_minutes (int): The lookback period in minutes.
        failure_threshold (int): The minimum number of failures to trigger an alert.
    """
    logging.info(f"Searching index '{index_name}' for IPs with >= {failure_threshold} failed logins in the last {time_window_minutes} minutes...")
    
    # Calculate the start time for the query window
    now = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware UTC time
    start_time = now - datetime.timedelta(minutes=time_window_minutes)
    start_time_iso = start_time.isoformat() # isoformat() on timezone-aware object includes offset

    # Define the OpenSearch query
    # 1. Filter for "Failed password" messages within the time window
    # 2. Aggregate on the ip_address field
    # 3. Use a bucket_selector sub-aggregation to filter for IPs meeting the threshold
    query = {
        "size": 0,  # We only care about aggregations
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"message": "Failed password"}}, # Filter for failed logins
                    {"range": {"@timestamp": {"gte": start_time_iso}}} # Filter by time window
                ]
            }
        },
        "aggs": {
            "failed_logins_by_ip": {
                "terms": {
                    "field": "ip_address", # Aggregate on the keyword IP field
                    "size": 100 # Limit number of IPs returned - TODO: Make configurable?
                    }, 
                "aggs": {
                    "min_failure_count": {
                        "bucket_selector": {
                            "buckets_path": {"count": "_count"}, # Use the doc count for each IP bucket
                            "script": f"params.count >= {failure_threshold}"
                        }
                    }
                }
            }
        }
    }

    try:
        # Execute the search
        response = client.search(index=index_name, body=query)
        
        # Process the aggregation results
        suspicious_ips = []
        # Safely access nested dictionary keys
        aggregations = response.get('aggregations', {})
        failed_logins_agg = aggregations.get('failed_logins_by_ip', {})
        buckets = failed_logins_agg.get('buckets', [])
        
        logging.info(f"OpenSearch query returned {len(buckets)} IPs meeting the threshold.")

        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip: # Should always have an IP here now
                 suspicious_ips.append({"ip": ip, "count": count})

        # Dispatch alerts if any suspicious IPs were found
        if suspicious_ips:
             dispatch_alert(suspicious_ips)
        else:
            logging.info("No suspicious IPs found meeting the threshold.")

    except Exception as e:
        logging.error(f"Error querying or processing results from OpenSearch for failed logins: {e}", exc_info=True)


def detect_high_404s(client, index_name, time_window_minutes, threshold):
    """
    Queries OpenSearch for clients generating excessive 404 errors within a specified time window.
    """
    logging.info(f"Searching index '{index_name}' for IPs with >= {threshold} 404 errors in the last {time_window_minutes} minutes...")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = now - datetime.timedelta(minutes=time_window_minutes)
    start_time_iso = start_time.isoformat()

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"log_type": "web"}}, # Filter for web logs
                    {"term": {"status_code": 404}}, # Filter for 404 status
                    {"range": {"@timestamp": {"gte": start_time_iso}}}
                ]
            }
        },
        "aggs": {
            "high_404s_by_ip": {
                "terms": {"field": "client_ip", "size": 100}, # Aggregate on client_ip
                "aggs": {
                    "min_404_count": {
                        "bucket_selector": {
                            "buckets_path": {"count": "_count"},
                            "script": f"params.count >= {threshold}"
                        }
                    }
                }
            }
        }
    }

    try:
        response = client.search(index=index_name, body=query)
        suspicious_ips = []
        aggregations = response.get('aggregations', {})
        high_404s_agg = aggregations.get('high_404s_by_ip', {})
        buckets = high_404s_agg.get('buckets', [])
        
        logging.info(f"High 404s query returned {len(buckets)} IPs meeting the threshold.")

        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip:
                 suspicious_ips.append({"client_ip": ip, "count": count}) # Use client_ip key

        if suspicious_ips:
             dispatch_alert("high_404s", suspicious_ips) # Dispatch with specific type
        else:
            logging.info("No IPs found meeting the high 404 threshold.")

    except Exception as e:
        logging.error(f"Error querying or processing results from OpenSearch for high 404s: {e}", exc_info=True)


# --- Job Function ---

if __name__ == "__main__":
    logging.info("Starting anomaly detection script...")
    try:
        # Client uses constants derived from config
        os_client = create_opensearch_client() 
        # Check if index exists before querying
        # Use index name from config
        if os_client.indices.exists(index=OPENSEARCH_INDEX_NAME): 
            # Pass config values to detection function
            detect_failed_logins(os_client, OPENSEARCH_INDEX_NAME, TIME_WINDOW_MINUTES, FAILURE_THRESHOLD) 
        else:
            logging.error(f"Index '{OPENSEARCH_INDEX_NAME}' does not exist. Run the ingestion script first.")
            
    except ValueError as ve: # Catch connection errors from create_opensearch_client
        logging.error(f"Connection error: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during anomaly detection: {e}", exc_info=True)

# --- Job Functions ---
# Renamed for clarity
def run_failed_login_detection_job():
    """Connects to OpenSearch and runs the failed login detection logic."""
    logging.info("Running scheduled failed login detection job...")
    try:
        os_client = create_opensearch_client() 
        if os_client.indices.exists(index=OPENSEARCH_INDEX_NAME): 
            detect_failed_logins(os_client, OPENSEARCH_INDEX_NAME, TIME_WINDOW_MINUTES, FAILURE_THRESHOLD) 
        else:
            logging.error(f"Index '{OPENSEARCH_INDEX_NAME}' does not exist. Cannot run failed login detection.")
            
    except ValueError as ve: # Catch connection errors
        logging.error(f"Connection error during failed login detection job: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during failed login detection job: {e}", exc_info=True)
    logging.info("Scheduled failed login detection job finished.")

def run_high_404_detection_job():
    """Connects to OpenSearch and runs the high 404 detection logic."""
    logging.info("Running scheduled high 404 detection job...")
    try:
        os_client = create_opensearch_client() 
        if os_client.indices.exists(index=OPENSEARCH_INDEX_NAME): 
            detect_high_404s(os_client, OPENSEARCH_INDEX_NAME, HIGH_404_TIME_WINDOW, HIGH_404_THRESHOLD) 
        else:
            logging.error(f"Index '{OPENSEARCH_INDEX_NAME}' does not exist. Cannot run high 404 detection.")
            
    except ValueError as ve: # Catch connection errors
        logging.error(f"Connection error during high 404 detection job: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during high 404 detection job: {e}", exc_info=True)
    logging.info("Scheduled high 404 detection job finished.")


# --- Main Scheduler Execution ---

# Flag to control the main loop for graceful shutdown
running = True

def shutdown_handler(signum, frame):
    """Handles signals like SIGINT (Ctrl+C) for graceful shutdown."""
    global running
    logging.info(f"Received signal {signum}. Shutting down scheduler...")
    running = False
    # The BlockingScheduler should exit automatically when the main thread finishes,
    # but we can also explicitly shut it down if needed (requires scheduler instance).
    # If using BackgroundScheduler, you'd call scheduler.shutdown() here.

# Register signal handlers
signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


if __name__ == "__main__":
    logging.info(f"Starting anomaly detection scheduler...")
    
    # Initialize the scheduler
    scheduler = BlockingScheduler(timezone="UTC") 

    # --- Schedule Failed Login Detector ---
    # Check if the rule is enabled in config (assuming it is for now, add check if needed)
    # failed_login_enabled = config['detection'].get('failed_login_rule', {}).get('enabled', False) # Example check
    # if failed_login_enabled: # Add this check if enabling/disabling rules is desired
    logging.info(f"Scheduling failed login detection every {SCHEDULER_INTERVAL_MINUTES} minutes.")
    # Run once immediately
    run_failed_login_detection_job() 
    # Schedule subsequent runs
    scheduler.add_job(
        run_failed_login_detection_job, 
        'interval', 
        minutes=SCHEDULER_INTERVAL_MINUTES, # Use the main interval for now
        id='failed_login_detector', 
        replace_existing=True 
    )
    # else:
    #    logging.info("Failed login detection rule is disabled in config.")

    # --- Schedule High 404 Detector ---
    if HIGH_404_ENABLED:
        logging.info(f"Scheduling high 404 detection every {SCHEDULER_INTERVAL_MINUTES} minutes.") # Using same interval for now
         # Run once immediately
        run_high_404_detection_job()
        # Schedule subsequent runs
        scheduler.add_job(
            run_high_404_detection_job,
            'interval',
            minutes=SCHEDULER_INTERVAL_MINUTES, # TODO: Make interval configurable per rule?
            id='high_404_detector',
            replace_existing=True
        )
    else:
         logging.info("High 404 detection rule is disabled in config.")

    
    if not scheduler.get_jobs():
         logging.warning("No detection jobs were scheduled. Check configuration. Exiting.")
         sys.exit(0)

    logging.info("Scheduler starting with configured jobs. Press Ctrl+C to exit.")

    try:
        # Start the scheduler (this blocks the main thread)
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logging.info("Scheduler stopped via interrupt.")
    except Exception as e:
        logging.error(f"Scheduler failed: {e}", exc_info=True)
    finally:
        # Optional cleanup if scheduler needs explicit shutdown
        if scheduler.running:
             scheduler.shutdown()
        logging.info("Anomaly detection scheduler finished.")
