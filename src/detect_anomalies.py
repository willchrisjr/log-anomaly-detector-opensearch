"""
Detects anomalies in log data stored in OpenSearch.

Supports multiple detection rules (failed logins, high 404s).
Queries OpenSearch based on configured rules, dispatches alerts 
(to log file, webhook, and/or a dedicated OpenSearch alert index), 
and runs detection jobs periodically via a scheduler.
"""
import re
import datetime
import logging
import sys
import os
import json
import time 
import signal 
import requests 
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers 
from apscheduler.schedulers.blocking import BlockingScheduler 
from config_loader import load_config # Use direct import (run with PYTHONPATH=.)

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
    OPENSEARCH_INDEX_NAME = config['opensearch']['index_name'] # Index for raw logs
    ALERT_INDEX_NAME = config['opensearch']['alert_index_name'] # Index for generated alerts
except KeyError as e:
    logging.error(f"Missing required opensearch configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Failed Login Rule Settings ---
try:
    FAILED_LOGIN_RULE = config['detection'].get('failed_login_rule', {})
    FAILED_LOGIN_ENABLED = FAILED_LOGIN_RULE.get('enabled', False)
    FAILED_LOGIN_TIME_WINDOW = FAILED_LOGIN_RULE.get('time_window_minutes', 60)
    FAILED_LOGIN_THRESHOLD = FAILED_LOGIN_RULE.get('failure_threshold', 5)
except Exception as e:
     logging.warning(f"Issue reading failed_login_rule configuration: {e}. Rule will be disabled.")
     FAILED_LOGIN_ENABLED = False

# --- High 404 Rule Settings ---
try:
    HIGH_404_RULE = config['detection'].get('high_404_rule', {}) 
    HIGH_404_ENABLED = HIGH_404_RULE.get('enabled', False)
    HIGH_404_TIME_WINDOW = HIGH_404_RULE.get('time_window_minutes', 60)
    HIGH_404_THRESHOLD = HIGH_404_RULE.get('threshold', 10)
except Exception as e: 
    logging.warning(f"Issue reading high_404_rule configuration: {e}. Rule will be disabled.")
    HIGH_404_ENABLED = False

# --- Alerting Settings ---
try:
    ALERT_CONFIG = config['alerting']
    LOG_ALERT_ENABLED = ALERT_CONFIG.get('log_file', {}).get('enabled', False)
    LOG_ALERT_PATH = ALERT_CONFIG.get('log_file', {}).get('path', 'logs/alerts.log')
    WEBHOOK_ALERT_ENABLED = ALERT_CONFIG.get('generic_webhook', {}).get('enabled', False)
    WEBHOOK_URL = ALERT_CONFIG.get('generic_webhook', {}).get('url')
    INDEX_ALERT_ENABLED = True # Always try to index alerts if possible
except KeyError as e:
    logging.error(f"Missing required alerting configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Scheduler Settings ---
try:
    SCHEDULER_INTERVAL_MINUTES = config['scheduler']['interval_minutes']
    # TODO: Add per-rule interval configuration later if needed
except KeyError as e:
    logging.error(f"Missing required scheduler configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Alert Logger Setup ---
alert_logger = None
if LOG_ALERT_ENABLED:
    try:
        log_dir = os.path.dirname(LOG_ALERT_PATH)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            logging.info(f"Created log directory: {log_dir}")
        alert_logger = logging.getLogger('AlertLogger')
        alert_logger.setLevel(logging.WARNING) 
        alert_logger.propagate = False 
        formatter = logging.Formatter('%(asctime)s - ALERT - %(message)s') 
        file_handler = logging.FileHandler(LOG_ALERT_PATH)
        file_handler.setFormatter(formatter)
        # Avoid adding handler multiple times if script restarts unexpectedly
        if not alert_logger.hasHandlers():
            alert_logger.addHandler(file_handler)
        logging.info(f"Alert logging enabled. Alerts will be written to: {LOG_ALERT_PATH}")
    except Exception as e:
        logging.error(f"Failed to set up alert file logger at {LOG_ALERT_PATH}: {e}")
        alert_logger = None 

# --- OpenSearch Client ---
def create_opensearch_client():
    """Creates and returns an OpenSearch client instance."""
    try:
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_conn_options={'timeout': 10},
            use_ssl=False, # TODO: Read from config
            verify_certs=False, # TODO: Read from config
            ssl_show_warn=False,
            connection_class=RequestsHttpConnection
        )
        if not client.ping(): raise ValueError("Connection failed")
        logging.debug("Successfully connected to OpenSearch.") # Changed to debug
        return client
    except Exception as e:
        logging.error(f"Failed to connect to OpenSearch: {e}")
        raise 

# --- Index Creation ---
def create_alert_index_if_not_exists(client, index):
    """Creates the alert index with mapping if it doesn't exist."""
    if not client.indices.exists(index=index):
        logging.info(f"Alert index '{index}' not found. Creating...")
        try:
            mapping = { # Mapping for the alert documents themselves
                "properties": {
                    "alert_timestamp": {"type": "date"}, 
                    "alert_type": {"type": "keyword"}, 
                    "details": { # Store details as nested objects
                        "type": "nested", 
                        "properties": {
                            # Potential fields from different alert types
                            "ip": {"type": "keyword"},
                            "client_ip": {"type": "keyword"},
                            "count": {"type": "integer"},
                            "hostname": {"type": "keyword"},
                            "process": {"type": "keyword"},
                            # Add other relevant summary fields if needed
                        }
                    },
                    "summary": {"type": "text", "index": False} # Store the summary message
                }
            }
            client.indices.create(index=index, body={'mappings': mapping})
            logging.info(f"Alert index '{index}' created successfully.")
        except Exception as e:
            logging.error(f"Error creating alert index '{index}': {e}")
            # Don't raise here, detection might still work, just won't index alerts
    else:
        logging.debug(f"Alert index '{index}' already exists.") # Changed to debug

# --- Alerting Functions ---

def send_webhook_alert(alert_type, alert_details_list, alert_summary):
    """Sends alert data (including type and summary) to the configured generic webhook."""
    if not WEBHOOK_URL:
        logging.warning("Webhook URL is not configured or webhook alerting is disabled.")
        return
    headers = {'Content-Type': 'application/json'}
    payload = {
        "alert_type": alert_type, 
        "summary": alert_summary, # Include summary
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "details": alert_details_list 
    }
    try:
        response = requests.post(WEBHOOK_URL, headers=headers, json=payload, timeout=15)
        response.raise_for_status() 
        logging.info(f"Successfully sent alert to webhook: {WEBHOOK_URL}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending alert to webhook {WEBHOOK_URL}: {e}")

def index_alert_to_opensearch(client, alert_type, alert_details_list, alert_summary):
    """Formats and indexes alert documents into the alert index."""
    if not client:
        logging.error("OpenSearch client not available for indexing alert.")
        return
    if not ALERT_INDEX_NAME:
         logging.error("Alert index name not configured.")
         return

    actions = []
    alert_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Create one document per alert summary
    doc = {
        "alert_timestamp": alert_ts,
        "alert_type": alert_type,
        "summary": alert_summary,
        "details": alert_details_list # Store the list of detail dicts as nested objects
    }
    actions.append({"_index": ALERT_INDEX_NAME, "_source": doc})

    if actions:
        try:
            success, errors = helpers.bulk(client, actions, chunk_size=100, request_timeout=60)
            if errors:
                logging.error(f"Errors encountered while indexing alerts: {errors[:5]}") 
            else:
                logging.info(f"Successfully indexed {success} alert document(s) to {ALERT_INDEX_NAME}.")
        except Exception as e:
            logging.error(f"Failed to index alerts to OpenSearch: {e}", exc_info=True)

def dispatch_alert(os_client, alert_type, alert_details_list):
    """Dispatches alerts based on configuration (log file, webhook, alert index)."""
    if not alert_details_list: return 

    count = len(alert_details_list)
    # Generate summary message
    if alert_type == "failed_logins":
        alert_summary = f"[{alert_type.upper()}] Found {count} IPs meeting failed login threshold ({FAILED_LOGIN_THRESHOLD})."
    elif alert_type == "high_404s":
         alert_summary = f"[{alert_type.upper()}] Found {count} IPs meeting high 404 threshold ({HIGH_404_THRESHOLD})."
    else:
         alert_summary = f"[{alert_type.upper()}] Found {count} suspicious entries."

    logging.warning(alert_summary) # Log summary to main console/log

    # Log details to dedicated alert log file if enabled
    if alert_logger:
        # alert_logger.warning(alert_summary) # Optionally log summary here too
        for item in alert_details_list:
             if alert_type == "failed_logins":
                 alert_logger.warning(f"  IP: {item.get('ip', 'N/A')}, Failures: {item.get('count', 'N/A')}")
             elif alert_type == "high_404s":
                  alert_logger.warning(f"  Client IP: {item.get('client_ip', 'N/A')}, 404 Count: {item.get('count', 'N/A')}")
             else:
                 alert_logger.warning(f"  Item: {item}") 
    
    # Send to webhook if enabled
    if WEBHOOK_ALERT_ENABLED:
        send_webhook_alert(alert_type, alert_details_list, alert_summary)
        
    # Index alert to OpenSearch if enabled (implicitly enabled if client is available)
    if INDEX_ALERT_ENABLED:
        index_alert_to_opensearch(os_client, alert_type, alert_details_list, alert_summary)


# --- Detection Logic ---

def detect_failed_logins(client, index_name, time_window_minutes, failure_threshold):
    """Queries OpenSearch for multiple failed logins from the same IP."""
    logging.info(f"Running detection: Failed Logins (Threshold: {failure_threshold}, Window: {time_window_minutes}m)")
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = now - datetime.timedelta(minutes=time_window_minutes)
    start_time_iso = start_time.isoformat()
    query = {
        "size": 0, "query": {"bool": {"must": [
            {"match_phrase": {"message": "Failed password"}}, 
            {"range": {"@timestamp": {"gte": start_time_iso}}} ]}},
        "aggs": {"failed_logins_by_ip": {"terms": {"field": "client_ip", "size": 100}, # Standardize on client_ip if available
            "aggs": {"min_failure_count": {"bucket_selector": {
                "buckets_path": {"count": "_count"}, "script": f"params.count >= {failure_threshold}" }}}}}}
    try:
        response = client.search(index=index_name, body=query)
        suspicious_ips = []
        aggregations = response.get('aggregations', {})
        failed_logins_agg = aggregations.get('failed_logins_by_ip', {})
        buckets = failed_logins_agg.get('buckets', [])
        logging.debug(f"Failed login query returned {len(buckets)} IPs meeting threshold.")
        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip: suspicious_ips.append({"ip": ip, "count": count}) # Keep 'ip' key for this alert type details
        if suspicious_ips: dispatch_alert(client, "failed_logins", suspicious_ips) 
        else: logging.info("No IPs found meeting failed login threshold.")
    except Exception as e:
        logging.error(f"Error during failed login detection: {e}", exc_info=True)

def detect_high_404s(client, index_name, time_window_minutes, threshold):
    """Queries OpenSearch for clients generating excessive 404 errors."""
    logging.info(f"Running detection: High 404s (Threshold: {threshold}, Window: {time_window_minutes}m)")
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = now - datetime.timedelta(minutes=time_window_minutes)
    start_time_iso = start_time.isoformat()
    query = {
        "size": 0, "query": {"bool": {"must": [
            {"term": {"log_type": "web"}}, 
            {"term": {"status_code": 404}}, 
            {"range": {"@timestamp": {"gte": start_time_iso}}} ]}},
        "aggs": {"high_404s_by_ip": {"terms": {"field": "client_ip", "size": 100}, 
            "aggs": {"min_404_count": {"bucket_selector": {
                "buckets_path": {"count": "_count"}, "script": f"params.count >= {threshold}" }}}}}
    }
    try:
        response = client.search(index=index_name, body=query)
        suspicious_ips = []
        aggregations = response.get('aggregations', {})
        high_404s_agg = aggregations.get('high_404s_by_ip', {})
        buckets = high_404s_agg.get('buckets', [])
        logging.debug(f"High 404s query returned {len(buckets)} IPs meeting threshold.")
        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip: suspicious_ips.append({"client_ip": ip, "count": count}) 
        if suspicious_ips: dispatch_alert(client, "high_404s", suspicious_ips) 
        else: logging.info("No IPs found meeting high 404 threshold.")
    except Exception as e:
        logging.error(f"Error during high 404 detection: {e}", exc_info=True)

# --- Job Functions ---
def run_detection_jobs():
    """Connects to OpenSearch and runs all enabled detection jobs."""
    logging.info("Running scheduled detection jobs...")
    try:
        os_client = create_opensearch_client() 
        # Ensure alert index exists
        create_alert_index_if_not_exists(os_client, ALERT_INDEX_NAME)

        if os_client.indices.exists(index=OPENSEARCH_INDEX_NAME): 
            # Run Failed Login Detection if enabled
            if FAILED_LOGIN_ENABLED:
                 detect_failed_logins(os_client, OPENSEARCH_INDEX_NAME, FAILED_LOGIN_TIME_WINDOW, FAILED_LOGIN_THRESHOLD) 
            else:
                 logging.info("Failed login detection rule is disabled.")
                 
            # Run High 404 Detection if enabled
            if HIGH_404_ENABLED:
                 detect_high_404s(os_client, OPENSEARCH_INDEX_NAME, HIGH_404_TIME_WINDOW, HIGH_404_THRESHOLD)
            else:
                 logging.info("High 404 detection rule is disabled.")
        else:
            logging.error(f"Log index '{OPENSEARCH_INDEX_NAME}' does not exist. Cannot run detection jobs.")
            
    except ValueError as ve: # Catch connection errors
        logging.error(f"Connection error during detection job run: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during detection job run: {e}", exc_info=True)
    logging.info("Scheduled detection jobs finished.")


# --- Main Scheduler Execution ---
# Flag to control the main loop for graceful shutdown
running = True
def shutdown_handler(signum, frame):
    """Handles signals like SIGINT (Ctrl+C) for graceful shutdown."""
    global running, scheduler # Need scheduler instance
    logging.info(f"Received signal {signum}. Shutting down scheduler...")
    running = False
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False) # Don't wait for jobs to finish

# Register signal handlers
signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

if __name__ == "__main__":
    logging.info(f"Starting anomaly detection scheduler...")
    
    # Initialize the scheduler
    scheduler = BlockingScheduler(timezone="UTC") 

    # Run jobs once immediately on startup
    run_detection_jobs() 

    # Schedule the combined job runner
    if FAILED_LOGIN_ENABLED or HIGH_404_ENABLED:
        logging.info(f"Scheduling detection runs every {SCHEDULER_INTERVAL_MINUTES} minutes.")
        scheduler.add_job(
            run_detection_jobs, 
            'interval', 
            minutes=SCHEDULER_INTERVAL_MINUTES, 
            id='detection_runner', 
            replace_existing=True 
        )
    else:
        logging.warning("All detection rules are disabled in config. Scheduler will not run jobs.")

    if not scheduler.get_jobs():
         logging.warning("No detection jobs were scheduled. Exiting.")
         sys.exit(0)

    logging.info("Scheduler starting. Press Ctrl+C to exit.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logging.info("Scheduler stopped via interrupt.")
    except Exception as e:
        logging.error(f"Scheduler failed: {e}", exc_info=True)
    finally:
        if scheduler.running: # Check again in case shutdown happened quickly
             scheduler.shutdown(wait=False)
        logging.info("Anomaly detection scheduler finished.")
