"""
Detects anomalies in SSH log data stored in OpenSearch.

Specifically, this script queries an OpenSearch index for multiple failed
SSH login attempts originating from the same IP address within a defined
time window. It prints basic alerts to the console if the failure count
for an IP exceeds a set threshold.
"""
import re
import datetime
import logging # Added for better logging
from opensearchpy import OpenSearch, RequestsHttpConnection

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (should match ingest_logs.py for connection)
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9200
INDEX_NAME = 'ssh-logs'

# Anomaly Detection Parameters
TIME_WINDOW_MINUTES = 1440 # Look for failures in the last 24 hours (to catch mock data)
FAILURE_THRESHOLD = 3    # Trigger alert if >= X failures from the same IP

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
    client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_conn_options={'timeout': 10},
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection
    )
    if not client.ping():
        logging.error("Connection to OpenSearch failed")
        raise ValueError("Connection to OpenSearch failed")
    logging.info("Successfully connected to OpenSearch.")
    return client

# Unused function removed: extract_ip_from_message

def detect_failed_logins(client, index, time_window_minutes, failure_threshold):
    """
    Queries OpenSearch for multiple failed logins from the same IP within a specified time window.

    Uses an aggregation query to count failed logins per IP address and filters
    based on the failure threshold. Prints alerts for suspicious IPs found.

    Args:
        client (OpenSearch): The OpenSearch client instance.
        index (str): The name of the index to query.
        time_window_minutes (int): The lookback period in minutes.
        failure_threshold (int): The minimum number of failures to trigger an alert.
    """
    logging.info(f"Searching index '{index}' for IPs with >= {failure_threshold} failed logins in the last {time_window_minutes} minutes...")
    
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
                    "size": 100 # Limit number of IPs returned
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
        response = client.search(index=index, body=query)
        
        # Process the aggregation results
        suspicious_ips = []
        # Safely access nested dictionary keys
        aggregations = response.get('aggregations', {})
        failed_logins_agg = aggregations.get('failed_logins_by_ip', {})
        buckets = failed_logins_agg.get('buckets', [])
        
        logging.info(f"Aggregation query returned {len(buckets)} IPs meeting the threshold.")

        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip: # Should always have an IP here now
                 suspicious_ips.append({"ip": ip, "count": count})


        logging.info("--- Anomaly Detection Results ---")
        if suspicious_ips:
            logging.warning(f"Found {len(suspicious_ips)} suspicious IPs meeting threshold ({failure_threshold}). Triggering alerts:")
            # Simulate triggering an alert for each suspicious IP
            for item in suspicious_ips:
                # Using warning level for alerts to make them stand out
                logging.warning(f"ALERT: High number of failed logins ({item['count']}) detected from IP: {item['ip']}")
        else:
            logging.info("No suspicious IPs found meeting the threshold.")
        logging.info("-------------------------------")

    except Exception as e:
        logging.error(f"Error querying or processing results from OpenSearch: {e}", exc_info=True)


if __name__ == "__main__":
    logging.info("Starting anomaly detection script...")
    try:
        os_client = create_opensearch_client()
        # Check if index exists before querying
        if os_client.indices.exists(index=INDEX_NAME):
            detect_failed_logins(os_client, INDEX_NAME, TIME_WINDOW_MINUTES, FAILURE_THRESHOLD)
        else:
            logging.error(f"Index '{INDEX_NAME}' does not exist. Run the ingestion script first.")
            
    except ValueError as ve:
        logging.error(f"Configuration or Connection error: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during anomaly detection: {e}", exc_info=True)

    logging.info("Anomaly detection script finished.")
