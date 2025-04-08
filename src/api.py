"""
Backend API Server using Flask.

Provides endpoints to interact with the security automation framework,
initially focusing on retrieving recent alerts.
"""
import logging
import sys
import os
import json
import datetime # Added
from flask import Flask, jsonify, request 
from flask_cors import CORS 
from opensearchpy import OpenSearch, RequestsHttpConnection # Added
from config_loader import load_config 

# --- Setup ---
# Basic logging for the API server
logging.basicConfig(level=logging.INFO, format='%(asctime)s - API - %(levelname)s - %(message)s')

# Load configuration
config = load_config()
if not config:
    logging.error("API failed to load configuration. Exiting.")
    sys.exit(1)

# --- OpenSearch Settings ---
try:
    OPENSEARCH_HOST = config['opensearch']['host']
    OPENSEARCH_PORT = config['opensearch']['port']
    OPENSEARCH_INDEX_NAME = config['opensearch']['index_name']
except KeyError as e:
    logging.error(f"API missing required opensearch configuration key: {e}. Exiting.")
    sys.exit(1)

# --- Detection Settings (needed for query) ---
try:
    DETECTION_RULE = config['detection']['failed_login_rule']
    TIME_WINDOW_MINUTES = DETECTION_RULE['time_window_minutes']
    FAILURE_THRESHOLD = DETECTION_RULE['failure_threshold']
except KeyError as e:
    logging.error(f"API missing required detection configuration key: {e}. Exiting.")
    sys.exit(1)


# Initialize Flask app
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- OpenSearch Client ---
# Duplicated from detect_anomalies.py - consider refactoring to utils later
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
        if not client.ping():
            raise ValueError("Connection failed")
        logging.info("API successfully connected to OpenSearch.")
        return client
    except Exception as e:
        logging.error(f"API failed to connect to OpenSearch: {e}")
        raise # Re-raise exception to be caught by endpoint handler


# --- API Endpoints ---
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    API endpoint to retrieve IPs with recent failed logins exceeding threshold.
    Queries OpenSearch directly based on config settings.
    """
    logging.info("API request received for /api/alerts")
    
    try:
        os_client = create_opensearch_client()
    except Exception:
         return jsonify({"error": "API could not connect to OpenSearch"}), 500

    # Calculate time window
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = now - datetime.timedelta(minutes=TIME_WINDOW_MINUTES)
    start_time_iso = start_time.isoformat()

    # Build the aggregation query (same as in detect_anomalies.py)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"range": {"@timestamp": {"gte": start_time_iso}}}
                ]
            }
        },
        "aggs": {
            "failed_logins_by_ip": {
                "terms": {"field": "ip_address", "size": 100}, 
                "aggs": {
                    "min_failure_count": {
                        "bucket_selector": {
                            "buckets_path": {"count": "_count"},
                            "script": f"params.count >= {FAILURE_THRESHOLD}"
                        }
                    }
                }
            }
        }
    }

    try:
        # Execute the search
        response = os_client.search(index=OPENSEARCH_INDEX_NAME, body=query)
        
        # Process the aggregation results into structured data
        results_list = []
        aggregations = response.get('aggregations', {})
        failed_logins_agg = aggregations.get('failed_logins_by_ip', {})
        buckets = failed_logins_agg.get('buckets', [])
        
        logging.info(f"API query found {len(buckets)} IPs meeting the threshold.")

        for bucket in buckets:
            ip = bucket.get('key')
            count = bucket.get('doc_count')
            if ip:
                 results_list.append({"ip": ip, "count": count})

        return jsonify({"alerts": results_list})

    except Exception as e:
        logging.error(f"API error querying OpenSearch: {e}", exc_info=True)
        return jsonify({"error": "Failed to query OpenSearch for alerts"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "ok"}), 200

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Starting Flask API server...")
    # Run the app (use development server for now)
    # Host '0.0.0.0' makes it accessible on the network, not just localhost
    # Use port 5001 as 5000 might be in use
    api_port = 5001 
    logging.info(f"Attempting to start API on port {api_port}")
    try:
        app.run(host='0.0.0.0', port=api_port, debug=False) 
        # Note: debug=True is helpful for development but should be False in production
    except OSError as e:
        if "Address already in use" in str(e):
             logging.error(f"Port {api_port} is already in use. Please try a different port or stop the existing service.")
        else:
             logging.error(f"Failed to start Flask server: {e}")
