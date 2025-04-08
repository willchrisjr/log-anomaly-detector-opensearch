"""
Backend API Server using Flask.

Provides endpoints to retrieve structured alerts from the OpenSearch alert index.
"""
import logging
import sys
import os
import json
import datetime 
from flask import Flask, jsonify, request 
from flask_cors import CORS 
from opensearchpy import OpenSearch, RequestsHttpConnection 
from config_loader import load_config # Direct import is correct here, no change needed.

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - API - %(levelname)s - %(message)s')

config = load_config()
if not config:
    logging.error("API failed to load configuration. Exiting.")
    sys.exit(1)

# --- OpenSearch Settings ---
try:
    OPENSEARCH_HOST = config['opensearch']['host']
    OPENSEARCH_PORT = config['opensearch']['port']
    # Get the ALERT index name, default if not found
    ALERT_INDEX_NAME = config['opensearch'].get('alert_index_name', 'security-alerts-details') 
except KeyError as e:
    logging.error(f"API missing required opensearch configuration key: {e}. Exiting.")
    sys.exit(1)

# Initialize Flask app
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

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
        logging.info("API successfully connected to OpenSearch.")
        return client
    except Exception as e:
        logging.error(f"API failed to connect to OpenSearch: {e}")
        raise 

# --- API Endpoints ---
@app.route('/api/alerts', methods=['GET'])
def get_alerts_from_opensearch():
    """
    API endpoint to retrieve recent alerts directly from the OpenSearch alert index.
    Accepts an optional 'limit' query parameter.
    """
    try:
        limit = int(request.args.get('limit', 100)) # Default to 100 alerts
    except ValueError:
        return jsonify({"error": "Invalid 'limit' parameter. Must be an integer."}), 400

    logging.info(f"API request received for /api/alerts (from OpenSearch) with limit={limit}")
    
    try:
        os_client = create_opensearch_client()
    except Exception:
         return jsonify({"error": "API could not connect to OpenSearch"}), 500

    # Query the alert index, sort by timestamp descending
    query = {
        "size": limit,
        "query": {"match_all": {}}, # Get all alert types for now
        "sort": [
            {"alert_timestamp": {"order": "desc"}}
        ]
    }

    try:
        response = os_client.search(index=ALERT_INDEX_NAME, body=query)
        
        hits = response.get('hits', {}).get('hits', [])
        results_list = [hit['_source'] for hit in hits] # Extract the source documents
        
        logging.info(f"API query found {len(results_list)} alert documents in {ALERT_INDEX_NAME}.")
        return jsonify({"alerts": results_list})

    except Exception as e:
        # Handle case where alert index might not exist yet
        if "index_not_found_exception" in str(e):
             logging.warning(f"Alert index '{ALERT_INDEX_NAME}' not found. Returning empty list.")
             return jsonify({"alerts": []})
        else:
             logging.error(f"API error querying OpenSearch alert index: {e}", exc_info=True)
             return jsonify({"error": "Failed to query OpenSearch for alerts"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "ok"}), 200

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Starting Flask API server...")
    api_port = 5001 
    logging.info(f"Attempting to start API on port {api_port}")
    try:
        app.run(host='0.0.0.0', port=api_port, debug=False) 
    except OSError as e:
        if "Address already in use" in str(e):
             logging.error(f"Port {api_port} is already in use. Please try a different port or stop the existing service.")
        else:
             logging.error(f"Failed to start Flask server: {e}")
    except Exception as e:
         logging.error(f"An unexpected error occurred starting the API server: {e}")
