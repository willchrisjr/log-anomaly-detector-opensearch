"""
Ingests log data from specified files into an OpenSearch index.

Supports parsing SSH and Apache Combined Log Format logs.
Reads log lines, parses them using regex, extracts relevant fields
(including timestamp and IP address), creates an OpenSearch index with an
appropriate mapping if it doesn't exist, and uses the bulk API to index
the processed log data.
"""
import re
import datetime
import logging 
import sys 
import os 
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
from config_loader import load_config # Use direct import (run with PYTHONPATH=.)

# Setup basic logging
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

# --- Log File Paths (Consider making these configurable) ---
# For now, we determine which file to ingest based on an argument or default
# Defaulting to web log for Phase 9 testing
DEFAULT_LOG_FILE = 'data/mock_access.log' 
DEFAULT_LOG_TYPE = 'web' 

# --- Regex Patterns ---

# SSH Log Regex
ssh_log_pattern = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<process>\S+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)
ssh_ip_pattern = re.compile(r"from\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# Apache Combined Log Format Regex
apache_log_pattern = re.compile(
    r'^(?P<client_ip>\S+)\s+'          # Client IP
    r'(?P<ident>\S+)\s+'               # RFC 1413 identity (usually '-')
    r'(?P<auth>\S+)\s+'                # Userid of person requesting (usually '-')
    r'\[(?P<timestamp_str>[^\]]+)\]\s+' # Timestamp [dd/Mon/YYYY:HH:MM:SS +ZZZZ]
    r'"(?P<method>[A-Z]+)\s+'          # Request method (GET, POST, etc.)
    r'(?P<request_path>\S+)\s+'        # Requested path
    r'(?P<http_version>HTTP/\d\.\d)"\s+' # HTTP version
    r'(?P<status_code>\d{3})\s+'       # Status code (e.g., 200, 404)
    r'(?P<bytes_sent>\S+)\s+'          # Bytes sent ('-' if none)
    r'"(?P<referrer>[^"]*)"\s+'        # Referrer URL
    r'"(?P<user_agent>[^"]*)"$'        # User agent string
)

# --- Parsing Functions ---

def parse_ssh_log_line(line):
    """Parses a single SSH log line."""
    match = ssh_log_pattern.match(line)
    if not match: return None
    data = match.groupdict()
    data['log_type'] = 'ssh'
    ip_match = ssh_ip_pattern.search(data['message'])
    if ip_match: data['client_ip'] = ip_match.group("ip_address") # Standardize field name
    try:
        current_year = datetime.datetime.now().year
        ts_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
        ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
        local_tz = datetime.datetime.now().astimezone().tzinfo
        aware_ts = ts.replace(tzinfo=local_tz)
        data['@timestamp'] = aware_ts.isoformat()
    except ValueError as e:
        logging.warning(f"SSH ts parse error: {e}. Using current UTC.")
        data['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    del data['month'], data['day'], data['time']
    data['log_original'] = line.strip()
    data['pid'] = int(data['pid']) if data.get('pid') else None
    return data

def parse_apache_log_line(line):
    """Parses a single Apache Combined Log Format line."""
    match = apache_log_pattern.match(line)
    if not match: return None
    data = match.groupdict()
    data['log_type'] = 'web'
    try:
        ts = datetime.datetime.strptime(data['timestamp_str'], "%d/%b/%Y:%H:%M:%S %z")
        data['@timestamp'] = ts.isoformat()
    except ValueError as e:
        logging.warning(f"Apache ts parse error: {e}. Using current UTC.")
        data['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    del data['timestamp_str']
    try: data['status_code'] = int(data['status_code'])
    except ValueError: data['status_code'] = None 
    try: data['bytes_sent'] = int(data['bytes_sent'])
    except ValueError: data['bytes_sent'] = 0
    if data['ident'] == '-': data['ident'] = None
    if data['auth'] == '-': data['auth'] = None
    if data['referrer'] == '-': data['referrer'] = None
    data['log_original'] = line.strip()
    return data

def parse_log_line(line, log_type):
    """Dispatcher function to parse log line based on type."""
    if log_type == 'ssh': return parse_ssh_log_line(line)
    elif log_type == 'web': return parse_apache_log_line(line)
    else:
        logging.warning(f"Unsupported log_type for parsing: {log_type}")
        return None

# --- OpenSearch Client & Index ---

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
        logging.info("Successfully connected to OpenSearch.")
        return client
    except Exception as e:
        logging.error(f"Failed to connect to OpenSearch: {e}")
        raise 

def create_index_if_not_exists(client, index):
    """Creates the index with a combined mapping if it doesn't exist."""
    if not client.indices.exists(index=index):
        logging.info(f"Index '{index}' not found. Creating...")
        try:
            mapping = {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "log_type": {"type": "keyword"}, 
                    "hostname": {"type": "keyword"},
                    "process": {"type": "keyword"},
                    "pid": {"type": "integer"},
                    "message": {"type": "text"}, 
                    "client_ip": {"type": "keyword"}, 
                    "ident": {"type": "keyword"},
                    "auth": {"type": "keyword"},
                    "method": {"type": "keyword"},
                    "request_path": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "http_version": {"type": "keyword"},
                    "status_code": {"type": "integer"},
                    "bytes_sent": {"type": "long"},
                    "referrer": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                    "user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                    "log_original": {"type": "text", "index": False} 
                }
            }
            client.indices.create(index=index, body={'mappings': mapping})
            logging.info(f"Index '{index}' created successfully.")
        except Exception as e:
            logging.error(f"Error creating index '{index}': {e}")
            raise 
    else:
        logging.info(f"Index '{index}' already exists.")

# --- Bulk Ingestion ---

def generate_actions(log_file, index_name, log_type):
    """Reads log file, parses lines, yields actions for bulk API."""
    try:
        with open(log_file, 'r') as f:
            for line in f:
                parsed_data = parse_log_line(line, log_type)
                if parsed_data:
                    yield {"_index": index_name, "_source": parsed_data}
                else:
                    logging.warning(f"Skipping unparseable line: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"Log file not found at {log_file}")
    except Exception as e:
        logging.error(f"Error reading log file {log_file}: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    # Basic argument parsing (optional, could use argparse)
    log_file_to_ingest = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_FILE
    log_type_to_ingest = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_LOG_TYPE
    
    # Validate log type
    if log_type_to_ingest not in ['ssh', 'web']:
        logging.error(f"Invalid log_type specified: {log_type_to_ingest}. Use 'ssh' or 'web'.")
        sys.exit(1)

    logging.info(f"Starting log ingestion script for type '{log_type_to_ingest}'...")
    
    try:
        os_client = create_opensearch_client() 
        index_name_from_config = config['opensearch']['index_name']
        # Ensure index exists with the correct mapping
        # NOTE: If mapping changes, you MUST delete the index first
        create_index_if_not_exists(os_client, index_name_from_config) 
        
        logging.info(f"Reading '{log_type_to_ingest}' logs from {log_file_to_ingest} and indexing to '{index_name_from_config}'...")
        
        success_count, errors = helpers.bulk(
            os_client,
            generate_actions(log_file_to_ingest, index_name_from_config, log_type_to_ingest), 
            chunk_size=500,  
            request_timeout=60 
        )
        
        logging.info(f"Successfully indexed {success_count} log entries.")
        if errors:
            logging.error(f"Encountered {len(errors)} errors during indexing.")
            for i, error in enumerate(errors[:5]):
                 logging.error(f"  Bulk Indexing Error {i+1}: {error}")

    except ValueError as ve:
        logging.error(f"Configuration or Connection error: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during ingestion: {e}", exc_info=True)

    logging.info("Log ingestion script finished.")
