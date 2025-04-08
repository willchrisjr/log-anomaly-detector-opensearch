"""
Ingests log data from a specified file into an OpenSearch index.

This script reads log lines, parses them using regex, extracts relevant fields
(including timestamp and IP address), creates an OpenSearch index with an
appropriate mapping if it doesn't exist, and uses the bulk API to index
the processed log data.
"""
import re
import datetime
import logging # Added for better logging
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9200
INDEX_NAME = 'ssh-logs'
LOG_FILE_PATH = 'data/mock_ssh.log'

# Regex to parse the log line (simple example)
# Example: Apr 8 10:15:30 server1 sshd[1234]: Message
log_pattern = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<process>\S+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

# Regex to extract IP (reused from detect_anomalies)
ip_pattern = re.compile(r"from\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def extract_ip_from_message(message):
    """Extracts IP address from the log message."""
    match = ip_pattern.search(message)
    if match:
        return match.group("ip_address")
    return None

def parse_log_line(line):
    """
    Parses a single log line based on the defined regex pattern.

    Extracts fields like timestamp, hostname, process, PID, message, and IP address.
    Attempts to convert the log timestamp to ISO 8601 format.

    Args:
        line (str): A single line from the log file.

    Returns:
        dict: A dictionary containing the parsed fields, or None if parsing fails.
    """
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        
        # Attempt to create a proper timestamp
        try:
            # Assuming current year for simplicity
            current_year = datetime.datetime.now().year
            timestamp_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            # Make timestamp timezone-aware (assuming local time if not specified, adjust if needed)
            # For simplicity, let's assume logs are in local time and convert to UTC for storage
            # A more robust solution would handle timezone info if present in logs
            local_tz = datetime.datetime.now().astimezone().tzinfo
            aware_timestamp = timestamp.replace(tzinfo=local_tz)
            data['@timestamp'] = aware_timestamp.isoformat()
        except ValueError as e:
            logging.warning(f"Could not parse timestamp from log line: {line.strip()}. Error: {e}. Using current UTC time.")
            # Fallback if parsing fails - use timezone-aware UTC now
            data['@timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
        # Remove original time fields if timestamp is created
        del data['month']
        del data['day']
        del data['time']
        
        # Add the raw log line as well
        data['log_original'] = line.strip()
        
        # Convert PID to integer
        data['pid'] = int(data['pid'])

        # Extract IP address if present in the message
        ip_address = extract_ip_from_message(data['message'])
        if ip_address:
            data['ip_address'] = ip_address
        
        return data
    return None # Return None if line doesn't match pattern

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
        http_conn_options={'timeout': 10}, # Add timeout
        use_ssl=False, # Assuming local instance without SSL
        verify_certs=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection # Recommended for compatibility
    )
    # Verify connection
    if not client.ping():
        logging.error("Connection to OpenSearch failed")
        raise ValueError("Connection to OpenSearch failed")
    logging.info("Successfully connected to OpenSearch.")
    return client

def create_index_if_not_exists(client, index):
    """
    Creates the specified OpenSearch index with a predefined mapping if it doesn't already exist.

    Args:
        client (OpenSearch): The OpenSearch client instance.
        index (str): The name of the index to create.
    """
    if not client.indices.exists(index=index):
        logging.info(f"Index '{index}' not found. Creating...")
        try:
            # A simple index mapping, can be expanded later
            mapping = {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "hostname": {"type": "keyword"},
                    "process": {"type": "keyword"},
                    "pid": {"type": "integer"},
                    "message": {"type": "text"},
                    "ip_address": {"type": "keyword"}, # Add keyword field for IP
                    "log_original": {"type": "text", "index": False} # Don't index raw log by default
                }
            }
            client.indices.create(index=index, body={'mappings': mapping})
            logging.info(f"Index '{index}' created successfully.")
        except Exception as e:
            logging.error(f"Error creating index '{index}': {e}")
            # Decide if you want to proceed without mapping or raise error
            raise e # Re-raise the exception to halt execution if index creation fails
    else:
        logging.info(f"Index '{index}' already exists.")

def generate_actions(log_file, index_name):
    """
    Reads a log file line by line, parses each line, and yields actions formatted for the OpenSearch bulk API.

    Args:
        log_file (str): The path to the log file.
        index_name (str): The name of the target OpenSearch index.

    Yields:
        dict: An action dictionary for the OpenSearch bulk helper.
    """
    try:
        with open(log_file, 'r') as f:
            for line in f:
                parsed_data = parse_log_line(line)
                if parsed_data:
                    yield {
                        "_index": index_name,
                        "_source": parsed_data
                    }
                else:
                    logging.warning(f"Skipping unparseable line: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"Log file not found at {log_file}")
    except Exception as e:
        logging.error(f"Error reading log file {log_file}: {e}")


if __name__ == "__main__":
    logging.info("Starting log ingestion script...")
    
    try:
        os_client = create_opensearch_client()
        # Ensure index exists with the correct mapping before ingesting
        create_index_if_not_exists(os_client, INDEX_NAME) 
        
        logging.info(f"Reading logs from {LOG_FILE_PATH} and indexing to '{INDEX_NAME}'...")
        
        # Use bulk helper for efficiency
        success_count, errors = helpers.bulk(
            os_client,
            generate_actions(LOG_FILE_PATH, INDEX_NAME),
            chunk_size=500,  # Adjust as needed
            request_timeout=60 # Increase timeout for bulk operations
        )
        
        logging.info(f"Successfully indexed {success_count} log entries.")
        if errors:
            logging.error(f"Encountered {len(errors)} errors during indexing.")
            # Log first few errors for debugging
            for i, error in enumerate(errors[:5]):
                 logging.error(f"  Bulk Indexing Error {i+1}: {error}")

    except ValueError as ve:
        logging.error(f"Configuration or Connection error: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during ingestion: {e}", exc_info=True)

    logging.info("Log ingestion script finished.")
