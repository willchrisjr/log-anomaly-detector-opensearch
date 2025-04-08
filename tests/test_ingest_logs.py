"""
Unit tests for log parsing functions in src/ingest_logs.py
"""
import pytest
import datetime
# Use correct import now that src is a package
from src.ingest_logs import parse_ssh_log_line, parse_apache_log_line 

# --- SSH Log Tests ---

def test_parse_valid_ssh_failed_password():
    """Test parsing a typical SSH failed password log line."""
    line = "Apr 8 10:16:15 server1 sshd[1238]: Failed password for user1 from 192.168.1.10 port 54324 ssh2"
    parsed = parse_ssh_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'ssh'
    assert parsed['hostname'] == 'server1'
    assert parsed['process'] == 'sshd'
    assert parsed['pid'] == 1238
    assert parsed['message'] == 'Failed password for user1 from 192.168.1.10 port 54324 ssh2'
    assert parsed['client_ip'] == '192.168.1.10'
    assert '@timestamp' in parsed # Check timestamp exists

def test_parse_valid_ssh_accepted_password():
    """Test parsing a typical SSH accepted password log line."""
    line = "Apr 8 10:15:30 server1 sshd[1234]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2"
    parsed = parse_ssh_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'ssh'
    assert parsed['client_ip'] == '192.168.1.10'
    assert parsed['message'] == 'Accepted password for user1 from 192.168.1.10 port 54321 ssh2'

def test_parse_valid_ssh_disconnect():
    """Test parsing an SSH disconnect log line (no IP)."""
    line = "Apr 8 10:17:20 server1 sshd[1240]: Received disconnect from 10.0.0.5 port 12345:11: Bye Bye [preauth]"
    parsed = parse_ssh_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'ssh'
    # Update assertion: The current regex *does* extract the IP from this message
    assert parsed['client_ip'] == '10.0.0.5' 
    assert parsed['message'] == 'Received disconnect from 10.0.0.5 port 12345:11: Bye Bye [preauth]'

def test_parse_invalid_ssh_line():
    """Test parsing a line that doesn't match the SSH format."""
    line = "This is not an ssh log line"
    parsed = parse_ssh_log_line(line)
    assert parsed is None

# --- Apache Log Tests ---

def test_parse_valid_apache_get():
    """Test parsing a typical Apache GET request log line."""
    line = '192.168.1.10 - - [08/Apr/2025:14:30:01 +0000] "GET /index.html HTTP/1.1" 200 1543 "-" "Mozilla/5.0"'
    parsed = parse_apache_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'web'
    assert parsed['client_ip'] == '192.168.1.10'
    assert parsed['ident'] is None
    assert parsed['auth'] is None
    assert parsed['method'] == 'GET'
    assert parsed['request_path'] == '/index.html'
    assert parsed['http_version'] == 'HTTP/1.1'
    assert parsed['status_code'] == 200
    assert parsed['bytes_sent'] == 1543
    assert parsed['referrer'] is None
    assert parsed['user_agent'] == 'Mozilla/5.0'
    assert '@timestamp' in parsed
    # Check timestamp parsing specifically
    expected_dt = datetime.datetime(2025, 4, 8, 14, 30, 1, tzinfo=datetime.timezone.utc)
    assert parsed['@timestamp'] == expected_dt.isoformat()

def test_parse_valid_apache_post_with_referrer():
    """Test parsing an Apache POST request with a referrer."""
    line = '192.168.1.15 - - [08/Apr/2025:14:30:15 +0000] "POST /api/data HTTP/1.1" 201 50 "http://example.com" "CustomClient/1.1"'
    parsed = parse_apache_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'web'
    assert parsed['client_ip'] == '192.168.1.15'
    assert parsed['method'] == 'POST'
    assert parsed['request_path'] == '/api/data'
    assert parsed['status_code'] == 201
    assert parsed['bytes_sent'] == 50
    assert parsed['referrer'] == 'http://example.com'
    assert parsed['user_agent'] == 'CustomClient/1.1'

def test_parse_apache_404():
    """Test parsing an Apache 404 error log line."""
    line = '10.0.0.99 - - [08/Apr/2025:14:31:05 +0000] "GET /admin/config.php HTTP/1.1" 404 210 "-" "curl/7.68.0"'
    parsed = parse_apache_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'web'
    assert parsed['client_ip'] == '10.0.0.99'
    assert parsed['status_code'] == 404
    assert parsed['bytes_sent'] == 210

def test_parse_apache_bytes_sent_dash():
    """Test parsing an Apache log line where bytes sent is '-'."""
    line = '172.16.0.5 - - [08/Apr/2025:15:00:00 +0000] "HEAD / HTTP/1.1" 200 - "-" "HealthCheck"'
    parsed = parse_apache_log_line(line)
    assert parsed is not None
    assert parsed['log_type'] == 'web'
    assert parsed['status_code'] == 200
    assert parsed['bytes_sent'] == 0 # Should be converted to 0

def test_parse_invalid_apache_line():
    """Test parsing a line that doesn't match the Apache format."""
    line = "This is definitely not an apache log line"
    parsed = parse_apache_log_line(line)
    assert parsed is None
