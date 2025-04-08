document.addEventListener('DOMContentLoaded', () => {
    const tableBody = document.getElementById('alerts-table-body'); // Target table body
    const refreshButton = document.getElementById('refresh-button');
    const apiUrl = `http://localhost:5001/api/alerts`; 

    async function fetchAlerts() {
        // Show loading message in table
        tableBody.innerHTML = '<tr><td colspan="3">Loading alerts...</td></tr>'; // Updated colspan
        try {
            // Fetch data from the API (limit parameter IS used by the log reading API)
            const response = await fetch(`${apiUrl}?limit=100`); // Keep limit for now
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            // Clear the table body
            tableBody.innerHTML = ''; 
            
            // Check if the response contains the expected 'alerts' array
            if (data.alerts && Array.isArray(data.alerts) && data.alerts.length > 0) {
                // Create and append a table row for each alert object from OpenSearch
                data.alerts.forEach(alertDoc => {
                    const row = document.createElement('tr');
                    
                    const tsCell = document.createElement('td');
                    // Format timestamp nicely if possible
                    try {
                        tsCell.textContent = new Date(alertDoc.alert_timestamp).toLocaleString();
                    } catch {
                        tsCell.textContent = alertDoc.alert_timestamp || 'N/A'; 
                    }
                    row.appendChild(tsCell);

                    const typeCell = document.createElement('td');
                    typeCell.textContent = alertDoc.alert_type || 'UNKNOWN'; 
                    row.appendChild(typeCell);
                    
                    const detailsCell = document.createElement('td');
                    // Display the summary and potentially format details
                    let detailsHtml = `<strong>${alertDoc.summary || 'Details:'}</strong><br/>`;
                    if (alertDoc.details && Array.isArray(alertDoc.details)) {
                        alertDoc.details.forEach(item => {
                            // Simple formatting, could be improved
                            detailsHtml += ` - IP: ${item.ip || item.client_ip || 'N/A'}, Count: ${item.count || 'N/A'}<br/>`;
                        });
                    } else {
                         detailsHtml += JSON.stringify(alertDoc.details); // Fallback
                    }
                    detailsCell.innerHTML = detailsHtml; // Use innerHTML for line breaks
                    row.appendChild(detailsCell);

                    tableBody.appendChild(row);
                });
            } else if (data.alerts && data.alerts.length === 0) {
                 tableBody.innerHTML = '<tr><td colspan="3">No alerts found in OpenSearch index.</td></tr>'; 
            } else {
                 // Handle cases where 'alerts' key might be missing or not an array
                 console.error("Unexpected API response format:", data);
                 tableBody.innerHTML = '<tr><td colspan="3" class="error-message">Received unexpected data format from API.</td></tr>'; // Updated colspan
            }

        } catch (error) {
            console.error('Error fetching or processing alerts:', error);
            tableBody.innerHTML = `<tr><td colspan="3" class="error-message">Failed to load alerts. Is the API server running? (${error})</td></tr>`; // Updated colspan
        }
    }

    // Add event listener for the refresh button
    if (refreshButton) {
        refreshButton.addEventListener('click', fetchAlerts);
    }

    // Initial fetch when the page loads
    fetchAlerts();
});
