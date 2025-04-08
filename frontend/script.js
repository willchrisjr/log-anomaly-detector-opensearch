document.addEventListener('DOMContentLoaded', () => {
    const tableBody = document.getElementById('alerts-table-body'); // Target table body
    const refreshButton = document.getElementById('refresh-button');
    const apiUrl = `http://localhost:5001/api/alerts`; 

    async function fetchAlerts() {
        // Show loading message in table
        tableBody.innerHTML = '<tr><td colspan="2">Loading alerts...</td></tr>'; 
        try {
            // Fetch data from the API (limit parameter is no longer used by the updated API)
            const response = await fetch(apiUrl); 
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            // Clear the table body
            tableBody.innerHTML = ''; 
            
            // Check if the response contains the expected 'alerts' array
            if (data.alerts && Array.isArray(data.alerts) && data.alerts.length > 0) {
                // Create and append a table row for each alert object
                data.alerts.forEach(alert => {
                    const row = document.createElement('tr');
                    
                    const ipCell = document.createElement('td');
                    ipCell.textContent = alert.ip || 'N/A'; // Handle potential missing data
                    row.appendChild(ipCell);
                    
                    const countCell = document.createElement('td');
                    countCell.textContent = alert.count !== undefined ? alert.count : 'N/A'; // Handle potential missing data
                    row.appendChild(countCell);

                    tableBody.appendChild(row);
                });
            } else if (data.alerts && data.alerts.length === 0) {
                 tableBody.innerHTML = '<tr><td colspan="2">No alerts found matching the criteria.</td></tr>';
            } else {
                 // Handle cases where 'alerts' key might be missing or not an array
                 console.error("Unexpected API response format:", data);
                 tableBody.innerHTML = '<tr><td colspan="2" class="error-message">Received unexpected data format from API.</td></tr>';
            }

        } catch (error) {
            console.error('Error fetching or processing alerts:', error);
            tableBody.innerHTML = `<tr><td colspan="2" class="error-message">Failed to load alerts. Is the API server running? (${error})</td></tr>`;
        }
    }

    // Add event listener for the refresh button
    if (refreshButton) {
        refreshButton.addEventListener('click', fetchAlerts);
    }

    // Initial fetch when the page loads
    fetchAlerts();
});
