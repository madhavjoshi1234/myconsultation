document.addEventListener('DOMContentLoaded', async () => {
    const messageDiv = document.getElementById('message');
    const clientInfoSection = document.getElementById('clientInfoSection');
    const clientNameSpan = document.getElementById('clientName');
    const clientEmailSpan = document.getElementById('clientEmail');
    const clientIdSpan = document.getElementById('clientId');
    const logoutButton = document.getElementById('logoutButton');

    const clientToken = localStorage.getItem('clientToken');

    if (!clientToken) {
        messageDiv.textContent = 'You are not logged in. Redirecting to login...';
        messageDiv.style.color = 'red';
        setTimeout(() => {
            window.location.href = 'client-login.html';
        }, 2000);
        return;
    }

    try {
        const response = await fetch('api/client/me', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${clientToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status === 401 || response.status === 403) {
            // Token is invalid or expired
            localStorage.removeItem('clientToken');
            messageDiv.textContent = 'Session expired or invalid. Please login again. Redirecting...';
            messageDiv.style.color = 'red';
            setTimeout(() => {
                window.location.href = 'client-login.html';
            }, 2500);
            return;
        }

        if (!response.ok) {
            const errorResult = await response.json().catch(() => ({ error: `Server error: ${response.status}` }));
            throw new Error(errorResult.error || `HTTP error! status: ${response.status}`);
        }

        const clientData = await response.json();

        clientNameSpan.textContent = `${clientData.first_name} ${clientData.last_name}`;
        clientEmailSpan.textContent = clientData.email;
        clientIdSpan.textContent = clientData.client_id;
        clientInfoSection.style.display = 'block';

    } catch (error) {
        console.error('Error fetching client data:', error);
        messageDiv.textContent = `Error loading dashboard: ${error.message}. Please try logging in again.`;
        messageDiv.style.color = 'red';
        // localStorage.removeItem('clientToken'); // Optionally clear token on error
    }

    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            localStorage.removeItem('clientToken');
            window.location.href = 'client-login.html';
        });
    }
});