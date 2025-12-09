// This script is loaded with 'defer' or dynamically, so the DOM is ready when it runs.
// The DOMContentLoaded wrapper is removed to ensure it executes correctly when loaded dynamically after the event has already fired.
const navbarPlaceholder = document.getElementById('navbar-placeholder');
if (!navbarPlaceholder) {
    console.error('Navbar placeholder element not found in the document.');
} else {
    // Fetch the navbar HTML
    fetch('client-navbar.html')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok: ' + response.statusText);
            }
            return response.text();
        })
        .then(html => {
            // Inject the navbar HTML into the placeholder
            navbarPlaceholder.innerHTML = html;

            // --- Post-injection logic ---

            // 1. Set the 'active' class on the correct link
            // Get the current page's filename (e.g., "client-food-plan.html")
            const currentPage = window.location.pathname.split('/').pop();
            const navLinks = navbarPlaceholder.querySelectorAll('.main-navbar a');

            navLinks.forEach(link => {
                const linkPage = link.getAttribute('href').split('/').pop().split('?')[0]; // Also remove query params
                if (linkPage === currentPage) {
                    link.classList.add('active');
                }
            });

            // 2. Attach the logout functionality
            const logoutButton = document.getElementById('logoutButton');
            if (logoutButton) {
                logoutButton.addEventListener('click', (e) => {
                    e.preventDefault(); // Prevent the link from navigating to "#"
                    localStorage.removeItem('clientToken');
                    window.location.href = 'login.html';
                });
            }
        })
        .catch(error => {
            console.error('Failed to fetch and load the navbar:', error);
            navbarPlaceholder.innerHTML = '<p style="color:red; text-align:center;">Error: Could not load navigation bar.</p>';
        });
}
