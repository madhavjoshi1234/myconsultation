// This script should be loaded with 'defer' on admin-related pages.
document.addEventListener('DOMContentLoaded', () => {
    const navbarPlaceholder = document.getElementById('navbar-placeholder');
    if (!navbarPlaceholder) {
        console.error('Navbar placeholder element with ID "navbar-placeholder" not found in the document.');
        return;
    }

    // Fetch the common navbar HTML
    fetch('admin-navbar.html')
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

            // Set user name in navbar by fetching from the server
            const adminToken = localStorage.getItem('adminToken');
            if (adminToken) {
                fetch('/api/admin/me', {
                    headers: { 'Authorization': `Bearer ${adminToken}` }
                })
                .then(response => {
                    if (!response.ok) return null;
                    return response.json();
                })
                .then(admin => {
                    if (admin && admin.first_name) {
                        const navbarBrand = navbarPlaceholder.querySelector('.navbar-brand');
                        if (navbarBrand) {
                            navbarBrand.textContent = `Welcome, ${admin.first_name}`;
                        }
                    }
                })
                .catch(error => console.error('Error fetching admin name:', error));
            }

            // 1. Set the 'active' class on the correct link
            const currentPage = window.location.pathname.split('/').pop();
            const navLinks = navbarPlaceholder.querySelectorAll('.navbar-links a');

            navLinks.forEach(link => {
                const linkPage = link.getAttribute('href').split('/').pop().split('#')[0]; // Handle anchors
                if (linkPage === currentPage) {
                    link.classList.add('active');
                }
            });

            // 2. Attach the logout functionality
            const logoutButton = document.getElementById('logoutButton');
            if (logoutButton) {
                logoutButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    localStorage.removeItem('adminToken');
                    window.location.href = 'login.html';
                });
            }
        })
        .catch(error => {
            console.error('Failed to fetch and load the admin navbar:', error);
            navbarPlaceholder.innerHTML = '<p style="color:red; text-align:center;">Error: Could not load navigation bar.</p>';
        });
});