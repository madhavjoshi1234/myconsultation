/**
 * Custom error class for handling authentication/authorization issues.
 */
class AuthError extends Error {
    constructor(message, tokenType) {
        super(message);
        this.name = 'AuthError';
        this.tokenType = tokenType; // 'client', 'admin', 'staff', or 'none'
    }
}

/**
 * Determines the user type based on available tokens.
 * @returns {string} 'admin', 'staff', 'client', or 'none'
 */
function getUserType() {
    if (localStorage.getItem('adminToken')) return 'admin';
    if (localStorage.getItem('staffToken')) return 'staff';
    if (localStorage.getItem('clientToken')) return 'client';
    return 'none';
}

/**
 * Handles user logout by clearing the appropriate token and redirecting.
 * @param {string} userType - 'admin', 'staff', or 'client'
 */
function handleLogout(userType) {
    const loginPage = 'login.html';
    switch (userType) {
        case 'admin':
            localStorage.removeItem('adminToken');
            break;
        case 'staff':
            localStorage.removeItem('staffToken');
            localStorage.removeItem('selectedRole');
            break;
        case 'client':
            localStorage.removeItem('clientToken');
            break;
    }
    window.location.href = loginPage;
}

/**
 * Renders the appropriate navigation bar based on the user type.
 */
function renderNavbar() {
    const userType = getUserType();
    const navbarContainer = document.getElementById('main-navbar-container');
    if (!navbarContainer) return;

    let navLinks = '';
    let brandText = 'Dashboard';
    let brandLink = '#';

    switch (userType) {
        case 'admin':
            brandText = 'Admin Dashboard';
            brandLink = 'admin.html';
            navLinks = `<li><a href="admin.html#manage-nutritionists">Nutritionists</a></li><li><a href="admin.html#manage-executives">Executives</a></li><li><a href="admin.html#manage-clients">Clients</a></li><li><a href="admin.html#generalFoodRecommendationsSection">General Recs</a></li>`;
            break;
        case 'staff':
            const role = localStorage.getItem('selectedRole');
            brandLink = role === 'nutritionist' ? 'nutritionist-dashboard.html' : 'executive-dashboard.html';
            brandText = role === 'nutritionist' ? 'Nutritionist Dashboard' : 'Executive Dashboard';
            navLinks = `<li><a href="${brandLink}">My Clients</a></li>`;
            break;
        case 'client':
            brandText = 'Client Dashboard';
            brandLink = 'client-dashboard.html';
            navLinks = `<li><a href="client-personal-details-form.html">Personal Details</a></li><li><a href="client-blood-tests-form.html">Blood Tests</a></li><li><a href="client-food-plan.html">Food Plan</a></li><li><a href="client-medical-history-form.html">Medical History</a></li><li><span class="nav-link-disabled" title="Please contact your Nutritionist to initiate Follow-up">Initiate Follow-up</span></li><li><a href="compare.html?clientId=me" class="active">History</a></li><li><a href="https://sevenpointfourtest.pages.dev/">Website</a></li>`;
            break;
        default:
            return; // No navbar for unknown users
    }

    const navbarHtml = `
        <nav class="navbar">
            <div class="navbar-brand"><a href="${brandLink}">${brandText}</a></div>
            <nav class="navbar-links">
                <ul>
                    ${navLinks}
                    <li><button id="logoutButton" class="nav-logout-btn">Logout</button></li>
                </ul>
            </nav>
        </nav>`;

    navbarContainer.innerHTML = navbarHtml;

    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => handleLogout(userType));
    }
}

/**
 * Fetches the comparison data for a client.
 * It determines the correct authentication token to use based on the user type.
 */
async function fetchData() {
    const urlParams = new URLSearchParams(window.location.search);
    const clientId = urlParams.get('client_id') || urlParams.get('clientId');

    if (!clientId) {
        throw new AuthError("No client ID found in URL. Please ensure the URL is correct (e.g., compare.html?client_id=123).", 'none');
    }

    let token;
    let tokenType = 'none';

    if (clientId === 'me') {
        token = localStorage.getItem('clientToken');
        tokenType = 'client';
    } else if ('adminToken' in localStorage) {
        token = localStorage.getItem('adminToken');
        tokenType = 'admin';
    } else if ('staffToken' in localStorage) {
        token = localStorage.getItem('staffToken');
        tokenType = 'staff';
    }

    if (!token) {
        throw new AuthError("Authentication token not found. Please log in again.", tokenType);
    }

    const res = await fetch(`/api/client/compare/${clientId}`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });

    if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
            throw new AuthError("Your session is invalid or has expired. Please log in again.", tokenType);
        }
        const errorData = await res.json().catch(() => ({}));
        const errorMessage = errorData.message || `Server returned an error (Status: ${res.status})`;
        throw new Error(`Failed to fetch data: ${errorMessage}`);
    }

    return await res.json();
}

async function render() {
    renderNavbar();

    // Add custom styles for different sections to improve readability
    const style = document.createElement('style');
    style.textContent = `
        .present-intake-row { background-color: #d1ecf1; } /* Light blue - darker shade */
        .proposed-structure-row { background-color: #d4edda; } /* Light green - darker shade */
        .additional-points-row { background-color: #fff3cd; } /* Light yellow - darker shade */
    `;
    document.head.appendChild(style);


    // Update page title if being viewed by an admin or staff for a specific client
    const urlParams = new URLSearchParams(window.location.search);
    const clientIdParam = urlParams.get('client_id') || urlParams.get('clientId');
    if (getUserType() !== 'client' && clientIdParam && clientIdParam !== 'me') {
        document.getElementById('page-title').textContent = `Consultation History for Client ID: ${clientIdParam}`;
    }

    const container = document.getElementById('pivot-table-container');

    const showMessage = (message, type = 'info') => {
        container.innerHTML = `<div class="message ${type}">${message}</div>`;
    };

    showMessage('Loading follow-up history...', 'info');

    try {
        let data = await fetchData();

        if (!data || data.length === 0) {
            showMessage('No follow-up history found for this client.', 'info');
            return;
        }

        // --- Enhancements for clarity and correctness ---

        // 1. Identify the date key dynamically from a list of common names.
        const dateKeys = [
            'consultation_date',
            'date',
            'follow_up_date',
            'created_at',
            'updated_at',
            'timestamp',
            'consultationDate',
            'followupDate',
            'dateOfConsultation'
        ];
        const usedDateKey = dateKeys.find(key => data.some(item => item[key]));

        // 2. Sort the data chronologically if a date key was found.
        if (usedDateKey) {
            data.sort((a, b) => {
                let dateAVal = a[usedDateKey];
                let dateBVal = b[usedDateKey];

                // The date value is a string that is itself quoted, e.g. "\"2025-01-01T...\""
                // We need to remove the outer quotes before parsing.
                if (typeof dateAVal === 'string' && dateAVal.startsWith('"') && dateAVal.endsWith('"')) {
                    dateAVal = dateAVal.slice(1, -1);
                }
                if (typeof dateBVal === 'string' && dateBVal.startsWith('"') && dateBVal.endsWith('"')) {
                    dateBVal = dateBVal.slice(1, -1);
                }

                const dateA = new Date(dateAVal);
                const dateB = new Date(dateBVal);
                if (isNaN(dateA.getTime())) return -1; // Invalid dates go first
                if (isNaN(dateB.getTime())) return 1;
                return dateA - dateB;
            });
        }

        // 3. Define keys to exclude from the display. These are typically IDs or metadata not useful for comparison.
        const keysToExclude = new Set([
            'id', 'client_id', 'consultation_id', 'client_consultation_id',
            'created_at', 'updated_at', 'is_latest', 'is_finalized', 'is_food_plan_complete',
            'created_by_admin_id', 'created_by_nutritionist_id',
            'blood_test_results_report_date' // Exclude to prevent it from being rendered as a separate row
        ]);
        if (usedDateKey) {
            keysToExclude.add(usedDateKey);
        }

        const table = document.createElement('table');
        table.classList.add('pivot-table');

        // Create the table header (thead).
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');

        // The first header cell is for the property names column.
        const propertyHeader = document.createElement('th');
        propertyHeader.textContent = 'Property';
        headerRow.appendChild(propertyHeader);

        // The rest of the headers are for each consultation (each item in the data array).
        const columnHeaders = data.map((item, index) => {
            // Prioritize the blood test report date for the header.
            // Fall back to the general consultation date if the blood test date isn't available for a column.
            const bloodTestDate = item['blood_test_results_report_date'];
            let dateValue = bloodTestDate || item['consultation_date'] || (usedDateKey ? item[usedDateKey] : null);

            if (dateValue) {
                try {
                    // The date value can be a string that is itself quoted, e.g. "\"2025-01-01T...\""
                    // We need to remove the outer quotes before parsing.
                    if (typeof dateValue === 'string' && dateValue.startsWith('"') && dateValue.endsWith('"')) {
                        dateValue = dateValue.slice(1, -1);
                    }

                    // Custom date parsing to handle DD-MM-YY format reliably, while falling back for ISO dates.
                    let d = null;
                    // Make the regex more flexible: trim whitespace and don't require the string to end right after the date. It handles DD-MM-YY or DD/MM/YY.
                    const dateParts = typeof dateValue === 'string' ? dateValue.trim().match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{2,4})/) : null;
                    const shortDateParts = typeof dateValue === 'string' ? dateValue.trim().match(/^(\d{2})(\d{2})(\d{2})$/) : null;

                    if (dateParts) {
                        // Handles DD-MM-YY or DD/MM/YY. Assumes DD-MM-YY for ambiguous cases.
                        const day = parseInt(dateParts[1], 10);
                        const month = parseInt(dateParts[2], 10) - 1; // JS months are 0-indexed
                        let year = parseInt(dateParts[3], 10);
                        if (year < 100) {
                            year += 2000; // Assume 21st century for 2-digit years.
                        }
                        d = new Date(year, month, day);
                    } else if (shortDateParts) {
                        // Handles DDMMYY format
                        const day = parseInt(shortDateParts[1], 10);
                        const month = parseInt(shortDateParts[2], 10) - 1; // JS months are 0-indexed
                        let year = parseInt(shortDateParts[3], 10);
                        if (year < 100) { // Should always be true for YY format
                            year += 2000;
                        }
                        d = new Date(year, month, day);
                    } else {
                        // Fallback for ISO 8601 or other standard formats that new Date() can handle.
                        d = new Date(dateValue);
                    }

                    // Check if the date is valid. An invalid date object's time is NaN.
                    if (d && !isNaN(d.getTime())) {
                        const dateString = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
                        if (index === 0) {
                            return `Initial (${dateString})`;
                        }
                        return `Follow-up ${index} (${dateString})`;
                    }
                } catch (e) {
                    // Log error if date parsing fails, and fall through to the default header.
                    console.error(`Error parsing date for header: '${dateValue}'`, e);
                }
            }
            // If a date key/value is not present or invalid, use a generic fallback.
            if (index === 0) {
                return 'Initial';
            }
            return `Follow-up ${index}`;
        });

        columnHeaders.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Create the table body (tbody).
        const tbody = document.createElement('tbody');

        // Helper function to create a row for a specific property, ensuring it exists in the data.
        const createRow = (propKey, displayName, isHtml = false) => {
            // Only create a row if at least one consultation has this property.
            if (data.some(item => item.hasOwnProperty(propKey))) {
                const row = tbody.insertRow();
                const propNameCell = row.insertCell();
                propNameCell.textContent = displayName;
                data.forEach(item => {
                    const valueCell = row.insertCell();
                    const value = item[propKey] !== undefined && item[propKey] !== null ? item[propKey] : '';
                    if (isHtml) {
                        valueCell.innerHTML = value; // Render as HTML
                    } else {
                        valueCell.textContent = value; // Render as plain text
                    }
                });
            }
        };

        // Helper function to create a row that is always displayed, regardless of data presence.
        const createGuaranteedRow = (propKey, displayName, className) => {
            const row = tbody.insertRow();
            if (className) {
                row.classList.add(className);
            }
            const propNameCell = row.insertCell();
            propNameCell.textContent = displayName;
            data.forEach(item => {
                const valueCell = row.insertCell();
                const value = item[propKey];
                valueCell.textContent = value !== undefined && value !== null ? value : '';
            });
        };

        // --- Render sections in a specific order ---

        // 1. Render all blood test sections and tests from the definition file.
        // This ensures all blood test fields appear, even if empty.
        for (const sectionKey in bloodTestDefinitions) {
            const section = bloodTestDefinitions[sectionKey];
            const sectionTitleRow = tbody.insertRow();
            sectionTitleRow.innerHTML = `<th colspan="${data.length + 1}" class="section-title">${section.title}</th>`;

            section.tests.forEach(testDef => {
                const propKey = `blood_test_results_value_${testDef.key}`;
                const row = tbody.insertRow();

                const propNameCell = row.insertCell();
                propNameCell.textContent = testDef.name; // Use the readable name from definition

                data.forEach(item => {
                    const valueCell = row.insertCell();
                    // Use the generated propKey to find the value in the data item
                    valueCell.textContent = item[propKey] !== undefined && item[propKey] !== null ? item[propKey] : '';
                });
            });
        }

        // 2. Client & Nutritionist Conversation Section
        const conversationSectionTitleRow = tbody.insertRow();
        conversationSectionTitleRow.innerHTML = `<th colspan="${data.length + 1}" class="section-title">Client & Nutritionist Notes</th>`;
        createRow('health_issues', 'Health Details');
        createRow('additional_personal_recommendations', 'Nutritionist Personal Recommendations', true);


        // 3. Food Plan Details Section
        const foodPlanSectionTitleRow = tbody.insertRow();
        foodPlanSectionTitleRow.innerHTML = `<th colspan="${data.length + 1}" class="section-title food-plan-title">Food Plan Details</th>`;

        // Generate hours from 6 AM to 5 AM next day
        const hours = [];
        for (let i = 6; i < 24; i++) hours.push(i); // 6 AM to 11 PM
        for (let i = 0; i < 6; i++) hours.push(i);  // 12 AM to 5 AM

        // --- Present Intake ---
        const presentIntakeSubHeader = tbody.insertRow();
        presentIntakeSubHeader.innerHTML = `<th colspan="${data.length + 1}" class="section-subtitle">Present Intake</th>`;
        hours.forEach(hour => {
            const hourString = hour.toString().padStart(2, '0');
            const propKey = `food_plan_hourly_details_present_intake_${hourString}:00`;
            createGuaranteedRow(propKey, `${hourString}:00`, 'present-intake-row');
        });

        // --- Proposed Structure ---
        const proposedStructureSubHeader = tbody.insertRow();
        proposedStructureSubHeader.innerHTML = `<th colspan="${data.length + 1}" class="section-subtitle">Proposed Structure</th>`;
        hours.forEach(hour => {
            const hourString = hour.toString().padStart(2, '0');
            const propKey = `food_plan_hourly_details_proposed_structure_${hourString}:00`;
            createGuaranteedRow(propKey, `${hourString}:00`, 'proposed-structure-row');
        });

        // 4. Additional Points Section
        const additionalPointsSectionTitleRow = tbody.insertRow();
        additionalPointsSectionTitleRow.innerHTML = `<th colspan="${data.length + 1}" class="section-title">Additional Points</th>`;
        hours.forEach(hour => {
            const hourString = hour.toString().padStart(2, '0');
            const propKey = `food_plan_hourly_details_additional_points_${hourString}:00`;
            createGuaranteedRow(propKey, `${hourString}:00`, 'additional-points-row');
        });

        table.appendChild(tbody);

        container.innerHTML = ''; // Clear "Loading..." or any other message
        container.appendChild(table);

    } catch (error) {
        if (error instanceof AuthError) {
            showMessage(`${error.message} Redirecting...`, 'error');
            setTimeout(() => {
                handleLogout(error.tokenType);
            }, 2500);
        } else {
            console.error('Error rendering follow-up data:', error);
            showMessage(error.message, 'error');
        }
    }
}

render();