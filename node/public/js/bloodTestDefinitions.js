// Define the test structure for the admin view (similar to client-blood-tests-form.html)
const bloodTestDefinitions = {
    cbc: {
        title: 'COMPLETE BLOOD COUNT (CBC)',
        tests: [
            { key: 'hemoglobin', name: 'HEMOGLOBIN', range: 'M= 13.5-18 GM/DL; F=12-16.8 GM/DL' },
            { key: 'total_wbc', name: 'TOTAL WBC', range: '4000-11000 /CMM' },
            { key: 'total_rbc', name: 'TOTAL RBC', range: '4.5-6 MIL/CMM' },
            { key: 'platelet', name: 'PLATELET', range: '150000-450000 /CMM' },
            { key: 'pcv', name: 'PCV', range: 'M - 40 TO 50 , F - 36 TO 46' },
            { key: 'mcv', name: 'MCV', range: '83 TO 101 FL' },
            { key: 'mch', name: 'MCH', range: '27-32 PG' },
            { key: 'mchc', name: 'MCHC', range: '32-36% G/DL' },
            { key: 'rdw', name: 'RDW', range: '11.5-14%' },
            { key: 'eosinophils', name: 'EOSINOPHILS', range: '0 - 6' }
        ]
    },
    diabetes: {
        title: 'DIABETES INDICATORS',
        tests: [
            { key: 'fasting_glucose', name: 'FASTING BLOOD GLUCOSE', range: '70-110 MG/DL' },
            { key: 'fasting_insulin', name: 'FASTING INSULIN', range: '2.6-37.6 MICRO U/ML' },
            { key: 'hba1c_hplc', name: 'HbA 1 C (HPLC)', range: '&lt;/= 6.0 % OF TOTAL Hb' },
            { key: 'hba1c_ifcc', name: 'HbA 1 C (IFCC) (HPLC)', range: '&lt;/= 42MMOL/MOL' },
            { key: 'avg_plasma_glucose', name: 'AVG. PLASMA GLUCOSE OF LAST 3 MONTHS (CALC)', range: '80-140 MG/DL' }
        ]
    },
    kft: {
        title: 'KIDNEY FUNCTION TESTS (KFT)',
        tests: [
            { key: 'uric_acid', name: 'URIC ACID', range: 'M-3.5 TO 7.2, F - 2.6 TO 6' },
            { key: 'bun', name: 'BLOOD UREA NITROGEN ( BUN)', range: 'MG/DL 7.9 TO 20' },
            { key: 's_creatinine', name: 'S. CREATININE', range: 'M= 0.4-1.4 MG/DL; F= 0.2-1.2 MG/DL' },
            { key: 'bun_creatinine_ratio', name: 'BUN / S CREATININE RATIO', range: '9.1 TO 23.1' },
            { key: 'sodium', name: 'SODIUM', range: 'MMOL/L 136-146' },
            { key: 'chloride', name: 'CHLORIDE', range: 'MMOL/L 98 - 106' },
            { key: 'egfr', name: 'ESTIMATED GLOMERULAR FILTERATION RATE', range: '&gt;90, 60-90,45-59,30 -44, 15,29' }
        ]
    },
    lft: {
        title: 'LIVER FUNCTION TESTS (LFT)',
        tests: [
            { key: 's_bilirubin_total', name: 'S. BILIRUBIN TOTAL', range: '0.2-1.2 MG/DL' },
            { key: 's_bilirubin_direct', name: 'S. BILIRUBIN DIRECT', range: '0.0-0.4 MG/DL' },
            { key: 's_bilirubin_indirect', name: 'S. BILIRUBIN INDIRECT', range: '0.2-0.8 MG/DL' },
            { key: 'sgpt_alt', name: 'SGPT (ALT)', range: '0-45 U/L' },
            { key: 'sgot_ast', name: 'SGOT (AST)', range: '0-45 U/L' },
            { key: 's_alkaline_phosphatase', name: 'S. ALKALINE PHOSPHATASE', range: '40-129 U/L' },
            { key: 's_total_protein', name: 'S. TOTAL PROTEIN', range: '6.4-8.3 G/DL' },
            { key: 's_albumin', name: 'S. ALBUMIN', range: '3.5-5.0 G/DL' },
            { key: 's_globulin', name: 'S. GLOBULIN', range: '2.3-3.4 G/DL' },
            { key: 's_ag_ratio', name: 'S. A/G RATIO', range: '1.0-2.0' }
        ]
    },
    lipid: {
        title: 'LIPID PROFILE',
        tests: [
            { key: 's_cholesterol_total', name: 'S. CHOLESTEROL TOTAL', range: 'UPTO 200 MG/DL' },
            { key: 's_triglycerides', name: 'S. TRIGLYCERIDES', range: 'UPTO 150 MG/DL' },
            { key: 's_hdl_cholesterol', name: 'S. HDL CHOLESTEROL', range: 'M=35-55, F=40-60 MG/DL' },
            { key: 's_ldl_cholesterol', name: 'S. LDL CHOLESTEROL', range: 'UPTO 130 MG/DL' },
            { key: 's_vldl_cholesterol', name: 'S. VLDL CHOLESTEROL', range: '5-40 MG/DL' },
            { key: 's_hdl_ratio', name: 'S. HDL RATIO', range: 'UPTO 4.5' }
        ]
    },
    inflammation: {
        title: 'INFLAMMATION MARKERS',
        tests: [
            { key: 'hs_crp', name: 'HS-CRP', range: '<1.0 MG/L (LOW RISK), 1.0-3.0 MG/L (AVERAGE RISK), >3.0 MG/L (HIGH RISK)' }
        ]
    },
    vitamind3: {
        title: 'VITAMIN D3',
        tests: [
            { key: 's_vitamin_d3', name: 'S. VITAMIN D3', range: '30-100 NG/ML' }
        ]
    },
    vitaminb12: {
        title: 'VITAMIN B12',
        tests: [
            { key: 's_vitamin_b12', name: 'S. VITAMIN B12', range: '211-911 PG/ML' }
        ]
    },
    testosterone: {
        title: 'TESTOSTERONE',
        tests: [
            { key: 's_testosterone', name: 'S. TESTOSTERONE', range: 'M=249-836 NG/DL, F=8-60 NG/DL' }
        ]
    },
    thyroid: {
        title: 'THYROID FUNCTION TEST',
        tests: [
            { key: 't3', name: 'T3', range: 'NG/DL 60 TO 200' },
            { key: 't4', name: 'T4', range: 'MUG/DL 4.5 TO 12' },
            { key: 'tsh', name: 'TSH', range: 'MIU/ML  0.3 TO 5.5' }
        ]
    }
};

function buildReportsTable(reportData) {
    // Use a Map for efficient lookup of test results by test_code
    const resultsMap = new Map((reportData.results || []).map(r => [r.test_code, r]));
    console.log("Results Map created, size:", resultsMap.size);

    // Create the table structure
    const table = document.createElement('table');
    table.id = 'bloodTestsTable'; // For CSS targeting
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);

    // Populate the main generic header
    const mainHeaderRow = thead.insertRow();
    mainHeaderRow.innerHTML = `
                    <th>Test Name</th>
                    <th>Normal Range</th>
                    <th>Date 1</th>
                    <th>Date 2</th>
                    <th>Date 3</th>
                    <th>Date 4</th>
                    <th>Date 5</th>
                `;

    let cbcSubHeaderAdded = false; // Flag to ensure CBC subheader is added only once

    // Iterate through defined test sections and tests
    for (const sectionKey in bloodTestDefinitions) {
        const section = bloodTestDefinitions[sectionKey];

        // Add CBC specific subheader if this is the CBC section and it hasn't been added
        if (sectionKey === 'cbc' && !cbcSubHeaderAdded) {
            const cbcHeaderRow = tbody.insertRow();
            cbcHeaderRow.classList.add('cbc-admin-subheader-row'); // Use the correct CSS class
            let cbcSubHeaderHTML = `<th colspan="2">${escapeHtml(section.title)}</th>`; // Title spans 2 columns

            // Add date cells with specific DD/MM/YY format
            const dateValue = reportData[`report_date`];
            const formattedDate = dateValue
                ? (() => {
                    const d = new Date(dateValue);
                    const year = String(d.getFullYear()).slice(-2);
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    return escapeHtml(`${day}/${month}/${year}`); // DD/MM/YY format
                })()
                : '&nbsp;'; // Use &nbsp; for empty dates
            cbcSubHeaderHTML += `<th>${formattedDate}</th>`;
            cbcHeaderRow.innerHTML = cbcSubHeaderHTML; // Assign the complete HTML string
            cbcSubHeaderAdded = true; // Set flag
        } else if (sectionKey !== 'cbc') { // Only add generic title row for non-CBC sections
            // Add section title row
            const sectionTitleRow = tbody.insertRow();
            sectionTitleRow.classList.add('test-section-title-row'); // Use existing class for styling
            const titleCell = sectionTitleRow.insertCell();
            titleCell.colSpan = 7; // Span all 7 columns
            titleCell.outerHTML = `<th colspan="7">${escapeHtml(section.title)}</th>`; // Use th for section titles
        }

        // Add individual test rows
        section.tests.forEach(testDef => {
            const clientResult = resultsMap.get(testDef.key); // Efficiently get the result for this test

            const testRow = tbody.insertRow();
            testRow.innerHTML = `
                            <td>${escapeHtml(testDef.name)}</td>
                            <td>${testDef.range ? escapeHtml(testDef.range) : 'N/A'}</td>
                            <td>${clientResult?.value ?? 'N/A'}</td>
                            <td>${clientResult?.value_d2 ?? 'N/A'}</td>
                            <td>${clientResult?.value_d3 ?? 'N/A'}</td>
                            <td>${clientResult?.value_d4 ?? 'N/A'}</td>
                            <td>${clientResult?.value_d5 ?? 'N/A'}</td>
                        `;
        });
    }
    return table;
}

// Helper function to escape HTML for security
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe; // Return non-strings as is
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

