document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();
});
// --- Fetch data from Backend API ---
async function fetchDashboardData() {
    try {
        const response = await fetch('http://127.0.0.1:8000/dashboard/stats');
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        populateDashboard(data);
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        // Display error message to the user
        const errorElement = document.getElementById('error-message') || document.createElement('div');
        errorElement.id = 'error-message';
        errorElement.textContent = 'Failed to load dashboard data. Please ensure the backend server is running.';
        errorElement.style.color = 'red';
        // Make sure the main content area exists before inserting
        const mainContainer = document.querySelector('.dashboard-container');
        if(mainContainer){
            mainContainer.insertBefore(errorElement, mainContainer.firstChild);
        } else {
            document.body.insertBefore(errorElement, document.body.firstChild);
        }
    }
}

// --- Populate Dashboard with Fetched Data ---
function populateDashboard(data) {
    // Overall Stats
    document.getElementById('total-emails').textContent = data.total_emails !== null ? data.total_emails : 'N/A';
    document.getElementById('phishing-count').textContent = data.phishing_count !== null ? data.phishing_count : 'N/A';
    document.getElementById('suspicious-count').textContent = data.suspicious_count !== null ? data.suspicious_count : 'N/A';
    document.getElementById('safe-count').textContent = data.safe_count !== null ? data.safe_count : 'N/A';

    // Render Charts
    renderMonthlyTrendsChart(data.monthly_trends || []);
    renderCommonWordsChart(data.common_words || []);

    // Render Analysis History Table
    renderAnalysisHistory(data.analysis_history || []);
}

// --- Chart Rendering Functions ---
let monthlyTrendsChartInstance = null; // Keep track of chart instance
function renderMonthlyTrendsChart(trends) {
    const ctx = document.getElementById('monthlyTrendsChart')?.getContext('2d');
    if (!ctx) {
        console.error("Canvas context for 'monthlyTrendsChart' not found.");
        return;
    }

    // Destroy previous chart instance if it exists
    if (monthlyTrendsChartInstance) {
        monthlyTrendsChartInstance.destroy();
    }

    const labels = trends.map(item => item.month);
  const phishingData = trends.map(item => item.phishing);
  const safeData = trends.map(item => item.safe);
  
    monthlyTrendsChartInstance = new Chart(ctx, {
        type: 'line',
    data: {
            labels: labels,
      datasets: [
        {
                    label: 'Phishing Emails',
          data: phishingData,
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    fill: true,
                    tension: 0.1
                },
                {
                    label: 'Safe Emails',
          data: safeData,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    fill: true,
                    tension: 0.1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true
        }
      },
      plugins: {
        legend: {
          position: 'bottom'
        }
      }
    }
  });
}

let commonWordsChartInstance = null; // Keep track of chart instance
function renderCommonWordsChart(words) {
    const ctx = document.getElementById('commonWordsChart')?.getContext('2d');
    if (!ctx) {
        console.error("Canvas context for 'commonWordsChart' not found.");
        return;
    }

    // Destroy previous chart instance if it exists
    if (commonWordsChartInstance) {
        commonWordsChartInstance.destroy();
    }

    const labels = words.map(item => item.word);
    const counts = words.map(item => item.count);

    commonWordsChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Frequency in Phishing Emails',
                data: counts,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(255, 206, 86, 0.6)',
                    'rgba(75, 192, 192, 0.6)',
                    'rgba(153, 102, 255, 0.6)',
                    'rgba(255, 159, 64, 0.6)',
                    'rgba(199, 199, 199, 0.6)', // Added more colors
                    'rgba(83, 102, 255, 0.6)',
                    'rgba(255, 159, 244, 0.6)',
                    'rgba(159, 255, 164, 0.6)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 159, 64, 1)',
                    'rgba(199, 199, 199, 1)',
                    'rgba(83, 102, 255, 1)',
                    'rgba(255, 159, 244, 1)',
                    'rgba(159, 255, 164, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false // Hide legend for bar chart if desired
                },
                title: { // Add a title to the chart
                    display: true,
                    text: 'Top 10 Common Suspicious Words'
                }
            }
        }
    });
}

// --- Analysis History Table Rendering ---
function renderAnalysisHistory(history) {
    const historyTableBody = document.getElementById('analysis-history-body');
    if (!historyTableBody) {
        console.error("Element with ID 'analysis-history-body' not found.");
        return;
    }
    historyTableBody.innerHTML = ''; // Clear existing rows

    if (!history || history.length === 0) {
        historyTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No analysis history found.</td></tr>';
    return;
  }
  
    history.forEach(item => {
        const row = historyTableBody.insertRow();

        const cellTimestamp = row.insertCell();
        const cellSender = row.insertCell();
        const cellSubject = row.insertCell();
        const cellRisk = row.insertCell();
        const cellProbability = row.insertCell();
        const cellDownload = row.insertCell(); // Add cell for download button

        try {
            cellTimestamp.textContent = new Date(item.timestamp).toLocaleString();
        } catch (e) {
            cellTimestamp.textContent = item.timestamp; // Fallback if date is invalid
        }
        cellSender.textContent = item.sender || 'N/A';
        cellSubject.textContent = item.subject || 'N/A';

        // Determine risk level based on score (adjusted probability)
        let riskLevel = 'Safe';
        let riskColor = 'text-green-600'; // Ensure these Tailwind classes are in styles.css
        if (item.risk_score >= 0.75) { // Use 0.75 threshold
            riskLevel = 'Phishing';
            riskColor = 'text-red-600';
        } else if (item.risk_score >= 0.4) { // Use 0.4 threshold
            riskLevel = 'Suspicious';
            riskColor = 'text-yellow-600';
        }
        // Display the determined level and the original score (probability)
        const scoreText = typeof item.risk_score === 'number' ? item.risk_score.toFixed(2) : 'N/A';
        cellRisk.innerHTML = `<span class="${riskColor} font-semibold">${riskLevel} (${scoreText})</span>`;

        // Probability is now the same as risk_score in the DB, format as percentage
        const probabilityText = typeof item.risk_score === 'number' ? (item.risk_score * 100).toFixed(1) + '%' : 'N/A';
        cellProbability.textContent = probabilityText;

        // Add download button/icon
        cellDownload.innerHTML = `<button class="download-btn" data-id="${item.id}" title="Download PDF Report"><i class="fas fa-file-pdf"></i></button>`;
        cellDownload.style.textAlign = 'center'; // Center the icon

        // Remove row click listener if download button is used instead
        // row.style.cursor = 'pointer'; // Example: indicate clickable row
        // row.addEventListener('click', () => {
        //     // Maybe show full details in a modal or navigate somewhere
        //     console.log('Clicked analysis item ID:', item.id);
        // });
    });

    // --- Add event listener for download buttons (using event delegation) ---
    historyTableBody.addEventListener('click', function(event) {
        const target = event.target.closest('.download-btn'); // Find the button element
        if (target) {
            const analysisId = target.getAttribute('data-id');
            console.log(`Download requested for analysis ID: ${analysisId}`);
            fetchAnalysisDetailsAndGeneratePDF(analysisId);
        }
    });
}

// --- New function to fetch details and generate PDF ---
async function fetchAnalysisDetailsAndGeneratePDF(analysisId) {
    if (!analysisId) {
        console.error("Invalid analysis ID for PDF generation.");
        alert("Error: Could not generate PDF due to invalid ID.");
        return;
    }
    try {
        // We need a new backend endpoint to fetch full details by ID
        const response = await fetch(`http://127.0.0.1:8000/analysis/${analysisId}`);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const fullAnalysisData = await response.json();

        // Now call the existing generatePDF function from results.js
        // Ensure generatePDF is accessible (might need to move it to a shared utility file or duplicate)
        generatePDF(fullAnalysisData);

    } catch (error) {
        console.error('Error fetching analysis details for PDF:', error);
        alert('Failed to fetch analysis details needed for the PDF report. Please try again.');
    }
}

// --- PDF Generation Function (Copied from results.js for now) ---
// Ideally, this should be in a shared utility file to avoid duplication
function generatePDF(data) {
    const { jsPDF } = window.jspdf; // Ensure jsPDF is accessible
    if (!jsPDF) {
        console.error("jsPDF library not loaded!");
        alert("Error: Could not generate PDF. jsPDF library missing.");
        return;
    }
    
    // Document setup and constants definition
    const doc = new jsPDF('p', 'mm', 'a4');
    const pageWidth = doc.internal.pageSize.width;
    const pageHeight = doc.internal.pageSize.height;
    const margin = 20;
    const contentWidth = pageWidth - (margin * 2);
    let yPos = margin;
    
    // Define colors
    const headerColor = [41, 128, 185]; // Blue
    const titleColor = [44, 62, 80]; // Dark slate
    const labelColor = [52, 73, 94]; // Dark blueish
    const valueColor = [0, 0, 0]; // Black
    const lineColor = [189, 195, 199]; // Light gray
    const metaBgColor = [240, 240, 240]; // Light gray background
    const positiveBgColor = [240, 255, 240]; // Light green background
    const positiveTextColor = [0, 100, 0]; // Dark green text
    
    // Define risk colors
    const riskColors = {
        'Safe': [0, 128, 0], // Green
        'Suspicious': [255, 165, 0], // Orange
        'Phishing': [220, 20, 60], // Crimson
        'Unknown': [128, 128, 128] // Gray
    };
    
    // Define date string
    const today = new Date();
    const dateString = today.toLocaleDateString();
    
    // Helper function: Add header and footer to current page
    function addHeaderFooter() {
        // Header
        doc.setFillColor(...headerColor);
        doc.rect(0, 0, pageWidth, 15, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('PhishGuard Email Analysis Report', margin, 10);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.text(dateString, pageWidth - margin, 10, { align: 'right' });
        
        // Reset for content
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(12);
        doc.setFont('helvetica', 'normal');
    }
    
    // Helper function: Check if we need a new page based on current position
    function checkNewPage(currentY, requiredSpace) {
        if (currentY + requiredSpace > pageHeight - 20) {
            doc.addPage();
            addHeaderFooter();
            return margin + 15; // Reset Y position below header
        }
        return currentY;
    }
    
    // Helper function: Add text with options
    function addText(text, y, options = {}) {
        const defaultOptions = {
            fontSize: 11,
            fontStyle: 'normal',
            x: margin,
            maxWidth: contentWidth
        };
        
        // Handle legacy function signature (text, y, fontSize, fontStyle)
        if (typeof options === 'number') {
            options = { 
                fontSize: options,
                fontStyle: arguments[3] || 'normal'
            };
        }
        
        const opts = { ...defaultOptions, ...options };
        
        doc.setFontSize(opts.fontSize);
        doc.setFont('helvetica', opts.fontStyle);
        
        // Make sure text is a string
        const textStr = String(text);
        
        // Get max width
        const textLines = doc.splitTextToSize(textStr, opts.maxWidth);
        
        // Calculate line height based on font size (rough approximation)
        const lineHeight = opts.fontSize * 0.352; // mm per point
        
        // Draw each line
        let newY = y;
        for (let i = 0; i < textLines.length; i++) {
            doc.text(textLines[i], opts.x, newY);
            newY += lineHeight;
        }
        
        // Return the new Y position plus standard spacing
        return newY + 2;
    }
    
    // Helper function: Add horizontal line
    function addLine(y) {
        doc.setDrawColor(...lineColor);
        doc.line(margin, y, pageWidth - margin, y);
        return y + 2;
    }

    // --- PDF Generation Start ---
    addHeaderFooter(); // Add to first page
    yPos = margin + 15; // Start below header

    // --- Risk Score section ---
    // (This part needs the full data structure, assuming it's like results.js expects)
    yPos = checkNewPage(yPos, 40);
    let riskColor = [128, 128, 128]; // Default gray
    let riskText = 'Risk assessment data unavailable';
    let riskScoreValue = 'N/A';

    // The data structure from /analysis/{id} might differ slightly from localStorage
    // We need to adapt based on what the new endpoint returns.
    // Assuming it returns a structure similar to the original report for now:
    const fetchedRiskScore = data.risk_score; // Adjust based on actual API response
    const fetchedEmailDetails = data.email_details; // Adjust
    const fetchedAnalysis = data.analysis; // Adjust

    if (fetchedRiskScore && typeof fetchedRiskScore === 'object' && fetchedRiskScore.level) {
        riskScoreValue = fetchedRiskScore.score !== undefined ? `${fetchedRiskScore.score}%` : 'N/A';
        switch (fetchedRiskScore.level) {
            case 'Safe': riskColor = [0, 128, 0]; riskText = 'This email appears to be safe'; break;
            case 'Suspicious': riskColor = [255, 165, 0]; riskText = 'This email contains suspicious elements'; break;
            case 'Phishing': riskColor = [220, 20, 60]; riskText = 'This email is likely a phishing attempt'; break;
            default: riskText = 'Risk level could not be determined';
        }
    } else if (typeof fetchedRiskScore === 'number') { // Handle if only score (probability) is returned
         riskScoreValue = (fetchedRiskScore * 100).toFixed(1) + '%';
         if (fetchedRiskScore >= 0.75) { riskColor = [220, 20, 60]; riskText = 'This email is likely a phishing attempt'; }
         else if (fetchedRiskScore >= 0.4) { riskColor = [255, 165, 0]; riskText = 'This email contains suspicious elements'; }
         else { riskColor = [0, 128, 0]; riskText = 'This email appears to be safe'; }
    }

    yPos = addText('Risk Assessment', yPos, 14, 'bold');
    const scoreX = margin + 20, scoreY = yPos + 15, scoreRadius = 12;
    doc.setFillColor(...riskColor);
    doc.circle(scoreX, scoreY, scoreRadius, 'F');
    doc.setTextColor(255, 255, 255); doc.setFontSize(10);
    doc.text(riskScoreValue, scoreX, scoreY + 3, { align: 'center' });
    doc.setTextColor(0, 0, 0); doc.setFontSize(12);
    doc.text(riskText, scoreX + scoreRadius + 10, scoreY + 4);
    yPos = scoreY + scoreRadius + 10;

    // --- Email Metadata section ---
    yPos = checkNewPage(yPos, 40);
    yPos = addText('Email Details', yPos, 14, 'bold');
    const metadata = fetchedEmailDetails || {};
    doc.setDrawColor(220, 220, 220); doc.setFillColor(240, 240, 240);
    doc.roundedRect(margin, yPos, contentWidth, 30, 2, 2, 'FD');
    yPos += 6;
    doc.setFontSize(10); doc.setFont('helvetica', 'bold'); doc.text('From:', margin + 5, yPos); doc.setFont('helvetica', 'normal'); doc.text(metadata.sender || 'Unknown', margin + 25, yPos);
    yPos += 8;
    doc.setFont('helvetica', 'bold'); doc.text('Subject:', margin + 5, yPos); doc.setFont('helvetica', 'normal'); doc.text(metadata.subject || 'No Subject', margin + 25, yPos);
    yPos += 8;
    doc.setFont('helvetica', 'bold'); doc.text('Date:', margin + 5, yPos); doc.setFont('helvetica', 'normal'); doc.text(metadata.timestamp || 'Unknown', margin + 25, yPos);
    yPos += 12;

    // --- Suspicious Elements section ---
    yPos = checkNewPage(yPos, 60);
    const elements = fetchedAnalysis?.suspicious_elements || {};
    const hasElements = Object.values(elements).some(val => Array.isArray(val) && val.length > 0);
    yPos = addText('Detected Suspicious Elements', yPos, 14, 'bold');
    if (!hasElements) {
        yPos = addText('No suspicious elements detected in this email.', yPos);
    } else {
        const categories = [
            { name: 'Urgent Language', items: elements.urgent_language }, { name: 'Sensitive Information Requests', items: elements.sensitive_requests },
            { name: 'Suspicious Senders', items: elements.suspicious_senders }, { name: 'Suspicious URLs', items: elements.suspicious_urls },
            { name: 'Language/Grammar Issues', items: elements.language_issues }
        ];
        for (const category of categories) {
            if (category.items && category.items.length > 0) {
                yPos = checkNewPage(yPos, 15 + (category.items.length * 5));
                yPos = addText(category.name + ':', yPos, 12, 'bold');
                category.items.forEach(item => {
                    yPos = checkNewPage(yPos, 8);
                    
                    const bulletPoint = '\u2022';
                    const itemIndent = 4; // Indentation from margin for item text (mm)
                    const bulletX = margin;
                    const itemX = margin + itemIndent;
                    const itemMaxWidth = contentWidth - itemIndent;

                    // Add bullet point (using addText to keep styling consistent, but only for one line)
                    // We don't actually need the returned yPos from the bullet point draw
                    addText(bulletPoint, yPos, { fontSize: 10, x: bulletX, maxWidth: itemIndent }); 

                    // Add item text, indented, letting addText handle wrapping and return the new yPos
                    yPos = addText(item, yPos, { fontSize: 10, x: itemX, maxWidth: itemMaxWidth });
                });
                yPos += 5; // Add space after the category list
            }
        }
    }

    // --- Positive Signals ---
    yPos = checkNewPage(yPos, 40);
    const positiveSignals = fetchedAnalysis?.positive_signals;
    if (positiveSignals && positiveSignals.length > 0) {
        yPos = addText('Positive Signals', yPos, 14, 'bold');
        doc.setFillColor(240, 255, 240);
        let boxHeight = 5;
        positiveSignals.forEach(signal => { const lines = doc.splitTextToSize('\u2022 ' + signal, contentWidth - 10); boxHeight += lines.length * (10 * 0.352) + 3; });
        doc.roundedRect(margin, yPos, contentWidth, boxHeight, 2, 2, 'F');
        yPos += 5;
        doc.setTextColor(0, 100, 0);
        positiveSignals.forEach(signal => { yPos = checkNewPage(yPos, 8); yPos = addText('\u2022 ' + signal, yPos, 10); });
        doc.setTextColor(0, 0, 0);
        yPos += 5;
    }

    // --- Analysis Summary ---
    yPos = checkNewPage(yPos, 60);
    yPos = addText('Analysis Summary', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    // (Restored summary text generation logic)
    let summaryText = '';
     // Use the fetched data structure for consistency
     const riskLevelData_summary = data.risk_score; // Renamed
     const analysisData_summary = data.analysis; // Renamed
     const elements_summary = analysisData_summary?.suspicious_elements || {}; // Renamed
     const hasElements_summary = Object.values(elements_summary).some(val => Array.isArray(val) && val.length > 0); // Renamed
     const positiveSignals_summary = analysisData_summary?.positive_signals; // Renamed

     if (riskLevelData_summary && typeof riskLevelData_summary === 'object' && riskLevelData_summary.level) {
         const riskLevel_summary = riskLevelData_summary.level; // Renamed
         if (riskLevel_summary === 'Phishing') {
             summaryText = 'This email has been identified as a likely phishing attempt. ';
             if (hasElements_summary) {
                 summaryText += 'Multiple suspicious elements were detected including: ';
                 const allSuspicious = [
                     ...(elements_summary.urgent_language || []),
                     ...(elements_summary.sensitive_requests || []),
                     ...(elements_summary.suspicious_urls ? ['suspicious links'] : []),
                     ...(elements_summary.suspicious_senders ? ['sender issues'] : []),
                     ...(elements_summary.language_issues ? ['grammar problems'] : [])
                 ];
                 summaryText += allSuspicious.slice(0, 3).join(', ') + '.';
             }
             summaryText += ' We recommend deleting this email and not interacting with any links or attachments it contains.';
         } else if (riskLevel_summary === 'Suspicious') {
             summaryText = 'This email contains some suspicious elements that warrant caution. ';
             if (hasElements_summary) {
                 summaryText += 'Potentially concerning elements include: ';
                 const allSuspicious = [
                     ...(elements_summary.urgent_language || []),
                     ...(elements_summary.sensitive_requests || []),
                     ...(elements_summary.suspicious_urls ? ['suspicious links'] : []),
                     ...(elements_summary.suspicious_senders ? ['sender issues'] : []),
                     ...(elements_summary.language_issues ? ['grammar problems'] : [])
                 ];
                 summaryText += allSuspicious.slice(0, 2).join(', ') + '.';
             }
             summaryText += ' Exercise caution when dealing with this email, and verify its legitimacy through alternative means if possible.';
         } else { // Safe
             summaryText = 'This email appears to be legitimate. ';
             if (positiveSignals_summary && positiveSignals_summary.length > 0) {
                 summaryText += 'The following positive signals were detected: ' + positiveSignals_summary.slice(0, 2).join(', ') + '. ';
             }
             summaryText += 'Our analysis suggests this is a safe email, though you should always maintain standard security practices.';
         }
     } else {
         summaryText = "Analysis summary could not be generated due to missing risk assessment data.";
     }
    yPos = addText(summaryText, yPos, { fontSize: 10 });
    yPos += 5;

    // --- Email Content Preview ---
    yPos = checkNewPage(yPos, 40);
    yPos = addText('Email Content Preview', yPos, 14, 'bold');
    let bodyText = fetchedAnalysis?.highlighted_body || '';
    const tempDiv = document.createElement('div'); tempDiv.innerHTML = bodyText;
    bodyText = tempDiv.textContent || tempDiv.innerText || '';
    if (bodyText.length > 400) { bodyText = bodyText.substring(0, 400) + '...'; }
    const bodyLines = doc.splitTextToSize(bodyText, contentWidth - 10);
    const bodyBoxHeight = Math.max(50, 10 + bodyLines.length * (9 * 0.352) + 5);
    doc.setDrawColor(200, 200, 200); doc.setFillColor(250, 250, 250);
    doc.roundedRect(margin, yPos, contentWidth, bodyBoxHeight, 2, 2, 'FD');
    yPos += 5;
    yPos = addText(bodyText, yPos, 9);
    yPos += bodyBoxHeight - (5 + bodyLines.length * (9 * 0.352));

    // --- Footer ---
    const totalPages = doc.internal.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i); doc.setFontSize(8); doc.setTextColor(100, 100, 100);
        doc.text(`Page ${i} of ${totalPages} | Phishing Email Analysis | Confidential`, pageWidth / 2, 290, { align: 'center' });
    }

    // --- Save the PDF ---
    const safeSubject = (metadata.subject || 'NoSubject').replace(/[^a-z0-9]/gi, '_').substring(0, 30);
    const fileName = `Phishing_Analysis_${safeSubject}_${dateString.replace(/\//g, '-')}.pdf`;
    doc.save(fileName);
}