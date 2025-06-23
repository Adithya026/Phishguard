document.addEventListener('DOMContentLoaded', function() {
    // Retrieve analysis result from localStorage
    const resultData = JSON.parse(localStorage.getItem('analysis-result'));
    
    if (!resultData) {
        window.location.href = 'index.html';
        return;
    }
    
    // Tab switching functionality
    const tabBtns = document.querySelectorAll('.analysis-tab');
    const tabContents = document.querySelectorAll('.analysis-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            // Remove active class from all tabs
            tabBtns.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to current tab
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Populate the analysis result
    populateRiskScore(resultData.risk_score);
    populateEmailMetadata(resultData.email_details);
    populateEmailBody(resultData.analysis.highlighted_body);
    populateSuspiciousElements(resultData.analysis.suspicious_elements);
    createVisualizations(resultData);
    
    // Download report button
    const downloadButton = document.getElementById('download-report');
    if (downloadButton) {
        downloadButton.addEventListener('click', function() {
            console.log("Download report button clicked");
            if (resultData) {
        generatePDF(resultData);
            } else {
                console.error("Cannot generate PDF: resultData is missing.");
                alert("Error: Analysis data is missing, cannot generate PDF.");
            }
    });
    } else {
        console.error("Button with ID 'download-report' not found.");
    }
});

function populateRiskScore(riskScore) {
    const riskScoreElement = document.getElementById('risk-score');
    let riskClass = '';
    let riskText = '';
    
    switch (riskScore.level) {
        case 'Safe':
            riskClass = 'safe';
            riskText = 'This email appears to be safe';
            break;
        case 'Suspicious':
            riskClass = 'suspicious';
            riskText = 'This email contains suspicious elements';
            break;
        case 'Phishing':
            riskClass = 'phishing';
            riskText = 'This email is likely a phishing attempt';
            break;
    }
    
    riskScoreElement.innerHTML = `
        <div class="${riskClass}">
            <h2>Risk Assessment</h2>
            <div class="score-display">${riskScore.score}%</div>
            <p>${riskText}</p>
        </div>
    `;
}

function populateEmailMetadata(metadata) {
    const metadataElement = document.getElementById('email-metadata');
    
    metadataElement.innerHTML = `
        <div class="metadata-content">
            <div class="label">From:</div>
            <div>${metadata.sender || 'Unknown'}</div>
            
            <div class="label">Subject:</div>
            <div>${metadata.subject || 'No Subject'}</div>
            
            <div class="label">Date:</div>
            <div>${metadata.timestamp || 'Unknown'}</div>
        </div>
    `;
}

function populateEmailBody(body) {
    const bodyElement = document.getElementById('email-body');
    bodyElement.innerHTML = body || 'No email content available';
}

function populateSuspiciousElements(elements) {
    const elementsContainer = document.getElementById('suspicious-elements');
    
    // Check if the elements object is empty or has no significant elements
    const hasElements = elements && (
        (elements.urgent_language && elements.urgent_language.length > 0) || 
        (elements.sensitive_requests && elements.sensitive_requests.length > 0) || 
        (elements.suspicious_senders && elements.suspicious_senders.length > 0) || 
        (elements.suspicious_urls && elements.suspicious_urls.length > 0) || 
        (elements.language_issues && elements.language_issues.length > 0)
    );
    
    if (!hasElements) {
        elementsContainer.innerHTML = '<div class="no-elements">No suspicious elements detected</div>';
        return;
    }
    
    let tableContent = `
        <table class="suspicious-table">
            <thead>
                <tr>
                    <th>Element Type</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    // Urgent language
    if (elements.urgent_language && elements.urgent_language.length > 0) {
        tableContent += `
            <tr>
                <td>Urgent Language</td>
                <td>${elements.urgent_language.join(', ')}</td>
            </tr>
        `;
    }
    
    // Sensitive requests
    if (elements.sensitive_requests && elements.sensitive_requests.length > 0) {
        tableContent += `
            <tr>
                <td>Sensitive Information Requests</td>
                <td>${elements.sensitive_requests.join(', ')}</td>
            </tr>
        `;
    }
    
    // Suspicious senders
    if (elements.suspicious_senders && elements.suspicious_senders.length > 0) {
        tableContent += `
            <tr>
                <td>Suspicious Senders</td>
                <td>${elements.suspicious_senders.join('<br>')}</td>
            </tr>
        `;
    }
    
    // Suspicious URLs
    if (elements.suspicious_urls && elements.suspicious_urls.length > 0) {
        tableContent += `
            <tr>
                <td>Suspicious URLs</td>
                <td>${elements.suspicious_urls.join('<br>')}</td>
            </tr>
        `;
    }
    
    // Language issues
    if (elements.language_issues && elements.language_issues.length > 0) {
        tableContent += `
            <tr>
                <td>Language/Grammar Issues</td>
                <td>${elements.language_issues.join(', ')}</td>
            </tr>
        `;
    }
    
    tableContent += `
            </tbody>
        </table>
    `;
    
    elementsContainer.innerHTML = tableContent;
}

function createVisualizations(data) {
    createRiskFactorHeatmap(data);
    createSuspiciousWordsCloud(data);
}

function createRiskFactorHeatmap(data) {
    const heatmapContainer = document.getElementById('heatmap');
    heatmapContainer.innerHTML = '';
    
    // Get risk factors and scores
    const elements = data.analysis.suspicious_elements;
    const riskFactors = [
        { name: 'Urgent Language', count: elements.urgent_language ? elements.urgent_language.length : 0 },
        { name: 'Sensitive Requests', count: elements.sensitive_requests ? elements.sensitive_requests.length : 0 },
        { name: 'Suspicious Senders', count: elements.suspicious_senders ? elements.suspicious_senders.length : 0 },
        { name: 'Suspicious URLs', count: elements.suspicious_urls ? elements.suspicious_urls.length : 0 },
        { name: 'Grammar Issues', count: elements.language_issues ? elements.language_issues.length : 0 }
    ];
    
    // Filter out factors with zero count
    const validFactors = riskFactors.filter(factor => factor.count > 0);
    
    if (validFactors.length === 0) {
        heatmapContainer.innerHTML = '<div class="placeholder">No risk factors detected</div>';
        return;
    }
    
    // Create simple bar chart
    const chart = document.createElement('div');
    chart.className = 'risk-chart';
    
    validFactors.forEach(factor => {
        const barContainer = document.createElement('div');
        barContainer.className = 'bar-container';
        
        const label = document.createElement('div');
        label.className = 'bar-label';
        label.textContent = factor.name;
        
        const barWrapper = document.createElement('div');
        barWrapper.className = 'bar-wrapper';
        
        const bar = document.createElement('div');
        bar.className = 'bar';
        // Calculate intensity - max count assumed to be 10
        const intensity = Math.min((factor.count / 10) * 100, 100);
        bar.style.width = `${intensity}%`;
        bar.style.backgroundColor = `hsl(0, ${intensity}%, 50%)`;
        
        const count = document.createElement('span');
        count.className = 'bar-count';
        count.textContent = factor.count;
        
        barWrapper.appendChild(bar);
        barWrapper.appendChild(count);
        
        barContainer.appendChild(label);
        barContainer.appendChild(barWrapper);
        
        chart.appendChild(barContainer);
    });
    
    heatmapContainer.appendChild(chart);
}

function createSuspiciousWordsCloud(data) {
    const wordcloudContainer = document.getElementById('wordcloud');
    wordcloudContainer.innerHTML = '';
    
    // Collect all suspicious words from different categories
    const elements = data.analysis.suspicious_elements;
    let words = [
        ...(elements.urgent_language || []),
        ...(elements.sensitive_requests || []),
        ...(elements.language_issues || [])
    ];
    
    // Add domain names from suspicious URLs
    if (elements.suspicious_urls && elements.suspicious_urls.length > 0) {
        elements.suspicious_urls.forEach(url => {
            try {
                // Extract domain from URL
                const match = url.match(/https?:\/\/([^\/]+)/);
                if (match && match[1]) {
                    words.push(match[1]);
                }
            } catch (e) {
                // If parsing fails, just use the whole URL
                words.push(url.split(' ')[0]);
            }
        });
    }
    
    // Remove duplicates
    words = [...new Set(words)];
    
    if (words.length === 0) {
        wordcloudContainer.innerHTML = '<div class="placeholder">No suspicious words detected</div>';
        return;
    }
    
    // Create simple word cloud
    const wordCloud = document.createElement('div');
    wordCloud.className = 'word-cloud';
    
    words.forEach(word => {
        const wordElement = document.createElement('span');
        wordElement.className = 'cloud-word';
        wordElement.textContent = word;
        
        // Random font size between 1rem and 2.5rem
        const fontSize = 1 + Math.random() * 1.5;
        wordElement.style.fontSize = `${fontSize}rem`;
        
        // Random rotation between -20 and 20 degrees
        const rotation = Math.random() * 40 - 20;
        wordElement.style.transform = `rotate(${rotation}deg)`;
        
        // Random color intensity
        const intensity = Math.floor(Math.random() * 100);
        wordElement.style.color = `hsl(0, 100%, ${50 + intensity/10}%)`;
        
        wordElement.style.margin = '0.5rem';
        wordElement.style.display = 'inline-block';
        
        wordCloud.appendChild(wordElement);
    });
    
    wordcloudContainer.appendChild(wordCloud);
}

// --- PDF Generation (Client-Side) with Enhanced Design ---
function generatePDF(data) {
    const { jsPDF } = window.jspdf; // Ensure jsPDF is accessible
    if (!jsPDF) {
        console.error("jsPDF library not loaded!");
        alert("Error: Could not generate PDF. jsPDF library missing.");
        return;
    }
    const doc = new jsPDF('p', 'mm', 'a4');

    // --- Configuration ---
    const margin = 15;
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const contentWidth = pageWidth - (margin * 2);
    let yPos = 20;

    // --- Colors ---
    const headerColor = [0, 46, 104];      // Dark Blue
    const titleColor = [0, 0, 0];         // Black
    const labelColor = [80, 80, 80];       // Dark Gray
    const valueColor = [0, 0, 0];         // Black
    const lineColor = [200, 200, 200];     // Light Gray
    const metaBgColor = [245, 245, 245];   // Very Light Gray
    const positiveBgColor = [230, 255, 230]; // Light Green
    const positiveTextColor = [0, 100, 0];  // Dark Green
    const riskColors = {
        Safe: [60, 179, 113],      // Medium Sea Green
        Suspicious: [255, 140, 0], // Dark Orange
        Phishing: [205, 92, 92],   // Indian Red
        Unknown: [128, 128, 128]   // Gray
    };

    // --- Helper Functions ---
    // Adds text with optional styling and returns new y position
    function addText(text, y, options = {}) {
        const { fontSize = 10, fontStyle = 'normal', color = titleColor, align = 'left', maxWidth = contentWidth, x = margin } = options;
        doc.setFontSize(fontSize);
        doc.setFont('helvetica', fontStyle);
        doc.setTextColor(color[0], color[1], color[2]);

        const textLines = doc.splitTextToSize(String(text) || '', maxWidth);
        doc.text(textLines, x, y, { align: align });

        // Calculate height based on font size and lines
        const lineHeight = fontSize * 0.352 * 1.2; // mm conversion * line spacing
        return y + (textLines.length * lineHeight);
    }

    // Adds a dividing line
    function addLine(y) {
        doc.setDrawColor(lineColor[0], lineColor[1], lineColor[2]);
        doc.setLineWidth(0.2);
        doc.line(margin, y, pageWidth - margin, y);
        return y + 2; // Space after line
    }

    // Checks for page break
    function checkNewPage(y, requiredSpace = 20) {
        if (y + requiredSpace > pageHeight - margin) { // Check against page height
            doc.addPage();
            addHeaderFooter(); // Add header/footer to new page
            return margin + 10; // Start position for new page
        }
        return y;
    }

    // Adds Header and Footer (call on each page)
    function addHeaderFooter() {
        const currentPage = doc.internal.getCurrentPageInfo().pageNumber;
        const totalPages = doc.internal.getNumberOfPages();

        // Header
        doc.setFillColor(headerColor[0], headerColor[1], headerColor[2]);
        doc.rect(0, 0, pageWidth, 15, 'F');
        addText('Phishing Email Analysis Report', 10, { fontSize: 14, fontStyle: 'bold', color: [255, 255, 255], x: margin });

        // Footer
        const footerY = pageHeight - 10;
        addLine(footerY - 2);
        addText(`Page ${currentPage} of ${totalPages} | PhishGuard Analysis`, footerY, { fontSize: 8, color: labelColor, align: 'center', x: pageWidth / 2 });
    }

    // --- PDF Generation Start ---
    addHeaderFooter(); // Add to first page
    yPos = margin + 15; // Start below header

    const today = new Date();
    const dateString = today.toLocaleDateString();
    yPos = addText(`Generated on: ${dateString}`, yPos, { fontSize: 9, color: labelColor, align: 'right', x: pageWidth - margin });
    yPos += 5;

    // --- Risk Assessment Section ---
    yPos = checkNewPage(yPos, 40);
    yPos = addText('Risk Assessment', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    let riskLevel = 'Unknown';
    let riskScoreValue = 'N/A';
    if (data.risk_score && typeof data.risk_score === 'object' && data.risk_score.level) {
        riskLevel = data.risk_score.level in riskColors ? data.risk_score.level : 'Unknown';
        riskScoreValue = data.risk_score.score !== undefined ? `${data.risk_score.score}%` : 'N/A';
    }
    const riskColor = riskColors[riskLevel];
    const riskTextMap = {
        Safe: 'This email appears to be safe.',
        Suspicious: 'This email contains suspicious elements.',
        Phishing: 'This email is likely a phishing attempt.',
        Unknown: 'Risk level could not be determined.'
    };
    const riskText = riskTextMap[riskLevel];

    // Draw risk score circle
    const scoreRadius = 10;
    const scoreCircleY = yPos + scoreRadius + 3;
    const scoreTextY = yPos + scoreRadius + 5; // Align text vertically
    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.circle(margin + scoreRadius + 5, scoreCircleY, scoreRadius, 'F');
    addText(riskScoreValue, scoreTextY, { fontSize: 10, fontStyle: 'bold', color: [255, 255, 255], x: margin + scoreRadius + 5, align: 'center' });

    // Risk text beside circle
    addText(riskText, scoreTextY - 3, { fontSize: 11, x: margin + (scoreRadius * 2) + 15, maxWidth: contentWidth - (scoreRadius * 2) - 10 });
    yPos = scoreCircleY + scoreRadius + 8;

    // --- Email Details Section ---
    yPos = checkNewPage(yPos, 45);
    yPos = addText('Email Details', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    const metadata = data.email_details || {};
    doc.setFillColor(metaBgColor[0], metaBgColor[1], metaBgColor[2]);
    doc.roundedRect(margin, yPos, contentWidth, 28, 2, 2, 'F'); // Adjusted height

    let detailY = yPos + 6;
    detailY = addText('From:', detailY, { fontSize: 10, fontStyle: 'bold', color: labelColor, x: margin + 5, maxWidth: 20 });
    addText(metadata.sender || 'N/A', detailY - 6.5, { fontSize: 10, color: valueColor, x: margin + 25, maxWidth: contentWidth - 30 }); // Align value
    detailY += 2; // Adjusted spacing

    detailY = addText('Subject:', detailY, { fontSize: 10, fontStyle: 'bold', color: labelColor, x: margin + 5, maxWidth: 20 });
    addText(metadata.subject || 'N/A', detailY - 6.5, { fontSize: 10, color: valueColor, x: margin + 25, maxWidth: contentWidth - 30 });
    detailY += 2;

    detailY = addText('Date:', detailY, { fontSize: 10, fontStyle: 'bold', color: labelColor, x: margin + 5, maxWidth: 20 });
    addText(metadata.timestamp || 'N/A', detailY - 6.5, { fontSize: 10, color: valueColor, x: margin + 25, maxWidth: contentWidth - 30 });

    yPos += 35;

    // --- Detected Suspicious Elements Section ---
    yPos = checkNewPage(yPos, 50);
    yPos = addText('Detected Suspicious Elements', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    const elements = data.analysis?.suspicious_elements || {};
    const hasElements = Object.values(elements).some(val => Array.isArray(val) && val.length > 0);

    if (!hasElements) {
        yPos = addText('No suspicious elements detected.', yPos, { fontSize: 10, color: labelColor });
        yPos += 5;
    } else {
        const categories = [
            { name: 'Urgent Language', items: elements.urgent_language },
            { name: 'Sensitive Information Requests', items: elements.sensitive_requests },
            { name: 'Suspicious Senders', items: elements.suspicious_senders },
            { name: 'Suspicious URLs', items: elements.suspicious_urls },
            { name: 'Language/Grammar Issues', items: elements.language_issues }
        ];
        for (const category of categories) {
            if (category.items && category.items.length > 0) {
                yPos = checkNewPage(yPos, 15);
                yPos = addText(category.name + ':', yPos, { fontSize: 11, fontStyle: 'bold' });
                category.items.forEach(item => {
                    yPos = checkNewPage(yPos, 8);
                    // Add bullet point with indentation
                    yPos = addText('\u2022', yPos, { fontSize: 10, color: labelColor, x: margin + 3 });
                    yPos = addText(item, yPos - 6.5, { fontSize: 10, x: margin + 8, maxWidth: contentWidth - 8 }); // Indent value text
                });
                yPos += 5;
            }
        }
    }

    // --- Positive Signals Section ---
    yPos = checkNewPage(yPos, 30);
    const positiveSignals = data.analysis?.positive_signals;
    if (positiveSignals && positiveSignals.length > 0) {
        yPos = addText('Positive Signals Detected', yPos, { fontSize: 14, fontStyle: 'bold' });
        yPos += 2;
        yPos = addLine(yPos);
        yPos += 3;

        // Background box for positive signals
        let startYPositiveBox = yPos;
        let tempYPos = yPos;
        positiveSignals.forEach(signal => {
            tempYPos = checkNewPage(tempYPos, 8);
            tempYPos = addText('\u2022', tempYPos, { fontSize: 10, color: positiveTextColor, x: margin + 3 });
            tempYPos = addText(signal, tempYPos - 6.5, { fontSize: 10, color: positiveTextColor, x: margin + 8, maxWidth: contentWidth - 8 });
        });
        let endYPositiveBox = tempYPos;
        doc.setFillColor(positiveBgColor[0], positiveBgColor[1], positiveBgColor[2]);
        doc.roundedRect(margin, startYPositiveBox - 2, contentWidth, endYPositiveBox - startYPositiveBox + 5, 2, 2, 'F');

        // Re-render text on top of the background box
        yPos = startYPositiveBox; // Reset yPos to draw text again
        positiveSignals.forEach(signal => {
             yPos = checkNewPage(yPos, 8);
             yPos = addText('\u2022', yPos, { fontSize: 10, color: positiveTextColor, x: margin + 3 });
             yPos = addText(signal, yPos - 6.5, { fontSize: 10, color: positiveTextColor, x: margin + 8, maxWidth: contentWidth - 8 });
        });
        yPos += 5;
    }

    // --- Analysis Summary Section ---
    yPos = checkNewPage(yPos, 50);
    yPos = addText('Analysis Summary', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    // (Keep the existing summary text generation logic from the original snippet)
    let summaryText = '';
     if (data.risk_score && typeof data.risk_score === 'object' && data.risk_score.level) {
         const riskLevel = data.risk_score.level;
         if (riskLevel === 'Phishing') {
             summaryText = 'This email has been identified as a likely phishing attempt. ';
             if (hasElements) {
                 summaryText += 'Multiple suspicious elements were detected including: ';
                 const allSuspicious = [
                     ...(elements.urgent_language || []),
                     ...(elements.sensitive_requests || []),
                     ...(elements.suspicious_urls ? ['suspicious links'] : []),
                     ...(elements.suspicious_senders ? ['sender issues'] : []),
                     ...(elements.language_issues ? ['grammar problems'] : [])
                 ];
                 summaryText += allSuspicious.slice(0, 3).join(', ') + '.';
             }
             summaryText += ' We recommend deleting this email and not interacting with any links or attachments it contains.';
         } else if (riskLevel === 'Suspicious') {
             summaryText = 'This email contains some suspicious elements that warrant caution. ';
             if (hasElements) {
                 summaryText += 'Potentially concerning elements include: ';
                 const allSuspicious = [
                     ...(elements.urgent_language || []),
                     ...(elements.sensitive_requests || []),
                     ...(elements.suspicious_urls ? ['suspicious links'] : []),
                     ...(elements.suspicious_senders ? ['sender issues'] : []),
                     ...(elements.language_issues ? ['grammar problems'] : [])
                 ];
                 summaryText += allSuspicious.slice(0, 2).join(', ') + '.';
             }
             summaryText += ' Exercise caution when dealing with this email, and verify its legitimacy through alternative means if possible.';
         } else { // Safe
             summaryText = 'This email appears to be legitimate. ';
             if (positiveSignals && positiveSignals.length > 0) {
                 summaryText += 'The following positive signals were detected: ' + positiveSignals.slice(0, 2).join(', ') + '. ';
             }
             summaryText += 'Our analysis suggests this is a safe email, though you should always maintain standard security practices.';
         }
     } else {
         summaryText = "Analysis summary could not be generated due to missing risk assessment data.";
     }
    yPos = addText(summaryText, yPos, { fontSize: 10 });
    yPos += 5;

    // --- Email Content Preview Section ---
    yPos = checkNewPage(yPos, 60);
    yPos = addText('Email Content Preview', yPos, { fontSize: 14, fontStyle: 'bold' });
    yPos += 2;
    yPos = addLine(yPos);
    yPos += 3;

    let bodyText = data.analysis?.highlighted_body || '';
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = bodyText;
    bodyText = tempDiv.textContent || tempDiv.innerText || '';
    if (bodyText.length > 500) {
        bodyText = bodyText.substring(0, 500) + '... [Content Truncated]';
    }

    // Calculate needed height
    doc.setFontSize(9);
    const bodyLines = doc.splitTextToSize(bodyText, contentWidth - 10); // Padding
    const bodyBoxHeight = Math.max(30, 10 + bodyLines.length * (9 * 0.352 * 1.2)); // Min height 30mm

    doc.setFillColor(metaBgColor[0], metaBgColor[1], metaBgColor[2]);
    doc.roundedRect(margin, yPos, contentWidth, bodyBoxHeight, 2, 2, 'F');

    // Add text inside the box
    addText(bodyText, yPos + 5, { fontSize: 9, x: margin + 5, maxWidth: contentWidth - 10 });
    yPos += bodyBoxHeight + 5;

    // --- Final Check for Page Break Before Saving ---
    checkNewPage(yPos, 1); // Ensure footer fits if near bottom

    // --- Save the PDF ---
    const safeSubject = (metadata.subject || 'NoSubject').replace(/[^a-z0-9]/gi, '_').substring(0, 30);
    const fileName = `PhishGuard_Analysis_${safeSubject}_${dateString.replace(/\//g, '-')}.pdf`;
    doc.save(fileName);
}