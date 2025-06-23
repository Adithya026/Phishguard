document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

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

    // File upload functionality
    const fileInput = document.getElementById('file-input');
    const fileNameDisplay = document.querySelector('.file-name');
    const dropArea = document.querySelector('.drop-area');

    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            fileNameDisplay.textContent = this.files[0].name;
            dropArea.style.borderColor = 'var(--success-color)';
        }
    });

    // Drag and drop functionality
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight() {
        dropArea.style.borderColor = 'var(--primary-color)';
        dropArea.style.backgroundColor = 'rgba(74, 108, 255, 0.05)';
    }

    function unhighlight() {
        dropArea.style.borderColor = 'var(--border-color)';
        dropArea.style.backgroundColor = 'white';
    }

    dropArea.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        fileInput.files = files;
        
        if (files.length > 0) {
            fileNameDisplay.textContent = files[0].name;
            dropArea.style.borderColor = 'var(--success-color)';
        }
    }

    // Form submission
    const uploadForm = document.getElementById('upload-form');
    const pasteForm = document.getElementById('paste-form');
    const loader = document.querySelector('.loader');

    uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        if (!fileInput.files[0]) {
            alert('Please upload an email file');
            return;
        }

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        
        loader.classList.remove('hidden');
        
        try {
            const response = await fetch('http://127.0.0.1:8000/analyze/upload', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            // Store the result in localStorage for the results page
            localStorage.setItem('analysis-result', JSON.stringify(data));
            
            // Redirect to results page
            window.location.href = 'results.html';
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during analysis');
        } finally {
            loader.classList.add('hidden');
        }
    });

    pasteForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const emailText = document.getElementById('email-text').value;
        
        if (!emailText) {
            alert('Please paste email content');
            return;
        }

        const formData = new FormData();
        formData.append('email_text', emailText);
        
        loader.classList.remove('hidden');
        
        try {
            const response = await fetch('http://127.0.0.1:8000/analyze/text', {
                method: 'POST',
                body: formData
            });
            
    
            
            const data = await response.json();
            
            // Store the result in localStorage for the results page
            localStorage.setItem('analysis-result', JSON.stringify(data));
            
            // Redirect to results page
            window.location.href = 'results.html';
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during analysis');
        } finally {
            loader.classList.add('hidden');
        }
    });
});
