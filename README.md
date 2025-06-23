# 🛡️ PhishGuard - AI-Powered Phishing Email Detection System

PhishGuard is an AI-powered phishing detection system that uses Machine Learning (ML) and Natural Language Processing (NLP) techniques to analyze email content and sender information. It classifies emails into **Safe**, **Suspicious**, or **Phishing**, while also offering detailed visual feedback and trend analysis to help users stay vigilant against cyber threats.

## 🔍 Key Features

- **Web Interface for Easy Usage**  
  Upload email files or paste raw email content for instant phishing analysis through a user-friendly web UI.

- **Phishing Detection Using ML & NLP**  
  Detects malicious or suspicious emails based on trained machine learning models and NLP text features.

- **Detailed Phishing Analysis Report**  
  Highlights:
  - Suspicious words  
  - Fake sender details  
  - Urgent language triggers  

- **Interactive Dashboard**  
  Visualizes phishing patterns through:
  - Statistical graphs  
  - Pie charts  
  - Word clouds  
  - Heatmaps

- **Visualization-Based Explanation**  
  Risky words are color-coded:
  - 🔴 Red: Phishing  
  - 🟡 Yellow: Suspicious  
  - 🟢 Green: Safe  

---

## ⚙️ Tech Stack

### 🧠 Machine Learning
- **Scikit-learn**  
- **NLP libraries** for email text processing

### 🌐 Frontend
- **HTML**  
- **CSS**  
- **JavaScript**

### 🖥️ Backend
- **FastAPI** (served using **Uvicorn**)

### 🗃️ Database
- **SQLite3**


---

## 🧪 How to Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com/Adithya026/Phishguard.git
   cd Phishguard
   pip install -r requirements.txt
->To run the backend - uvicorn backend.main:app --reload
->Open frontend/index.html in a browser.



🙌 Adithya026 – Developer & Designer




