from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import email
from email import policy
import re
import os
import numpy as np
import joblib
from io import BytesIO
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import pickle
# --- Database Imports ---
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import func # Added for aggregation
from sqlalchemy.sql.expression import extract # Added for date extraction
from sqlalchemy.sql import case # Added for case function
from contextlib import asynccontextmanager
from datetime import datetime, timedelta # Added timedelta
from collections import Counter # Added Counter
from pydantic import BaseModel # Needed for response model
from typing import Optional # To handle optional fields if needed
# ------------------------


# --- Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./phishing_analysis.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} # Needed for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# --- Database Model ---
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sender = Column(String, index=True, nullable=True)
    subject = Column(String, index=True, nullable=True)
    risk_score = Column(Float, index=True)
    probability = Column(Float)
    # Store the detailed analysis report as JSON
    analysis_details = Column(JSON)

# --- Lifespan for DB table creation ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created.")
    yield
    # Clean up resources if needed on shutdown (optional)
    print("Application shutdown.")

app = FastAPI(title="Phishing Email Detector", lifespan=lifespan)
# -----------------------

# --- Dependency for DB Session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# -------------------------------

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Suspicious words and patterns for basic analysis
suspicious_words = [
    "urgent", "action required", "verify", "account suspended",
    "click here", "password", "security alert", "update your information",
    "bank", "credit card", "payment", "congratulations", "won", "lottery"
]

# Modify the extract_features function to include legitimate email patterns
def extract_features(email_text):
    features = {}
    # Existing features
    features['num_links'] = len(re.findall(r'http[s]?://\S+', email_text))
    features['num_urgent_words'] = sum(1 for word in ['urgent', 'immediately', 'verify', 'suspended', 'alert'] if word in email_text.lower())
    features['num_sensitive_terms'] = sum(1 for term in ['password', 'credit card', 'ssn', 'bank account'] if term in email_text.lower())
    features['text_length'] = len(email_text)
    features['num_special_chars'] = len(re.findall(r'[^\w\s]', email_text))
   
    # Add features for legitimate emails
    features['has_signature'] = 1 if re.search(r'(regards|sincerely|best|thank you),?\s+\w+', email_text.lower()) else 0
    features['has_greeting'] = 1 if re.search(r'(dear|hello|hi)\s+\w+', email_text.lower()) else 0
    features['has_contact_info'] = 1 if re.search(r'(phone|tel|contact|email).*?[\d@]', email_text.lower()) else 0
   
    # Additional features for legitimate emails
    features['has_meeting_info'] = 1 if re.search(r'(meeting|appointment|schedule|calendar)', email_text.lower()) else 0
    features['has_project_discussion'] = 1 if re.search(r'(project|task|report|presentation|update)', email_text.lower()) else 0
    features['has_follow_up'] = 1 if re.search(r'(follow up|let me know|if you have any questions)', email_text.lower()) else 0
   
    return features

def analyze_email_details(email_text):
    """Extract detailed information for the phishing report with positive signals"""
    analysis = {}

    # Suspicious words detection
    urgent_words = ['urgent', 'immediately', 'verify', 'suspended', 'alert', 'warning',
                    'required', 'action needed', 'account locked', 'security', 'unusual activity']
    found_urgent_words = [word for word in urgent_words if word in email_text.lower()]
    analysis['urgent_language'] = found_urgent_words

    # Sensitive information requests
    sensitive_terms = ['password', 'credit card', 'ssn', 'social security', 'bank account',
                      'verify your account', 'confirm details', 'login information', 'username']
    found_sensitive_terms = [term for term in sensitive_terms if term in email_text.lower()]
    analysis['sensitive_requests'] = found_sensitive_terms

    # Sender analysis - look for potentially fake/spoofed email addresses
    email_pattern = r'[\w\.-]+@[\w\.-]+'
    found_emails = re.findall(email_pattern, email_text)

    # Check for suspicious email domains
    suspicious_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'mail']
    corporate_terms = ['bank', 'paypal', 'amazon', 'netflix', 'microsoft', 'apple', 'google', 'support', 'service']

    suspicious_senders = []
    for email_addr in found_emails:
        domain = email_addr.split('@')[1].lower()
        # Check if email claims to be from a corporate entity but uses a generic email service
        for corp in corporate_terms:
            if corp in email_addr.lower() and any(susp in domain for susp in suspicious_domains):
                suspicious_senders.append(email_addr)
                break

    analysis['suspicious_senders'] = suspicious_senders

    # URL analysis
    urls = re.findall(r'http[s]?://\S+', email_text)
    suspicious_urls = []
    for url in urls:
        # Check for URL shorteners
        if any(shortener in url.lower() for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
            suspicious_urls.append(f"{url} (URL shortener)")
        # Check for IP addresses instead of domains
        elif re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
            suspicious_urls.append(f"{url} (IP address)")
        # Check for deceptive domains
        for corp in corporate_terms:
            if corp in url.lower() and corp not in url.lower().split('/')[2]:
                suspicious_urls.append(f"{url} (Suspicious domain)")
                break

    analysis['suspicious_urls'] = suspicious_urls

    # Grammar and spelling issues (simplified detection)
    common_errors = ['kindly', 'dear customer', 'valued customer', 'your account has been',
                     'will be terminate', 'verify you account', 'update you information']
    found_errors = [error for error in common_errors if error in email_text.lower()]
    analysis['language_issues'] = found_errors

    # Add positive signals that could offset suspicious elements
    positive_signals = []
   
    # Check for company signature blocks
    if re.search(r'(sincerely|regards|thank you)[\s\S]{1,50}(inc\.|ltd\.|corp|company)', email_text.lower()):
        positive_signals.append("Contains formal company signature")
   
    # Check for legitimate business follow-up language
    if re.search(r'(please let me know|do not hesitate to contact|if you have any questions)', email_text.lower()):
        positive_signals.append("Contains professional follow-up language")
   
    # Check for meeting details or specific business context
    if re.search(r'(meeting|conference|call|agenda|project|report|budget)(.*?)(scheduled|planned|attached|enclosed)', email_text.lower()):
        positive_signals.append("Contains specific business context")
   
    # Check for contextual information suggesting legitimate business
    if re.search(r'(our conversation|as discussed|in reference to our|following up on|as per our discussion)', email_text.lower()):
        positive_signals.append("References previous legitimate interaction")
   
    # Check for personalized content (not generic)
    if re.search(r'(team|department|project name|specific dates|specific locations)', email_text.lower()):
        positive_signals.append("Contains personalized business information")
       
    analysis['positive_signals'] = positive_signals
   
    return analysis

class PhishingDetector:
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000)
        self.feature_scaler = StandardScaler()
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        # Flag to check if the model is trained
        self.is_trained = False

    def preprocess(self, emails, labels=None):
        features = np.array([list(extract_features(email).values()) for email in emails])

        if labels is not None:
            # Training mode
            text_features = self.tfidf_vectorizer.fit_transform(emails).toarray()
            features_scaled = self.feature_scaler.fit_transform(features)
            self.is_trained = True
        else:
            # Prediction mode - check if vectorizer is fitted
            if not self.is_trained:
                # If not trained, fit with dummy data first
                self._ensure_fitted(emails)
            text_features = self.tfidf_vectorizer.transform(emails).toarray()
            features_scaled = self.feature_scaler.transform(features)

        return np.hstack((text_features, features_scaled)), labels
   
    def _ensure_fitted(self, emails):
        """Ensure the vectorizer and scaler are fitted with sample data"""
        print("Fitting vectorizer and scaler with sample data")
        # Fit the vectorizer with the current emails
        self.tfidf_vectorizer.fit(emails)
        # Fit the scaler with extracted features
        features = np.array([list(extract_features(email).values()) for email in emails])
        self.feature_scaler.fit(features)
        self.is_trained = True

    def train(self, emails, labels):
        X, y = self.preprocess(emails, labels)
        from sklearn.model_selection import train_test_split
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        print(f"Validation Accuracy: {self.model.score(X_val, y_val):.4f}")
        self.is_trained = True
        return self

    def predict_email(self, email_text):
        # Make sure the models are fitted before prediction
        if not self.is_trained:
            # Use sample data to initialize the vectorizer and scaler
            self._ensure_fitted([email_text])
            # For the actual model, we need to provide a reasonable default prediction
            return self._get_default_prediction(email_text)
           
        X, _ = self.preprocess([email_text])
        prob = self.model.predict_proba(X)[0][1]

        # Determine risk category with more granularity - adjusted thresholds
        if prob < 0.4:  # Increased from 0.3
            category = "Safe"
        elif prob < 0.75:  # Increased from 0.7
            category = "Suspicious"
        else:
            category = "Phishing"

        # Generate detailed analysis report
        detailed_analysis = analyze_email_details(email_text)

        # Adjust probability based on positive signals
        positive_signal_count = len(detailed_analysis.get('positive_signals', []))
        adjusted_prob = max(0.05, prob - (positive_signal_count * 0.05))  # Reduce prob by 5% per positive signal

        # Re-evaluate category based on adjusted probability
        if adjusted_prob < 0.4:
            category = "Safe"
        elif adjusted_prob < 0.75:
            category = "Suspicious"
        else:
            category = "Phishing"

        return {
            'risk_score': {
                'score': int(adjusted_prob * 100),
                'level': category
            },
            'probability': float(adjusted_prob),
            'original_probability': float(prob),
            'detailed_analysis': detailed_analysis
        }
   
    def _get_default_prediction(self, email_text):
        """Provide a reasonable default prediction when the model is not trained"""
        # Perform a simple rule-based analysis
        detailed_analysis = analyze_email_details(email_text)
       
        # Count suspicious elements
        suspicious_count = len(detailed_analysis.get('urgent_language', [])) + \
                          len(detailed_analysis.get('sensitive_requests', [])) + \
                          len(detailed_analysis.get('suspicious_senders', [])) + \
                          len(detailed_analysis.get('suspicious_urls', [])) + \
                          len(detailed_analysis.get('language_issues', []))
       
        # Subtract positive signals (safe indicators)
        positive_count = len(detailed_analysis.get('positive_signals', []))
        adjusted_count = max(0, suspicious_count - positive_count)
       
        # Assign a simple probability based on adjusted suspicious elements count with higher thresholds
        if adjusted_count > 8:  # Increased from 5
            prob = 0.8  # Likely phishing
            category = "Phishing"
        elif adjusted_count > 4:  # Increased from 2
            prob = 0.5  # Suspicious
            category = "Suspicious"
        else:
            prob = 0.2  # Likely safe
            category = "Safe"
       
        # Ensure probability stays within bounds
        prob = max(0.1, min(0.9, prob))  # Cap between 0.1 and 0.9
           
        return {
            'risk_score': {
                'score': int(prob * 100),
                'level': category
            },
            'probability': float(prob),
            'detailed_analysis': detailed_analysis,
            'adjusted_count': adjusted_count,
            'suspicious_count': suspicious_count,
            'positive_count': positive_count
        }

    def save(self, filename="phishing_detector.pkl"):
        model_data = {
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'feature_scaler': self.feature_scaler,
            'model': self.model,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, filename)
        print(f"Model saved to {filename}")

    @classmethod
    def load(cls, filename="phishing_detector.pkl"):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Model file {filename} not found")
        data = joblib.load(filename)
        detector = cls()
        detector.tfidf_vectorizer = data['tfidf_vectorizer']
        detector.feature_scaler = data['feature_scaler']
        detector.model = data['model']
        detector.is_trained = data.get('is_trained', False)
        return detector

# Sample training data for emergency initialization - including more legitimate examples
sample_emails = [
    "Hello, this is a normal email about meeting tomorrow.",
    "URGENT: Your account has been suspended. Click here to verify your password.",
    "Please find attached the report you requested yesterday.",
    "Hi team, just following up on our project discussion from last week.",
    "Dear customer, we detected unusual activity. Verify your account now: http://suspicious-link.com",
    "As discussed in our meeting, I've attached the project timeline for your review."
]
sample_labels = [0, 1, 0, 0, 1, 0]  # 0 for safe, 1 for phishing

# Initialize detector
try:
    # Try to load pre-trained model
    detector = PhishingDetector.load()
    print("Loaded pre-trained model")
    if not detector.is_trained:
        detector.train(sample_emails, sample_labels)
        detector.save()
        print("Model retrained and saved")
    else:
        print("Model is already trained")
except FileNotFoundError:
    # If no model exists, create a new one with minimal training
    detector = PhishingDetector()
    print("No pre-trained model found. Creating a basic model.")
   
    # Train with minimal sample data if no model exists
    detector.train(sample_emails, sample_labels)
   
    # Save this basic model
    detector.save()
    print("Basic model trained and saved")

@app.post("/analyze/upload")
async def analyze_email_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Read email file
    content = await file.read()
    return process_email(content, db)

@app.post("/analyze/text")
async def analyze_email_text(email_text: str = Form(...), db: Session = Depends(get_db)):
    try:
        # Parse the email text to extract potential headers
        email_lines = email_text.split('\n')
        sender = ""
        subject = ""
        body_lines = []
       
        # Simple header parsing
        for line in email_lines:
            line = line.strip()
            if line.startswith("From:"):
                sender = line[5:].strip()
            elif line.startswith("Subject:"):
                subject = line[8:].strip()
            elif not line and not sender and not subject:
                continue
            else:
                body_lines.append(line)
       
        # If no explicit headers were found, use the whole text as body
        if not body_lines:
            body_lines = email_lines
           
        # Join body lines back together
        body = '\n'.join(body_lines)
       
        # Create email message with proper encoding
        msg = email.message.EmailMessage(policy=policy.default)
        msg['From'] = sender if sender else "Unknown Sender <unknown@example.com>"
        msg['Subject'] = subject if subject else "Email Text Analysis"
        msg.set_content(body, charset='utf-8')
       
        # Process the email content
        return process_email(msg.as_bytes(), db)
       
    except Exception as e:
        print(f"Error in analyze_email_text: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process email text: {str(e)}"
        )

def process_email(content, db: Session):
    try:
        # Parse email with UTF-8 policy
        msg = email.message_from_bytes(content, policy=policy.EmailPolicy(utf8=True))

        # Extract email parts
        sender = msg.get("From", "Unknown Sender")
        subject = msg.get("Subject", "No Subject")
       
        # Initialize body
        body = ""
       
        # Get email body with improved charset handling
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        # Try to get the charset from the Content-Type header
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                       
                        # Try the specified charset first
                        try:
                            decoded_text = payload.decode(charset)
                        except UnicodeDecodeError:
                            # Fallback charsets if the specified one fails
                            for fallback_charset in ['utf-8', 'iso-8859-1', 'windows-1252', 'ascii']:
                                try:
                                    decoded_text = payload.decode(fallback_charset)
                                    break
                                except UnicodeDecodeError:
                                    continue
                            else:
                                # If all charsets fail, use 'replace' error handler
                                decoded_text = payload.decode('utf-8', errors='replace')
                       
                        body += decoded_text + "\n"
                    except Exception as e:
                        print(f"Error decoding part: {str(e)}")
                        continue
        else:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                payload = msg.get_payload(decode=True)
               
                try:
                    body = payload.decode(charset)
                except UnicodeDecodeError:
                    # Fallback charsets if the specified one fails
                    for fallback_charset in ['utf-8', 'iso-8859-1', 'windows-1252', 'ascii']:
                        try:
                            body = payload.decode(fallback_charset)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        # If all charsets fail, use 'replace' error handler
                        body = payload.decode('utf-8', errors='replace')
            except Exception as e:
                print(f"Error decoding main body: {str(e)}")
                body = msg.get_payload(decode=False) or ""

        # Clean the text while preserving Unicode characters
        body = re.sub(r'\s+', ' ', body).strip()
       
        if not body:
            print("Warning: Email body is empty or could not be extracted.")
            body = "Email body could not be extracted."

        # Use the ML model to analyze
        result = detector.predict_email(body)

        # Generate detailed report
        report = generate_report(sender, subject, body, result)

        # Save to Database
        try:
            score_to_save = result.get('probability', 0.0)
            analysis_details_to_save = report.get('analysis', {})

            db_entry = AnalysisResult(
                sender=sender[:255] if sender else None,
                subject=subject[:255] if subject else None,
                risk_score=score_to_save,
                probability=score_to_save,
                analysis_details=analysis_details_to_save
            )
            db.add(db_entry)
            db.commit()
            db.refresh(db_entry)
            print(f"Saved analysis result ID: {db_entry.id}")
        except Exception as e:
            db.rollback()
            print(f"Database Error: Failed to save analysis result - {e}")
            raise HTTPException(status_code=500, detail="Failed to save analysis result.")

        return report

    except Exception as e:
        print(f"Error processing email: {str(e)}")
        if 'db' in locals():
            db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during email processing: {str(e)}"
        )

def generate_report(sender, subject, body, result):
    # Get detailed analysis from the result
    detailed_analysis = result.get('detailed_analysis', {})
   
    # Highlight suspicious words in body
    highlighted_body = body
    suspicious_elements = detailed_analysis.get('urgent_language', []) + \
                          detailed_analysis.get('sensitive_requests', [])
   
    for word in suspicious_elements:
        pattern = r'(?i)\b' + re.escape(word) + r'\b'
        highlighted_body = re.sub(
            pattern,
            f"<span class='highlight-red'>{word}</span>",
            highlighted_body
        )
   
    # Highlight positive signals in body
    positive_signals = detailed_analysis.get('positive_signals', [])
    positive_keywords = [
        "meeting", "conference", "project", "agenda", "attached", "report",
        "as discussed", "following up", "let me know", "if you have any questions",
        "sincerely", "regards", "thank you"
    ]
   
    for word in positive_keywords:
        pattern = r'(?i)\b' + re.escape(word) + r'\b'
        highlighted_body = re.sub(
            pattern,
            f"<span class='highlight-green'>{word}</span>",
            highlighted_body
        )
   
    return {
        "risk_score": result['risk_score'],
        "probability": result['probability'],
        "original_probability": result.get('original_probability', result['probability']),
        "email_details": {
            "sender": sender,
            "subject": subject,
            "timestamp": "",  # Would extract from email headers
        },
        "analysis": {
            "highlighted_body": highlighted_body,
            "suspicious_elements": {
                "urgent_language": detailed_analysis.get('urgent_language', []),
                "sensitive_requests": detailed_analysis.get('sensitive_requests', []),
                "suspicious_senders": detailed_analysis.get('suspicious_senders', []),
                "suspicious_urls": detailed_analysis.get('suspicious_urls', []),
                "language_issues": detailed_analysis.get('language_issues', [])
            },
            "positive_signals": detailed_analysis.get('positive_signals', []),
            "adjustment_details": {
                "suspicious_count": result.get('suspicious_count', 0),
                "positive_count": result.get('positive_count', 0),
                "adjusted_count": result.get('adjusted_count', 0)
            }
        }
    }

@app.get("/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)): # Add db dependency
    try:
        # 1. Calculate Overall Counts
        total_emails = db.query(func.count(AnalysisResult.id)).scalar()
        phishing_count = db.query(func.count(AnalysisResult.id)).filter(AnalysisResult.risk_score >= 0.75).scalar()
        suspicious_count = db.query(func.count(AnalysisResult.id)).filter(AnalysisResult.risk_score >= 0.4, AnalysisResult.risk_score < 0.75).scalar()
        safe_count = db.query(func.count(AnalysisResult.id)).filter(AnalysisResult.risk_score < 0.4).scalar()

        # 2. Calculate Monthly Trends (Last 6 months)
        six_months_ago = datetime.utcnow() - timedelta(days=180)
        monthly_data = db.query(
            extract('year', AnalysisResult.timestamp).label('year'),
            extract('month', AnalysisResult.timestamp).label('month'),
            func.sum(case((AnalysisResult.risk_score >= 0.75, 1), else_=0)).label('phishing'),
            func.sum(case((AnalysisResult.risk_score < 0.4, 1), else_=0)).label('safe')
        ).\
            filter(AnalysisResult.timestamp >= six_months_ago).\
            group_by('year', 'month').\
            order_by('year', 'month').all()

        monthly_trends = [
            {"month": f"{int(row.year)}-{int(row.month):02d}", "phishing": row.phishing or 0, "safe": row.safe or 0}
            for row in monthly_data
        ]

        # 3. Calculate Common Words from Phishing/Suspicious Emails (Top 10)
        analyses_for_words = db.query(AnalysisResult.analysis_details).\
            filter(AnalysisResult.risk_score >= 0.4).\
            limit(500).all() # Limit query size for performance

        words = []
        for entry in analyses_for_words:
            details = entry[0]
            if details:
                const_suspicious = details.get('suspicious_elements', {})
                urgent = const_suspicious.get('urgent_language', [])
                sensitive = const_suspicious.get('sensitive_requests', [])
                if isinstance(urgent, list):
                    words.extend(urgent)
                if isinstance(sensitive, list):
                    words.extend(sensitive)

        common_word_counts = Counter(words).most_common(10)
        common_words = [{"word": word, "count": count} for word, count in common_word_counts]

        # 4. Fetch Recent Analysis History (Keep existing logic)
        recent_history = db.query(AnalysisResult).order_by(AnalysisResult.timestamp.desc()).limit(20).all()
        history_list = [
            {
                "id": item.id,
                "timestamp": item.timestamp.isoformat(),
                "sender": item.sender,
                "subject": item.subject,
                "risk_score": item.risk_score,
                "probability": item.probability, # Keep this if the DB column exists
            } for item in recent_history
        ]

    except Exception as e:
        print(f"Database Error fetching dashboard stats: {e}")
        # Return default structure on error
        return {
            "total_emails": 0, "phishing_count": 0, "suspicious_count": 0, "safe_count": 0,
            "monthly_trends": [], "common_words": [], "analysis_history": []
        }

    # Return calculated data
    return {
        "total_emails": total_emails,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "monthly_trends": monthly_trends,
        "common_words": common_words,
        "analysis_history": history_list
    }

# Optional: Create a route to train the model if necessary
@app.post("/train")
async def train_model(upload_file: UploadFile = File(None)):
    try:
        from datasets import load_dataset
       
        # Use uploaded dataset or fetch from Hugging Face
        if upload_file:
            # Process uploaded dataset (implementation depends on format)
            pass
        else:
            # Use the Hugging Face dataset
            dataset = load_dataset("ealvaradob/phishing-dataset", trust_remote_code=True)
            emails = [item['text'] for item in dataset['train']]
            labels = [item['label'] for item in dataset['train']]
           
            # Train the model
            detector.train(emails, labels)
            detector.save()
           
            return {"status": "success", "message": "Model trained and saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training error: {str(e)}")

# --- Define the nested model for risk score ---
class RiskScoreResponse(BaseModel):
    score: int
    level: str

# --- Response Model for Full Analysis Details (Updated) ---
class FullAnalysisResponse(BaseModel):
    id: int
    timestamp: datetime
    sender: Optional[str] = None # Use Optional for clarity
    subject: Optional[str] = None
    risk_score: RiskScoreResponse # <<< UPDATED: Use the nested model
    probability: float # Keep the original float probability
    email_details: dict
    analysis: dict

    class Config:
        orm_mode = True

# --- Endpoint to Fetch Full Analysis Details by ID (No change needed here now) ---
@app.get("/analysis/{analysis_id}", response_model=FullAnalysisResponse)
async def get_analysis_details(analysis_id: int, db: Session = Depends(get_db)):
    db_result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if db_result is None:
        raise HTTPException(status_code=404, detail="Analysis result not found")

    # --- Reconstruct the nested structure ---
    response_data = {
        "id": db_result.id,
        "timestamp": db_result.timestamp,
        "sender": db_result.sender,
        "subject": db_result.subject,
        # "risk_score": db_result.risk_score, # Initial float value (we override below)
        "probability": db_result.probability, # Keep the original float probability
    }

    response_data["email_details"] = {
        "sender": db_result.sender,
        "subject": db_result.subject,
        "timestamp": db_result.timestamp.isoformat() if db_result.timestamp else "Unknown"
    }

    analysis_json = db_result.analysis_details or {}
    response_data["analysis"] = {
        "highlighted_body": analysis_json.get("highlighted_body", ""),
        "suspicious_elements": analysis_json.get("suspicious_elements", {}),
        "positive_signals": analysis_json.get("positive_signals", [])
    }

    # --- Adapt the risk_score part for generatePDF ---
    risk_level_str = "Safe"
    if db_result.risk_score >= 0.75:
        risk_level_str = "Phishing"
    elif db_result.risk_score >= 0.4:
        risk_level_str = "Suspicious"

    # Create the nested dictionary for risk_score
    response_data["risk_score"] = {
        "score": int(db_result.risk_score * 100),
        "level": risk_level_str
    }
   
    # Return the manually reconstructed dict
    # FastAPI will validate it against the updated FullAnalysisResponse model
    return response_data

if __name__ == "__main__":
    # Note: The lifespan function handles table creation now
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

