from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanRecord(db.Model):
    """Store phishing scan history"""
    __tablename__ = 'scan_records'
    
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)  # 'PHISHING' or 'LEGITIMATE'
    risk_score = db.Column(db.Float, nullable=False)
    confidence = db.Column(db.Float, nullable=True)  # Model confidence 0-100
    reasons = db.Column(db.String(1000), nullable=True)  # JSON string of reasons
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanRecord {self.url} - {self.result}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'result': self.result,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'reasons': self.reasons,
            'timestamp': self.timestamp.isoformat()
        }


def init_db(app):
    """Initialize database"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
