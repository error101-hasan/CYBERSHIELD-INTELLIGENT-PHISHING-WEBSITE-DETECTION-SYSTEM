"""
Import existing JSONL scan logs to SQLite database
Run: python -c "from import_logs import import_jsonl_to_db; import_jsonl_to_db()"
"""
import json
from datetime import datetime
from database import db, ScanRecord, init_db
from app import app

def import_jsonl_to_db():
    """Import scan logs from JSONL file to database"""
    
    with open('logs/scan_logs.jsonl', 'r') as f:
        lines = f.readlines()
    
    print(f"Importing {len(lines)} records from scan_logs.jsonl...")
    
    with app.app_context():
        imported = 0
        for line in lines:
            try:
                data = json.loads(line.strip())
                
                # Check if already exists (avoid duplicates)
                existing = ScanRecord.query.filter_by(
                    url=data['url'],
                    timestamp=datetime.fromisoformat(data['timestamp'])
                ).first()
                
                if existing:
                    continue
                
                # Create new record
                record = ScanRecord(
                    url=data['url'],
                    result=data['label'],
                    risk_score=data.get('risk_score', 0),
                    confidence=data.get('confidence', None),
                    reasons=json.dumps(data.get('reasons', [])),
                    timestamp=datetime.fromisoformat(data['timestamp'])
                )
                db.session.add(record)
                imported += 1
                
            except Exception as e:
                print(f"Error importing record: {e}")
                continue
        
        db.session.commit()
        print(f"Successfully imported {imported} records!")
        
        # Show stats
        total = ScanRecord.query.count()
        phishing = ScanRecord.query.filter_by(result='PHISHING').count()
        legitimate = ScanRecord.query.filter_by(result='LEGITIMATE').count()
        
        print(f"\nDatabase Statistics:")
        print(f"Total scans: {total}")
        print(f"Phishing detected: {phishing}")
        print(f"Legitimate: {legitimate}")
        if total > 0:
            print(f"Detection rate: {(phishing/total)*100:.1f}%")

if __name__ == '__main__':
    import_jsonl_to_db()
