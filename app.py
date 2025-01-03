from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:superman80@localhost:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the model for vulnerabilities
class Vulnerability(db.Model):
    __tablename__ = 'vuln'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    endpoint = db.Column(db.String, nullable=False)
    severity = db.Column(db.String, nullable=False)
    cve = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    sensor = db.Column(db.String, nullable=False)

@app.route('/vulnerabilities/', methods=['GET'])
def get_grouped_vulnerabilities():
    vulnerabilities = Vulnerability.query.all()

    # Group vulnerabilities by endpoint and CVE
    grouped_data = {}
    for vuln in vulnerabilities:
        key = f"{vuln.endpoint}_{vuln.cve}"
        if key not in grouped_data:
            grouped_data[key] = {
                "title": vuln.title,
                "endpoint": vuln.endpoint,
                "tag": f"group_{len(grouped_data) + 1}",
                "severity": vuln.severity,
                "cve": vuln.cve,
                "description": vuln.description,
                "sensor": vuln.sensor,
            }

    # Convert grouped data to a list
    result = list(grouped_data.values())
    return jsonify(result)


# Create the database tables (Run once)
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

