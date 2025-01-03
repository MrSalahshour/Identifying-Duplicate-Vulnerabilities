from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

app = Flask(__name__)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:superman80@localhost:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the Vulnerability model
class Vulnerability(db.Model):
    __tablename__ = 'vuln'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.Text, nullable=True)
    cve = db.Column(db.Text, nullable=True)
    sensor = db.Column(db.Text, nullable=True)
    endpoint = db.Column(db.Text, nullable=True)

@app.route('/vulnerabilities/', methods=['GET'])
def get_grouped_vulnerabilities():
    # Fetch all vulnerabilities
    vulnerabilities = Vulnerability.query.all()

    # Extract relevant data
    vuln_data = [
        {
            "id": vuln.id,
            "title": vuln.title,
            "description": vuln.description or "",
            "severity": vuln.severity,
            "cve": vuln.cve,
            "sensor": vuln.sensor,
            "endpoint": vuln.endpoint
        }
        for vuln in vulnerabilities
    ]

    if not vuln_data:
        return jsonify({"message": "No vulnerabilities found."}), 404

    # Group vulnerabilities by endpoint
    endpoint_groups = {}
    for vuln in vuln_data:
        endpoint = vuln["endpoint"]
        if endpoint not in endpoint_groups:
            endpoint_groups[endpoint] = []
        endpoint_groups[endpoint].append(vuln)

    # Use TF-IDF and clustering within each endpoint group
    grouped_data = {}
    tag_counter = 1
    for endpoint, group in endpoint_groups.items():
        if len(group) == 1:
            # Skip single vulnerabilities (to be handled later)
            continue

        # Group by CVE explicitly
        cve_groups = {}
        for vuln in group:
            cve = vuln["cve"] or "no_cve"  # Use a placeholder if CVE is null
            if cve not in cve_groups:
                cve_groups[cve] = []
            cve_groups[cve].append(vuln)

        # Process each CVE group with clustering if needed
        for cve, cve_group in cve_groups.items():
            if len(cve_group) == 1:
                # Skip single CVE vulnerabilities (to be handled later)
                continue

            # Extract descriptions for TF-IDF
            descriptions = [vuln["description"] for vuln in cve_group]
            vectorizer = TfidfVectorizer(stop_words="english")
            tfidf_matrix = vectorizer.fit_transform(descriptions)

            # Cluster using DBSCAN
            dbscan_model = DBSCAN(eps=0.2, min_samples=2, metric="cosine")
            cluster_labels = dbscan_model.fit_predict(tfidf_matrix.toarray())

            # Assign tags based on clusters
            cluster_map = {}
            for idx, label in enumerate(cluster_labels):
                if label not in cluster_map:
                    cluster_map[label] = tag_counter
                    tag_counter += 1
                cluster_id = cluster_map[label]
                if cluster_id not in grouped_data:
                    grouped_data[cluster_id] = []
                grouped_data[cluster_id].append(cve_group[idx])

    # Collect all single vulnerabilities into a miscellaneous group
    ungrouped = [
        vuln for endpoint, group in endpoint_groups.items()
        for vuln in group if len(group) == 1
    ]
    if ungrouped:
        grouped_data[tag_counter] = ungrouped
        tag_counter += 1

    # Prepare response
    response = [{"cluster": f"group_{tag}", "vulnerabilities": items} for tag, items in grouped_data.items()]
    return jsonify(response)





if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
