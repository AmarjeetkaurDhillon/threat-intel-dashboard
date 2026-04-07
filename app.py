from flask import Flask, render_template, request, send_file, jsonify
from fetch_nvd import fetch_critical_cves
from fetch_otx import fetch_otx_indicators
from summariser import analyse_cve
from report_generator import generate_threat_report
import os

app = Flask(__name__)

@app.route("/")
def index():
    cves = fetch_critical_cves()
    analysed = []
    for cve in cves:
        analysis = analyse_cve(cve)
        analysed.append({**cve, **analysis})
    
    otx_data = fetch_otx_indicators()
    
    return render_template("index.html",
                         cves=analysed,
                         otx_indicators=otx_data,
                         total_cves=len(analysed),
                         critical_count=sum(1 for c in analysed if c.get("severity") == "CRITICAL"),
                         high_count=sum(1 for c in analysed if c.get("severity") == "HIGH"))

@app.route("/download-report")
def download_report():
    cves = fetch_critical_cves()
    analysed = []
    for cve in cves:
        analysis = analyse_cve(cve)
        analysed.append({**cve, **analysis})
    
    otx_data = fetch_otx_indicators()
    buffer = generate_threat_report(analysed, otx_data)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name="threat-intelligence-report.pdf",
        mimetype="application/pdf"
    )

@app.route("/api/cves")
def api_cves():
    cves = fetch_critical_cves()
    return jsonify(cves)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)