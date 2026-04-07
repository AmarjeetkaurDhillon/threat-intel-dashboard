from flask import Flask, render_template, request, send_file, jsonify
from fetch_nvd import get_critical_cves
from fetch_otx import get_threat_indicators
from summariser import summarise_cve
from report_generator import generate_report
import os

app = Flask(__name__)

@app.route("/")
def index():
    cves = get_critical_cves(10)
    for cve in cves:
        cve["summary"] = summarise_cve(cve["id"], cve["description"])
    indicators = get_threat_indicators()
    return render_template("index.html", cves=cves, indicators=indicators)

@app.route("/download-report")
def download_report():
    cves = get_critical_cves(10)
    for cve in cves:
        cve["summary"] = summarise_cve(cve["id"], cve["description"])
    indicators = get_threat_indicators()
    buffer = generate_report(cves, indicators)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="threat-intelligence-report.pdf",
        mimetype="application/pdf"
    )

@app.route("/api/cves")
def api_cves():
    cves = get_critical_cves(10)
    return jsonify(cves)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)