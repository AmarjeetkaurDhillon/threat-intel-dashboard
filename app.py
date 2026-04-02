from flask import Flask, render_template
from fetch_nvd import get_critical_cves
from summariser import summarise_cve

app = Flask(__name__)

@app.route("/")
def index():
    cves = get_critical_cves(5)
    for cve in cves:
        cve["summary"] = summarise_cve(cve["id"], cve["description"])
    return render_template("index.html", cves=cves)

if __name__ == "__main__":
    app.run(debug=True)