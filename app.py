from flask import Flask, render_template, request, redirect, url_for, flash
import logging
from tools.phishing import score_url


app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-string"  # replace in production

# basic logging to console
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@app.context_processor
def inject_year():
    from datetime import datetime
    return {"current_year": datetime.now().year}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/phising", methods=["GET", "POST"])
def phising():
    result = None
    details = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL to check.", "error")
            return redirect(url_for("phising"))
        try:
            score, details = score_url(url)
            if score >= 70:
                label = "High risk — Likely phishing"
            elif score >= 40:
                label = "Suspicious"
            else:
                label = "Low risk"
            result = {"score": score, "label": label}
        except Exception as e:
            logger.exception("phishing check failed")
            flash(f"Error checking URL: {e}", "error")
            return redirect(url_for("phising"))

    return render_template("phising.html", result=result, details=details)



if __name__ == "__main__":
    logger.info("Starting Flask app on http://127.0.0.1:5000")
    app.run(debug=True)