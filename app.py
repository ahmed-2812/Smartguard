import os
import json
from flask import Flask, request, jsonify, render_template, session

from analyser.parser import parse_rust_code
from analyser.detector import run_all_detectors

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB limit


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    code = None

    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        if not f.filename.endswith('.rs'):
            return jsonify({'error': 'Only .rs files are accepted.'}), 400
        code = f.read().decode('utf-8', errors='replace')
    elif request.form.get('code'):
        code = request.form.get('code')
    elif request.is_json:
        data = request.get_json()
        code = data.get('code', '')

    if not code or not code.strip():
        return jsonify({'error': 'No code provided.'}), 400

    try:
        tree, raw_code = parse_rust_code(code)
    except Exception as e:
        return jsonify({'error': f'Parse error: {str(e)}'}), 400

    findings = run_all_detectors(tree, raw_code)

    summary = {
        'total': len(findings),
        'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'low': sum(1 for f in findings if f['severity'] == 'LOW'),
    }

    session['findings'] = findings
    session['summary'] = summary

    return jsonify({'findings': findings, 'summary': summary})


@app.route('/results')
def results():
    findings = session.get('findings', [])
    summary = session.get('summary', {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
    })
    return render_template('results.html', findings=findings, summary=summary)


if __name__ == '__main__':
    app.run(debug=True)
