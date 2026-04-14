# SmartGuard

A web-based security auditing tool for Solana smart contracts written in Rust. You upload or paste your contract code and it scans for common vulnerabilities and tells you what's wrong.

Built as my final year project for BSc Cyber Security at the University of Huddersfield.

---

## What it checks for

| Vulnerability | Severity |
|---|---|
| Reentrancy | Critical |
| Missing access control | Critical |
| Integer overflow | High |
| Unchecked return values | High |
| Timestamp dependence | Medium |
| Deprecated functions | Low |

---

## Tech used

- Python + Flask (backend)
- HTML, CSS, JavaScript (frontend, no frameworks)
- tree-sitter for parsing Rust code

---

## How to run it

1. Clone the repo and go into the project folder

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the app:
```
python app.py
```

4. Open your browser and go to `http://localhost:5000`

---

## How to use it

- Paste your Rust smart contract code into the text box, or upload a `.rs` file
- Click Analyse
- The results page shows any vulnerabilities found, with the line number, a description of the issue, and a suggested fix

---

## Project structure

```
smartguard/
├── app.py
├── analyser/
│   ├── parser.py
│   ├── detector.py
│   └── detectors/
│       ├── reentrancy.py
│       ├── access_control.py
│       ├── integer_overflow.py
│       ├── unchecked_calls.py
│       ├── timestamp.py
│       └── deprecated.py
├── templates/
│   ├── index.html
│   └── results.html
└── static/
    ├── style.css
    └── script.js
```

---


