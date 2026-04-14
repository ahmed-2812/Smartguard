"""
detector.py - Orchestrates all vulnerability detectors.
"""

from analyser.detectors.reentrancy import detect_reentrancy
from analyser.detectors.access_control import detect_access_control
from analyser.detectors.integer_overflow import detect_integer_overflow
from analyser.detectors.unchecked_calls import detect_unchecked_calls
from analyser.detectors.timestamp import detect_timestamp
from analyser.detectors.deprecated import detect_deprecated

DETECTORS = [
    detect_reentrancy,
    detect_access_control,
    detect_integer_overflow,
    detect_unchecked_calls,
    detect_timestamp,
    detect_deprecated,
]


def run_all_detectors(tree, raw: bytes) -> list:
    """
    Run every detector against the parsed AST.

    Returns a flat list of finding dicts sorted by severity then line number.
    """
    findings = []
    for detector in DETECTORS:
        try:
            results = detector(tree, raw)
            if results:
                findings.extend(results)
        except Exception as e:
            # Never let a single detector crash the whole analysis
            findings.append({
                'vulnerability_type': 'Detector Error',
                'severity': 'LOW',
                'line_number': 0,
                'function_name': 'N/A',
                'description': f'Detector {detector.__name__} raised an exception: {e}',
                'impact': 'Analysis may be incomplete.',
                'recommendation': 'Report this as a bug.',
                'vulnerable_code': '',
                'secure_code': '',
            })

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda f: (severity_order.get(f['severity'], 4), f['line_number']))
    return findings
