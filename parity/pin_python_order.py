"""Pins the Python implementation's set-iteration order to the Java port's documented order.

Python iterates two sets whose order depends on the hash seed (PYTHONHASHSEED): the medical
terms, and allowlist entries of equal length. That order reaches detector output and the LLM
prompts, so the Python side is not reproducible run to run. The Java port sorts both by code
point (CLAUDE.md D12); this module applies the same order to Python before a parity run.
Import it after anonymizer is importable and before building any FileConfig."""
import dataclasses
import anonymizer.config as _config
import anonymizer.detectors as _detectors

_detectors._MEDICAL_TERMS = sorted(_detectors._MEDICAL_TERMS)
_original_load_file_config = _config.load_file_config

def load_file_config(config_dir):
    files = _original_load_file_config(config_dir)
    rules = dataclasses.replace(files.rules,
                                public_services=sorted(files.rules.public_services),
                                legal_refs=sorted(files.rules.legal_refs),
                                dou_allowlist=sorted(files.rules.dou_allowlist))
    return dataclasses.replace(files, rules=rules)

_config.load_file_config = load_file_config
