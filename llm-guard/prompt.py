import logging
import time
from datetime import timedelta
from typing import Dict, List
import re
import streamlit as st
from llm_guard.input_scanners import get_scanner_by_name
from llm_guard.input_scanners.anonymize import default_entity_types
from llm_guard.input_scanners.code import SUPPORTED_LANGUAGES as SUPPORTED_CODE_LANGUAGES
from llm_guard.input_scanners.language import MatchType as LanguageMatchType
from llm_guard.input_scanners.prompt_injection import MatchType as PromptInjectionMatchType
from llm_guard.input_scanners.toxicity import MatchType as ToxicityMatchType
from llm_guard.vault import Vault

logger = logging.getLogger("llm-guard-playground")

redaction_counters = {
    "competitor": 0,
}

def init_settings():
    settings = {
        "Anonymize": {
            "entity_types": ["DATE_TIME", "NRP", "LOCATION", "MEDICAL_LICENSE", "US_PASSPORT", "PERSON", "IP_ADDRESS", "EMAIL_ADDRESS_RE"],
            "hidden_names": [],
            "allowed_names": [],
            "preamble": "Text to prepend to sanitized prompt: ",
            "use_faker": False,
            "threshold": 0.0,
        },
        "BanCompetitors": {
            "competitors": ["openai", "anthropic", "deepmind", "google"],
            "threshold": 0.5,
        },
        "BanTopics": {
            "topics": ["violence"],
            "threshold": 0.6,
        },
        "Regex": {
            "patterns": ["Bearer [A-Za-z0-9-._~+/]+"],
            "is_blocked": True,
            "redact": True,
        },
        "BanSubstrings": {
            "substrings": ["test", "hello", "world"],
            "match_type": "str",
            "case_sensitive": False,
            "redact": True,
            "contains_all": False,
        },
        "TokenLimit": {
            "limit": 4096,
            "encoding_name": "cl100k_base",
        },
    }
    enabled_scanners = ["Anonymize", "BanCompetitors", "BanTopics", "Regex", "BanSubstrings", "TokenLimit"]
    return enabled_scanners, settings


def redact_competitors(text, competitors):
    global redaction_counters
    redaction_counters["competitor"] = 0 
    for competitor in competitors:
        if competitor in text:
            redaction_counters["competitor"] += 1
            text = text.replace(competitor, f"[REDACTED_COMPETITOR_{redaction_counters['competitor']}]")
    return text

def get_scanner(scanner_name: str, vault: Vault, settings: Dict):
    logger.debug(f"Initializing {scanner_name} scanner")
    if scanner_name in ["Anonymize"]:
        settings["vault"] = vault
    if scanner_name in ["Anonymize", "BanTopics"]:
        settings["use_onnx"] = True
    return get_scanner_by_name(scanner_name, settings)


def scan(vault: Vault, enabled_scanners: List[str], settings: Dict, text: str, fail_fast: bool = False):
    global mappings  # Reset mappings at the start of map_redactions
    mappings = {}
    global redaction_counters
    sanitized_prompt = text
    results = []
    for scanner_name in enabled_scanners:
        logger.debug(f"{scanner_name} scanner...")
        scanner = get_scanner(scanner_name, vault, settings.get(scanner_name, {}))
        start_time = time.monotonic()
        sanitized_prompt, is_valid, risk_score = scanner.scan(sanitized_prompt)
        end_time = time.monotonic()
        results.append({
            "scanner": scanner_name,
            "is_valid": is_valid,
            "risk_score": risk_score,
            "took_sec": round(timedelta(seconds=end_time - start_time).total_seconds(), 2),
        })
        if fail_fast and not is_valid:
            break
    if "BanCompetitors" in enabled_scanners:
        sanitized_prompt = redact_competitors(sanitized_prompt, settings["BanCompetitors"]["competitors"])

    return sanitized_prompt, results


def map_redactions(original_text, sanitized_text):
    global mappings  # Reference the global mappings variable
    mappings = {}
    sanitized_text = sanitized_text.split("Text to prepend to sanitized prompt:")[1].strip()
    redaction_pattern = r'\[REDACTED[^\]]*\]'
    redacted_segments = re.findall(redaction_pattern, sanitized_text)
    parts = re.split(redaction_pattern, sanitized_text)
    start = 0
    for i, part in enumerate(parts[:-1]):
        end = original_text.find(part, start) + len(part)
        next_start = original_text.find(parts[i+1], end)
        original_redacted = original_text[end:next_start].strip()
        mappings[original_redacted]=redacted_segments[i]
        start = next_start
    return mappings


def replace_redactions_with_originals(redacted_prompt: str, mappings: Dict[str, str]) -> str:
    for original_text, redacted_text in mappings.items():
        redacted_prompt = redacted_prompt.replace(redacted_text, original_text)
    return redacted_prompt
