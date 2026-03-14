# app/composite_detector.py

def has_composite_name_phone(pii_results) -> bool:
    """
    Composite entity detection: returns True if BOTH a person name and a phone number
    appear in the same input (higher sensitivity).
    """
    types = {r.entity_type for r in pii_results}

    has_phone = ("PHONE_NUMBER" in types) or ("KR_PHONE_NUMBER" in types)
    has_name = ("PERSON" in types)

    return has_phone and has_name