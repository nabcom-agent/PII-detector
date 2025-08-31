# Let me create a comprehensive list of common PII types and their corresponding regex patterns
# This will be used to build the JavaScript PII detection patterns

pii_patterns = {
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "description": "Email addresses",
        "example": "user@example.com"
    },
    "phone_us": {
        "pattern": r"\b(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        "description": "US phone numbers",
        "example": "+1-555-123-4567, (555) 123-4567, 5551234567"
    },
    "ssn": {
        "pattern": r"\b(?!666|000|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0{4})\d{4}\b",
        "description": "US Social Security Numbers",
        "example": "123-45-6789, 123456789"
    },
    "credit_card": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "description": "Credit card numbers",
        "example": "1234-5678-9012-3456, 1234567890123456"
    },
    "zipcode": {
        "pattern": r"\b\d{5}(-\d{4})?\b",
        "description": "US ZIP codes",
        "example": "12345, 12345-6789"
    },
    "ip_address": {
        "pattern": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "description": "IP addresses",
        "example": "192.168.1.1"
    },
    "url": {
        "pattern": r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?",
        "description": "URLs",
        "example": "https://www.example.com"
    },
    "name": {
        "pattern": r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",
        "description": "Full names (basic pattern)",
        "example": "John Doe, Jane Smith"
    },
    "address": {
        "pattern": r"\b\d+\s+[A-Za-z0-9\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Circle|Cir)\b",
        "description": "Street addresses",
        "example": "123 Main Street, 456 Oak Ave"
    },
    "date": {
        "pattern": r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b",
        "description": "Dates",
        "example": "12/31/2023, 2023-12-31, December 31, 2023"
    },
    "passport": {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "description": "Passport numbers",
        "example": "A1234567, AB1234567"
    },
    "license": {
        "pattern": r"\b[A-Z]{1,2}\d{6,8}\b",
        "description": "Driver's license numbers",
        "example": "D1234567, DL12345678"
    }
}

print("JavaScript PII Detection Patterns:")
print("==================================")

for key, value in pii_patterns.items():
    print(f"{key.upper()}:")
    print(f"  Pattern: {value['pattern']}")
    print(f"  Description: {value['description']}")
    print(f"  Example: {value['example']}")
    print()