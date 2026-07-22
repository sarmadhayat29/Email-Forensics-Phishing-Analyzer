"""Domain exceptions for the Email Forensics & Phishing Analyzer."""

class AnalyzerError(Exception):
    """Base exception for all domain-specific errors in the analyzer."""
    pass


class IngestionError(AnalyzerError):
    """Raised when an email file cannot be found, opened, or read."""
    pass


class MalformedEmailError(AnalyzerError):
    """Raised when the email structure is fundamentally corrupted or unparsable."""
    pass


class ParsingError(AnalyzerError):
    """Raised when extraction of specific fields (headers, body, attachments) fails."""
    pass
