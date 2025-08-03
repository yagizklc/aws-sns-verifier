"""
AWS SNS Verifier based on the official documentation:
https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html

"""

from .models import (
    SNSWebhookMessage,
    SNSSubscriptionConfirmation,
    EmailReceivedMessage,
)
from .attachments import EmailAttachment, extract_attachments_from_email
from .validator import validate_sns_signature

__all__ = [
    "validate_sns_signature",
    "SNSWebhookMessage",
    "SNSSubscriptionConfirmation",
    "EmailReceivedMessage",
    "EmailAttachment",
    "extract_attachments_from_email",
]
