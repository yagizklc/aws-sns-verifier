import json

from aws_sns_verifier.models import SNSWebhookMessage

# Abrv: swm = SNSWebhookMessage | ea = EmailAttachment


def test_swm_valid_with_email(valid_sns_message: bytes) -> None:
    """
    When a SNS webhook message is received with a valid message with an email
    I should be able to validate the message and get an EmailReceivedMessage.
    """
    msg = json.loads(valid_sns_message)
    assert isinstance(msg, dict), "Message must be a dictionary"
    x = SNSWebhookMessage.model_validate(msg)
    assert x.Email is not None, "Could not parse email message"
    assert x.Email.organization == "Areal AI", "Organization must be Areal AI"
    assert x.Email.subject == "lutfenn", "Subject must be lutfenn"
    print(f"{x.Email.notificationType=}")
