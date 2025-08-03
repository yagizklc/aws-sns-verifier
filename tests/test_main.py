import json
from aws_sns_verifier.models import SNSWebhookMessage

# Abrv: swm = SNSWebhookMessage | ea = EmailAttachment

# ---------------- SNS Webhook Message Tests -------------------


def test_swm_valid_with_email(valid_sns_message: bytes) -> None:
    """
    When a SNS webhook message is received with a valid message with an email
    I should be able to validate the message and get an EmailReceivedMessage.
    """
    msg = json.loads(valid_sns_message)
    assert isinstance(msg, dict), "Message must be a dictionary"
    x = SNSWebhookMessage.model_validate(msg)
    assert x.Email is not None, "Could not parse email message"
    print(f"{x.Email.notificationType=}")


# def test_swm_valid_without_email() -> None:
#     """
#     When a valid SNS webhook message is received
#     But the SNSWebhookMessage.Message is not of type EmailReceivedMessage
#     the SNSWebhookMessage.Email should be None
#     """
#     message = {
#         "Type": "Notification",
#         "MessageId": "12345678-1234-1234-1234-123456789012",
#         "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
#         "Subject": "Test Subject",
#         "Message": "Simple text message, not JSON",
#         "Timestamp": "2023-01-01T00:00:00.000Z",
#         "SignatureVersion": "2",
#         "Signature": "valid-signature-base64",
#         "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
#         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/unsubscribe",
#     }
#     validate_sns_signature(message)


# def test_swm_valid_with_valid_email() -> None:
#     """
#     When a valid SNS webhook message is received
#     And the SNSWebhookMessage.Message is of type EmailReceivedMessage
#     Then the SNSWebhookMessage.Email should be an instance of EmailReceivedMessage
#     """
#     email_message = {
#         "notificationType": "Received",
#         "mail": {
#             "source": "sender@example.com",
#             "messageId": "email-message-id-123",
#             "destination": ["recipient@example.com"],
#             "headersTruncated": False,
#             "headers": [
#                 {"name": "From", "value": "sender@example.com"},
#                 {"name": "To", "value": "recipient@example.com"},
#                 {"name": "Subject", "value": "Test Email"},
#             ],
#         },
#     }
#     message = {
#         "Type": "Notification",
#         "MessageId": "12345678-1234-1234-1234-123456789012",
#         "TopicArn": "arn:aws:sns:us-east-1:123456789012:email-topic",
#         "Subject": "Amazon SES Email Receipt",
#         "Message": json.dumps(email_message),
#         "Timestamp": "2023-01-01T00:00:00.000Z",
#         "SignatureVersion": "2",
#         "Signature": "valid-signature-base64",
#         "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
#         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/unsubscribe",
#     }
#     validate_sns_signature(message)


# # ---------------- Email Attachment Tests -------------------


# def test_ea_valid_no_attachments() -> None:
#     """
#     When a valid SNS webhook message is received with a valid email as the Message
#     But the email does not have any attachments
#     Then the SNSWebhookMessage.Email.attachments should be an None
#     """
#     email_message = {
#         "notificationType": "Received",
#         "mail": {
#             "source": "no-attachments@example.com",
#             "messageId": "no-attachments-message-id",
#             "destination": ["recipient@example.com"],
#             "headersTruncated": False,
#             "headers": [
#                 {"name": "From", "value": "no-attachments@example.com"},
#                 {"name": "To", "value": "recipient@example.com"},
#                 {"name": "Subject", "value": "Email without attachments"},
#                 {"name": "Content-Type", "value": "text/plain"},
#             ],
#         },
#     }
#     message = {
#         "Type": "Notification",
#         "MessageId": "12345678-1234-1234-1234-123456789012",
#         "TopicArn": "arn:aws:sns:us-east-1:123456789012:email-topic",
#         "Subject": "Amazon SES Email Receipt",
#         "Message": json.dumps(email_message),
#         "Timestamp": "2023-01-01T00:00:00.000Z",
#         "SignatureVersion": "2",
#         "Signature": "valid-signature-base64",
#         "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
#         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/unsubscribe",
#     }
#     validate_sns_signature(message)


# def test_ea_valid_with_attachments() -> None:
#     """
#     When a valid SNS webhook message is received with a valid email as the Message
#     And the email has valid attachments
#     Then the SNSWebhookMessage.Email.attachments should be a list of EmailAttachment
#     """
#     email_message = {
#         "notificationType": "Received",
#         "mail": {
#             "source": "with-attachments@example.com",
#             "messageId": "with-attachments-message-id",
#             "destination": ["recipient@example.com"],
#             "headersTruncated": False,
#             "headers": [
#                 {"name": "From", "value": "with-attachments@example.com"},
#                 {"name": "To", "value": "recipient@example.com"},
#                 {"name": "Subject", "value": "Email with attachments"},
#                 {
#                     "name": "Content-Type",
#                     "value": "multipart/mixed; boundary=boundary123",
#                 },
#             ],
#         },
#     }
#     message = {
#         "Type": "Notification",
#         "MessageId": "12345678-1234-1234-1234-123456789012",
#         "TopicArn": "arn:aws:sns:us-east-1:123456789012:email-topic",
#         "Subject": "Amazon SES Email Receipt",
#         "Message": json.dumps(email_message),
#         "Timestamp": "2023-01-01T00:00:00.000Z",
#         "SignatureVersion": "2",
#         "Signature": "valid-signature-base64",
#         "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
#         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/unsubscribe",
#     }
#     validate_sns_signature(message)


# def test_ea_valid_with_bad_attachments() -> None:
#     """
#     When a valid SNS webhook message is received with a valid email as the Message
#     And the email has invalid attachments (corrupted files etc.)
#     Then the SNSWebhookMessage.Email.attachments should be None
#     """
#     email_message = {
#         "notificationType": "Received",
#         "mail": {
#             "source": "bad-attachments@example.com",
#             "messageId": "bad-attachments-message-id",
#             "destination": ["recipient@example.com"],
#             "headersTruncated": False,
#             "headers": [
#                 {"name": "From", "value": "bad-attachments@example.com"},
#                 {"name": "To", "value": "recipient@example.com"},
#                 {"name": "Subject", "value": "Email with corrupted attachments"},
#                 {
#                     "name": "Content-Type",
#                     "value": "multipart/mixed; boundary=boundary123",
#                 },
#             ],
#         },
#     }
#     message = {
#         "Type": "Notification",
#         "MessageId": "12345678-1234-1234-1234-123456789012",
#         "TopicArn": "arn:aws:sns:us-east-1:123456789012:email-topic",
#         "Subject": "Amazon SES Email Receipt",
#         "Message": json.dumps(email_message),
#         "Timestamp": "2023-01-01T00:00:00.000Z",
#         "SignatureVersion": "2",
#         "Signature": "valid-signature-base64",
#         "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
#         "UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/unsubscribe",
#     }
#     validate_sns_signature(message)
