from typing import Any

from pydantic import BaseModel, model_validator

from aws_sns_verifier.attachments import (
    extract_attachments_from_email,
    EmailAttachment,
)


class EmailReceivedMessage(BaseModel):
    class Mail(BaseModel):
        class Headers(BaseModel):
            name: str
            value: str

        source: str
        messageId: str
        destination: list[str]
        headersTruncated: bool
        headers: list[Headers]

    notificationType: str
    mail: Mail

    @property
    def sender_address(self) -> str:
        """
        The sender address of the email.
        """
        return self.mail.source

    def attachments(
        self, s3_client, bucket_name: str, prefix: str
    ) -> list[EmailAttachment] | None:
        """
        Extract the attachments from the email.
        """
        try:
            key = f"{prefix}/{self.mail.messageId}"
            raw_email = s3_client.get_object(Bucket=bucket_name, Key=key)["Body"].read()
            return extract_attachments_from_email(raw_email=raw_email, key=key)
        except Exception:
            return None


class SNSWebhookMessage(BaseModel):
    Type: str
    MessageId: str
    TopicArn: str
    Subject: str
    Message: str
    Timestamp: str
    SignatureVersion: str
    Signature: str
    SigningCertURL: str
    UnsubscribeURL: str
    Email: EmailReceivedMessage | None = None

    @model_validator(mode="before")
    def validate_message(self) -> "SNSWebhookMessage":
        try:
            self.Email = EmailReceivedMessage.model_validate_json(self.Message)
        except Exception:
            pass

        return self


class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size: int
    data: Any
    s3_key: str


class SNSSubscriptionConfirmation(BaseModel):
    Type: str
    MessageId: str
    Token: str
    TopicArn: str
    Message: str
    SubscribeURL: str
    Timestamp: str
    SignatureVersion: str
    Signature: str
    SigningCertURL: str

    # for ease of use when trying to access 'validate_sns_signature.Email'
    Email: None = None
