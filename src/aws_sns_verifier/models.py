from typing import Any, Self
from pydantic import BaseModel, model_validator
from aws_sns_verifier.attachments import extract_attachments_from_email, EmailAttachment
import logfire_api as logfire


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
        commonHeaders: dict[str, Any]

    notificationType: str
    mail: Mail

    @property
    def sender_address(self) -> str:
        """
        The sender address of the email.
        """
        return self.mail.source

    @property
    def subject(self) -> str:
        """
        The subject of the email.
        """
        for header in self.mail.headers:
            if header.name == "Subject":
                return header.value
        return ""

    @property
    def organization(self) -> str | None:
        """
        The organization of the email.
        """
        for header in self.mail.headers:
            if header.name == "Organization":
                return header.value
        return None

    def attachments(
        self, s3_client, bucket_name: str, prefix: str
    ) -> list[EmailAttachment] | None:
        """
        Extract the attachments from the email.
        """
        try:
            key = f"{prefix}/{self.mail.messageId}"
            raw_email = (
                s3_client.get_object(Bucket=bucket_name, Key=key)["Body"]
                .read()
                .decode("utf-8")
            )
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

    @model_validator(mode="after")
    def validate_message(self) -> Self:
        try:
            logfire.debug(f"Validating email message: {self.Message}")
            self.Email = EmailReceivedMessage.model_validate_json(self.Message)
        except Exception as e:
            logfire.warn(f"Failed to validate email message: {e}")

        return self


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
