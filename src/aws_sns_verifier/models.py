from typing import Any

from pydantic import BaseModel


class EmailWebhookMessage(BaseModel):
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


class EmailWebhookRequest(BaseModel):
    Type: str
    MessageId: str
    TopicArn: str
    Subject: str
    Message: str | EmailWebhookMessage
    Timestamp: str
    SignatureVersion: str
    Signature: str
    SigningCertURL: str
    UnsubscribeURL: str


class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size: int
    data: Any


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
