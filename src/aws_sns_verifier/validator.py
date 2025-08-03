import base64
import functools
import json
import re
from datetime import datetime, timezone

import urllib.request
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1, SHA256

from aws_sns_verifier.models import SNSWebhookMessage, SNSSubscriptionConfirmation

_DEFAULT_CERTIFICATE_URL_REGEX = (
    r"^https://sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?/"
)


def validate_sns_signature(
    message: dict | bytes,
    expected_topic_arn: str | None = None,
    auto_confirm_subscription: bool = True,
) -> SNSWebhookMessage | SNSSubscriptionConfirmation:
    """
    Validate the signature of an SNS message.

    Args:
        message: The message to validate.
        expected_topic_arn: The expected topic ARN.
        is_mail_message: Whether the message is a mail message.
        auto_confirm_subscription: Whether to auto confirm subscription / unsubscribe.

    Returns:
        The validated message.
    """
    try:
        body = _validate_message_type(message)
        _validate_certificate_url(cert_url=body.SigningCertURL)
        hash_algorithm = _validate_signature_version(
            signature_version=body.SignatureVersion
        )

        if expected_topic_arn:
            assert body.TopicArn == expected_topic_arn, (
                f"Unexpected TopicArn: {body.TopicArn} != {expected_topic_arn}"
            )

        cert = _get_certificate(body.SigningCertURL)
        _validate_certificate(cert)
        public_key = cert.public_key()
        plaintext = _get_plaintext_to_sign(body).encode()
        signature = base64.b64decode(body.Signature)
        public_key.verify(  # type: ignore
            signature,
            plaintext,
            PKCS1v15(),  # type: ignore
            hash_algorithm,  # type: ignore
        )

        # auto confirm subscription
        _handle_auto_confirm_subscription(body, auto_confirm_subscription)

        return body
    except Exception as e:
        raise Exception(f"Invalid signature: {e}")


def _validate_message_type(
    message: dict | bytes,
) -> SNSWebhookMessage | SNSSubscriptionConfirmation:
    message = json.loads(message) if isinstance(message, bytes) else message
    assert isinstance(message, dict), "Message must be a dictionary"

    message_type = message["Type"]
    if (
        message_type == "SubscriptionConfirmation"
        or message_type == "UnsubscribeConfirmation"
    ):
        return SNSSubscriptionConfirmation.model_validate(message)
    elif message_type == "Notification":
        return SNSWebhookMessage.model_validate(message)
    else:
        raise Exception(f"Invalid message type: {message['Type']}")


def _validate_signature_version(signature_version: str) -> SHA1 | SHA256:
    assert signature_version in ["1", "2"], "Invalid signature version, must be 1 or 2"
    return SHA1() if signature_version == "1" else SHA256()


def _validate_certificate_url(cert_url: str) -> None:
    assert re.search(_DEFAULT_CERTIFICATE_URL_REGEX, cert_url), (
        "Invalid certificate URL."
    )


def _validate_certificate(cert: x509.Certificate) -> None:
    """Validate that the certificate is issued by Amazon SNS"""
    try:
        # Check if certificate is issued by Amazon
        issuer = cert.issuer

        # Basic validation that this looks like an Amazon certificate
        amazon_indicators = ["Amazon", "AWS", "amazon.com"]
        issuer_string = str(issuer)

        if not any(indicator in issuer_string for indicator in amazon_indicators):
            raise Exception("Certificate not issued by Amazon")

        now = datetime.now(timezone.utc)
        if cert.not_valid_after_utc < now:
            raise Exception("Certificate has expired")
        if cert.not_valid_before_utc > now:
            raise Exception("Certificate not yet valid")

    except Exception as e:
        raise Exception(f"Certificate validation failed: {e}")


@functools.lru_cache(maxsize=10)
def _get_certificate(cert_url: str):
    with urllib.request.urlopen(cert_url) as response:
        return x509.load_pem_x509_certificate(
            data=response.read(), backend=default_backend()
        )


def _get_plaintext_to_sign(
    body: SNSWebhookMessage | SNSSubscriptionConfirmation,
) -> str:
    message_type = body.Type
    if (
        message_type == "SubscriptionConfirmation"
        or message_type == "UnsubscribeConfirmation"
    ):
        assert isinstance(body, SNSSubscriptionConfirmation), (
            "SubscriptionConfirmation body must be an SNSSubscriptionConfirmation"
        )
        keys = (
            "Message",
            "MessageId",
            "SubscribeURL",
            "Timestamp",
            "Token",
            "TopicArn",
            "Type",
        )
    elif message_type == "Notification":
        assert isinstance(body, SNSWebhookMessage), (
            "Notification body must be an SNSWebhookMessage"
        )
        if body.Subject:
            keys = (
                "Message",
                "MessageId",
                "Subject",
                "Timestamp",
                "TopicArn",
                "Type",
            )
        else:
            keys = (
                "Message",
                "MessageId",
                "Timestamp",
                "TopicArn",
                "Type",
            )
    pairs = [f"{key}\n{getattr(body, key)}" for key in keys]
    return "\n".join(pairs) + "\n"


def _handle_auto_confirm_subscription(
    body: SNSSubscriptionConfirmation | SNSWebhookMessage,
    auto_confirm_subscription: bool,
) -> None:
    if auto_confirm_subscription and (
        body.Type == "SubscriptionConfirmation"
        or body.Type == "UnsubscribeConfirmation"
    ):
        assert isinstance(body, SNSSubscriptionConfirmation), (
            "SubscriptionConfirmation body must be an SNSSubscriptionConfirmation"
        )
        with urllib.request.urlopen(body.SubscribeURL) as response:
            response.read()
