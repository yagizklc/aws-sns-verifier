import email
from typing import Any

import logfire_api as logfire
from pydantic import BaseModel


class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size: int
    data: Any
    s3_key: str


@logfire.instrument("Extracting attachments from email")
def extract_attachments_from_email(raw_email: str, key: str) -> list[EmailAttachment]:
    """
    Extract attachments from raw email message.

    Args:
        raw_email: Raw email message string

    Returns:
        List of EmailAttachment objects
    """
    attachments = []

    try:
        # Parse the email & Walk through all parts of the email
        email_message = email.message_from_string(raw_email)
        email_parts = list(email_message.walk())
        logfire.debug(f"Parsed email with {len(email_parts)} parts")

        for part in email_parts:
            # Skip non-attachment parts
            if part.get_content_maintype() == "multipart":
                continue

            # Check if this part is an attachment
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" not in content_disposition:
                continue

            # Extract attachment information
            filename = part.get_filename()
            if not filename:
                continue

            # Get the payload (attachment data)
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            attachment = EmailAttachment(
                filename=filename,
                content_type=content_type,
                size=len(payload),
                data=payload,
                s3_key=key,
            )
            attachments.append(attachment)
            logfire.debug(f"Extracted attachment: {filename} ({len(payload)} bytes)")

        logfire.info(
            f"Successfully extracted {len(attachments)} attachments from email"
        )

    except Exception as e:
        logfire.warn(f"Failed to extract attachments: {e}")
        raise Exception(f"Failed to extract attachments: {e}")

    return attachments
