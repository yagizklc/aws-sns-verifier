# AWS SNS Verifier

A Python library for verifying AWS SNS signatures based on the [official AWS documentation](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html).

## Features

- Validates SNS message signatures (SHA1 and SHA256)
- Supports notification and subscription confirmation messages
- Email attachment extraction from SNS messages
- Type-safe Pydantic models
- Certificate validation and caching

## Installation

```bash
uv add aws-sns-verifier
```

## Usage

```python
from aws_sns_verifier.validator import validate_sns_signature
from aws_sns_verifier.models import EmailWebhookRequest

# Parse your SNS message
sns_message = EmailWebhookRequest(**sns_json_data)

# Verify the signature
validate_sns_signature(sns_message, expected_topic_arn="arn:aws:sns:...")
```

## Publish

```bash

#.env
UV_PUBLISH_TOKEN=pypi-...

# export all envs in .env to the terminal
export $(cat .env | xargs)
uv build && uv publish
```

 

## Dependencies

- Python 3.13+
- `cryptography>=45.0.5`
- `pydantic>=2.11.7`
