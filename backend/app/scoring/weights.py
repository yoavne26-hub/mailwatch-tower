"""Planned deterministic signal weights and category colors."""

CATEGORY_COLORS: dict[str, str] = {
    "sender": "#A67C52",
    "links": "#0B3D91",
    "attachments": "#E91E63",
    "content": "#000000",
    "headers": "#6A1B9A",
    "metadata": "#4A4A4A",
}

CATEGORY_LABELS: dict[str, str] = {
    "sender": "Sender Identity",
    "links": "Links and URLs",
    "attachments": "Attachments",
    "content": "Content/social engineering",
    "headers": "Headers/authentication",
    "metadata": "Metadata/context",
}

# TODO: Expand these constants into signal definitions when analyzers are built.

