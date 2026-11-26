import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class emailStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EMAIL_STATUS_UNSPECIFIED: _ClassVar[emailStatus]
    EMAIL_STATUS_GOOD: _ClassVar[emailStatus]
    EMAIL_STATUS_BAD: _ClassVar[emailStatus]
EMAIL_STATUS_UNSPECIFIED: emailStatus
EMAIL_STATUS_GOOD: emailStatus
EMAIL_STATUS_BAD: emailStatus

class email(_message.Message):
    __slots__ = ("message_id", "sender", "to", "cc", "bcc", "subject", "plain_text_body", "html_body", "sent_at", "attachment_urls", "custom_headers", "status", "status_reason", "pipeline_state", "severity", "score", "findings", "action_taken")
    class CustomHeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    CC_FIELD_NUMBER: _ClassVar[int]
    BCC_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    PLAIN_TEXT_BODY_FIELD_NUMBER: _ClassVar[int]
    HTML_BODY_FIELD_NUMBER: _ClassVar[int]
    SENT_AT_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_URLS_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_HEADERS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    STATUS_REASON_FIELD_NUMBER: _ClassVar[int]
    PIPELINE_STATE_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    ACTION_TAKEN_FIELD_NUMBER: _ClassVar[int]
    message_id: str
    sender: str
    to: _containers.RepeatedScalarFieldContainer[str]
    cc: _containers.RepeatedScalarFieldContainer[str]
    bcc: _containers.RepeatedScalarFieldContainer[str]
    subject: str
    plain_text_body: str
    html_body: str
    sent_at: _timestamp_pb2.Timestamp
    attachment_urls: _containers.RepeatedScalarFieldContainer[str]
    custom_headers: _containers.ScalarMap[str, str]
    status: emailStatus
    status_reason: str
    pipeline_state: str
    severity: str
    score: int
    findings: _containers.RepeatedScalarFieldContainer[str]
    action_taken: str
    def __init__(self, message_id: _Optional[str] = ..., sender: _Optional[str] = ..., to: _Optional[_Iterable[str]] = ..., cc: _Optional[_Iterable[str]] = ..., bcc: _Optional[_Iterable[str]] = ..., subject: _Optional[str] = ..., plain_text_body: _Optional[str] = ..., html_body: _Optional[str] = ..., sent_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., attachment_urls: _Optional[_Iterable[str]] = ..., custom_headers: _Optional[_Mapping[str, str]] = ..., status: _Optional[_Union[emailStatus, str]] = ..., status_reason: _Optional[str] = ..., pipeline_state: _Optional[str] = ..., severity: _Optional[str] = ..., score: _Optional[int] = ..., findings: _Optional[_Iterable[str]] = ..., action_taken: _Optional[str] = ...) -> None: ...

class analyzeMsg(_message.Message):
    __slots__ = ("email_to_analyze",)
    EMAIL_TO_ANALYZE_FIELD_NUMBER: _ClassVar[int]
    email_to_analyze: email
    def __init__(self, email_to_analyze: _Optional[_Union[email, _Mapping]] = ...) -> None: ...

class listMsg(_message.Message):
    __slots__ = ("list_size", "list_token")
    LIST_SIZE_FIELD_NUMBER: _ClassVar[int]
    LIST_TOKEN_FIELD_NUMBER: _ClassVar[int]
    list_size: int
    list_token: str
    def __init__(self, list_size: _Optional[int] = ..., list_token: _Optional[str] = ...) -> None: ...

class severityMsg(_message.Message):
    __slots__ = ("message_id",)
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    message_id: str
    def __init__(self, message_id: _Optional[str] = ...) -> None: ...

class analyzeReply(_message.Message):
    __slots__ = ("analyzed_email",)
    ANALYZED_EMAIL_FIELD_NUMBER: _ClassVar[int]
    analyzed_email: email
    def __init__(self, analyzed_email: _Optional[_Union[email, _Mapping]] = ...) -> None: ...

class listReply(_message.Message):
    __slots__ = ("emails", "next_list_token")
    EMAILS_FIELD_NUMBER: _ClassVar[int]
    NEXT_LIST_TOKEN_FIELD_NUMBER: _ClassVar[int]
    emails: _containers.RepeatedCompositeFieldContainer[email]
    next_list_token: str
    def __init__(self, emails: _Optional[_Iterable[_Union[email, _Mapping]]] = ..., next_list_token: _Optional[str] = ...) -> None: ...

class severityReply(_message.Message):
    __slots__ = ("severity",)
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    severity: str
    def __init__(self, severity: _Optional[str] = ...) -> None: ...
