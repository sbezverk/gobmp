# Unknown BMP message types

[RFC 7854 section 4.1](https://www.rfc-editor.org/rfc/rfc7854.html#section-4.1)
requires BMP implementations to ignore unrecognized message types. The collector
uses their declared frame length to continue processing subsequent messages.
This applies when an unknown frame has an empty body as well as when it carries
payload bytes. Parsed mode ignores the unknown frame; RAW mode preserves its
complete BMP bytes in the OpenBMP envelope and preserves connection order.

Previously the connection worker rejected every empty body except Initiation
and Termination. An unknown type with total Length=6 therefore closed the TCP
connection and prevented subsequent valid frames from reaching the publisher.
The empty-body rejection now applies only to the currently known peer-bearing
types: Route Monitoring, Statistics Report, Peer Down, Peer Up and Route
Mirroring (types 0, 1, 2, 3 and 6).

The six-byte minimum common-header length, version validation, integer-overflow
check and maximum payload limit of 1 MiB are unchanged. An unknown frame that
violates those guards still closes the connection. Truncated payloads are never
published. This adds no interpretation or typed support for unknown extensions,
configuration, dependency or public API change.

No consumer migration is required. RAW consumers can now receive an empty
unknown frame that previously caused a disconnect. Rolling back restores that
disconnect behavior; it does not alter any retained publications.
