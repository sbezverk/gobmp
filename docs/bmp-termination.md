# BMP Termination and connection shutdown

[RFC 7854 section 4.5](https://www.rfc-editor.org/rfc/rfc7854.html#section-4.5)
requires the monitoring station to close TCP after receiving Termination. The
collector closes the transport as soon as the complete Termination frame has
been read, without waiting for a sender FIN or a backend publication. It does
not read or publish subsequent frames from that connection.

Previously the parser logged Termination and the connection worker continued
reading. An unclosed sender connection could occupy a passive connection slot
or prevent an active connector from reconnecting.

Accepted frames still drain through the parser and producer before the worker
returns. RAW mode forwards the Termination frame in order; parsed mode retains
its existing diagnostic-only handling. A blocked backend call can therefore
delay worker completion, slot release, server Stop and active reconnection,
although TCP has already been closed. This change adds no hard shutdown
deadline, backend cancellation, delivery acknowledgement or flush guarantee.

Active mode reconnects after drain using the existing backoff policy. Maximum
frame sizes, handling of incomplete frames and ordinary EOF/Stop behavior are
unchanged. No configuration or public API change is required. Rolling back the
change restores the previous behavior of waiting for EOF after Termination.
