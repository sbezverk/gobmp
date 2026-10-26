# Native BMP serialization

`bmp.Message.Serialize() ([]byte, error)` builds a complete BMP version 3 frame
from the existing goBMP structures. It infers the message type from `Payload` and
returns independently owned bytes. Serialization does not mutate the input.

## Build an Initiation message

```go
package main

import (
    "fmt"
    "log"

    "github.com/sbezverk/gobmp/pkg/bmp"
)

func main() {
    msg := &bmp.Message{
        Payload: &bmp.InitiationMessage{
            TLV: []bmp.InformationalTLV{
                {InformationType: 1, Information: []byte("Example BMP speaker")},
                {InformationType: 2, Information: []byte("router-1")},
            },
        },
    }
    frame, err := msg.Serialize()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%x\n", frame)
}
```

The writer requires both sysDescr (type 1) and sysName (type 2), as specified by
[RFC 7854 section 4.3](https://www.rfc-editor.org/rfc/rfc7854.html#section-4.3).
It preserves additional TLVs and their order. The existing reader remains tolerant
of incomplete Initiation messages.

## Supported structures

| `Message.Payload` | Body serializer | Per-peer header |
| --- | --- | --- |
| `*bmp.RouteMonitor` | Complete embedded BGP UPDATE | Required |
| `*bmp.StatsReport` | Statistics count and TLVs | Required |
| `*bmp.PeerDownMessage` | Reason and reason-specific data | Required |
| `*bmp.PeerUpMessage` | Local address/ports, two BGP OPENs and informational TLVs | Required |
| `*bmp.InitiationMessage` | Informational TLVs | Forbidden |
| `*bmp.TerminationMessage` | Strings and mandatory Reason TLV | Forbidden |

Each listed payload has its own `Serialize()` method returning its body.
`PerPeerHeader.Serialize()` returns 42 bytes; `InformationalTLV.Serialize()` returns
a TLV. `bgp.OpenMessage.Serialize()` and `bgp.Update.Serialize()` return complete
BGP messages, including the 16-byte marker. `SpeakerIP` and `PeerIdentity` are
collector metadata and do not enter the wire representation.

BMP/BGP message lengths, optional-parameter lengths, UPDATE section lengths,
attribute lengths, TLV lengths and statistics counts are derived from the actual
data. Stored length/count fields are not authoritative. An attribute value over
255 bytes uses the extended-length flag. Invalid inputs return an error and no
partial output: examples include nil/unsupported payloads, missing or unexpected
peer headers, wrong field widths, reserved flags and oversized values.

## Peer flags and ASN width

Build `PerPeerHeader` using full wire-width slices: eight bytes for the
distinguisher, sixteen for the peer address, four for the BGP ID and eight for
the timestamp. IPv4 addresses occupy the final four address bytes, with zero
padding. Timestamp microseconds must be below 1,000,000.

Call `peer.SetFlags(flags)` after setting `PeerType`. For types 0–2, bits
`0x80/0x40/0x20/0x10` select V/L/A/O. In particular, A=1 selects two-byte AS_PATH
encoding; A=0 selects four-byte encoding. This setter changes the flags and
rejects reserved bits. Serialization preserves raw ASN widths and checks them
against the full BMP frame's peer header; it does not convert AS_PATH/AS4_PATH.

For Loc-RIB type 3, only F (`0x80`) is defined. The address is zero-filled, while
the distinguisher may be any locally defined eight-byte value. Full Loc-RIB
messages enforce AS4 Route Monitoring, reason 6 Peer Down TLVs, and zero-address,
zero-port Peer Up with identical fabricated OPENs containing AS4 capability.
See [RFC 9069 sections 5.1–5.4](https://www.rfc-editor.org/rfc/rfc9069.html#section-5).

## BGP inputs and compatibility

OPEN uses both `OptionalParameters` and the `Capabilities` map. Map keys are
encoded in increasing code order, retaining repeated entries. Supplying raw
type-2 optional parameters together with a nonempty map is an error. Ordinary
encoding supports a total of 255 optional-parameter bytes. Above 255, the writer
uses the [RFC 9072 section 2](https://www.rfc-editor.org/rfc/rfc9072.html#section-2)
sentinel and extended parameter lengths; type 255 cannot be supplied as an
ordinary parameter. Individual capability values still use one-byte lengths.

UPDATE's `WithdrawnRoutes`, `PathAttributes` and `NLRI` are its authoritative wire
inputs. `BaseAttributes` is a derived cache: changing it does not rewrite raw
attributes. A nonempty semantic-only `BaseAttributes` with no raw attributes is
rejected instead of silently becoming an empty UPDATE. Parsed EOR/withdrawal-only
messages remain serializable despite their nonnil cache and derived hash.

Context-free UPDATE/RouteMonitor serializers preserve zero-length ORIGIN,
NEXT_HOP and LOCAL_PREF placeholders. A complete BMP frame permits them only for
peer types 0–2 with O=1 and L=0, as allowed by
[RFC 8671 section 5.2](https://www.rfc-editor.org/rfc/rfc8671.html#section-5.2).
An empty AS_PATH is independently valid. Invalid nonzero lengths/ORIGIN values
still fail. Raw NLRI, including ADD-PATH IDs, must already match the session;
there is no semantic-to-wire NLRI builder.

The new BGP serializers enforce the ordinary 4096-byte message limit from
[RFC 4271 section 4.1](https://www.rfc-editor.org/rfc/rfc4271.html#section-4.1).
RFC 8654 extended-size messages return an error. Existing readers and
`CommonHeader.Serialize()` are unchanged. No dependency or publisher/player
interface changes are needed.

Round trips preserve represented semantics, not necessarily identical bytes:
OPEN parsing normalizes capability grouping and Termination parsing discards
unknown TLVs/original ordering. There is no RAW passthrough builder or typed Route
Mirroring support. Validation is structural plus the existing parser's supported
attribute checks; it is not an exhaustive validator for every opaque NLRI family.
