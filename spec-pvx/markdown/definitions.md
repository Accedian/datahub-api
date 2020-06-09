---
title: 'PVX API :: Documentation\> Definitions'
---

From: Snapshot-Content-Location:
https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/doc/definitions
Subject: PVX API :: Documentation\> Definitions Date: Sun, 7 Jun 2020
01:44:10 -0000 MIME-Version: 1.0 Content-Type: multipart/related;
type=\"text/html\";
boundary=\"\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--\"
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: text/html Content-ID: Content-Transfer-Encoding:
quoted-printable Content-Location:
https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/doc/definitions

::: {.3D\"Logo\"}
![](3D%22https://accedian.com/wp-content/themes/acce=){width="3D\"200px\""}
:::

PVX API
=======

Version 0.4

-   [Functions](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/doc/=)
-   [Definitions](3D%22https://pvdev2.pvdev2.npav.accedian.net/pv=)
-   [PVQL](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/doc/=)
-   [Changelog](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/doc/=)

::: {role="main"}
Table of contents
-----------------

::: {.3D\"Nav\"}
1.  [Fields](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
2.  [Types](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0=)
3.  [Values](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0=)
:::

Fields {#3D\"fields-list\"}
------

List of fields (both *values* and *keys*) used in [PVQL](3D%22=) to
query data.

::: {#3D\"filter-by-layer\"}
:::

::: {.section}
Field Name
:::
:::

Type

Layers

Description

[]{#3D\"field-aborts\"}

    aborts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of aborted Citrix sessions

[]{#3D\"field-aborts.ratio\"}

    aborts.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The ratio of aborts to the total number of la= unch attempts

[]{#3D\"field-ajax.requests\"}

    ajax.requests

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of javascript requests

[]{#3D\"field-alert.access_denied\"}

    alert.access_denied

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A valid certificate was received, but when ac= cess control was applied,
the sender decided not to proceed with negotiatio= n. Code 49.

[]{#3D\"field-alert.bad_certificate\"}

    alert.bad_certificate

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A certificate was corrupt, contained signatur= es that did not verify
correctly, etc. Code 42.

[]{#3D\"field-alert.bad_record_mac\"}

    alert.bad_record_mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This alert is returned if a record is receive= d with an incorrect MAC.
Code 20.

[]{#3D\"field-alert.certificate_expired\"}

    alert.certificate_ex=
    pired

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A certificate has expired or is not currently= valid. Code 45.

[]{#3D\"field-alert.certificate_revoked\"}

    alert.certificate_re=
    voked

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A certificate was revoked by its signer. Code= 44.

[]{#3D\"field-alert.certificate_unknown\"}

    alert.certificate_un=
    known

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Some other (unspecified) issue arose in proce= ssing the certificate,
rendering it unacceptable. Code 46.

[]{#3D\"field-alert.close_notify\"}

    alert.close_notify

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This message notifies the recipient that the = sender will not send any
more messages on this connection. Code 0.

[]{#3D\"field-alert.decode_error\"}

    alert.decode_error

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A message could not be decoded because some f= ield was out of the
specified range or the length of the message was incorr= ect. Code 50.

[]{#3D\"field-alert.decompression_failure\"}

    alert.decompressio=
    n_failure

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

The decompression function received improper = input (e.g., data that
would expand to excessive length). Code 30.

[]{#3D\"field-alert.decrypt_error\"}

    alert.decrypt_error

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A handshake cryptographic operation failed, i= ncluding being unable to
correctly verify a signature or validate a Finishe= d message. Code 51.

[]{#3D\"field-alert.decryption_failed\"}

    alert.decryption_faile=
    d

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This alert was used in some earlier versions = of TLS, and may have
permitted certain attacks against the CBC mode. Code 2= 1.

[]{#3D\"field-alert.export_restriction\"}

    alert.export_restrict=
    ion

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This alert was used in some earlier versions = of TLS. Code 60.

[]{#3D\"field-alert.handshake_failure\"}

    alert.handshake_failur=
    e

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Reception of a handshake failure alert messag= e indicates that the
sender was unable to negotiate an acceptable set of se= curity
parameters given the options available. Code 40.

[]{#3D\"field-alert.illegal_parameter\"}

    alert.illegal_paramete=
    r

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A field in the handshake was out of range or = inconsistent with other
fields. Code 47.

[]{#3D\"field-alert.insufficient_security\"}

    alert.insufficient=
    _security

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Returned instead of a handshake failure when = a negotiation has failed
specifically because the server requires ciphers m= ore secure than
those supported by the client. Code 71.

[]{#3D\"field-alert.internal_error\"}

    alert.internal_error

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

An internal error unrelated to the peer or th= e correctness of the
protocol (such as a memory allocation failure) makes i= t impossible to
continue. Code 80.

[]{#3D\"field-alert.no_certificate\"}

    alert.no_certificate

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This alert was used in SSLv3 but not any vers= ion of TLS. Code 41.

[]{#3D\"field-alert.no_renegotiation\"}

    alert.no_renegotiation<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Sent by the client in response to a hello req= uest or by the server in
response to a client hello after initial handshaki= ng. Code 100.

[]{#3D\"field-alert.protocol_version\"}

    alert.protocol_version<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

The protocol version the client has attempted= to negotiate is
recognized but not supported. Code 70.

[]{#3D\"field-alert.record_overflow\"}

    alert.record_overflow

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A TLSCiphertext record was received that had = a length more than
2\^14+2048 bytes, or a record decrypted to a TLSCompresse= d record with
more than 2\^14+1024 bytes. Code 22.

[]{#3D\"field-alert.unexpected_message\"}

    alert.unexpected_mess=
    age

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

An inappropriate message was received. Code 1= 0.

[]{#3D\"field-alert.unknown_ca\"}

    alert.unknown_ca

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A valid certificate chain or partial chain wa= s received, but the
certificate was not accepted because the CA certificate= could not be
located or couldn\'t be matched with a known, trusted CA. Code= 48.

[]{#3D\"field-alert.unsupported_certificate\"}

    alert.unsupporte=
    d_certificate

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

A certificate was of an unsupported type. Cod= e 43.

[]{#3D\"field-alert.unsupported_extension\"}

    alert.unsupported_=
    extension

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Sent by clients that receive an extended serv= er hello containing an
extension that they did not put in the corresponding= client hello. Code
110.

[]{#3D\"field-alert.user_canceled\"}

    alert.user_canceled

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

This handshake is being canceled for some rea= son unrelated to a
protocol failure. Code 90.

[]{#3D\"field-alert_types\"}

    alert_types

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    alerttypes

    tls

Flags of alerts present in the TLS conversati= on

[]{#3D\"field-application.id\"}

    application.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    application_id

    citrix
    citrix_channels
    databases
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The application ID

[]{#3D\"field-application.name\"}

    application.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    application

    citrix
    citrix_channels
    databases
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The application

[]{#3D\"field-attempts\"}

    attempts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of launch attempts

[]{#3D\"field-begins\"}

    begins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of VoIP flows that started

[]{#3D\"field-call\"}

    call

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The VoIP call id

[]{#3D\"field-call.direction\"}

    call.direction

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    calldirection

    voip

The direction (inbound, outbound, unknown) of= the VoIP calls

[]{#3D\"field-call.duration\"}

    call.duration

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total duration of the VoIP calls

[]{#3D\"field-call.global.jitter\"}

    call.global.jitter

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average measured jitter for call PDUs (pr= otocol data units) in
both directions

[]{#3D\"field-call.global.rtt\"}

    call.global.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for call PDUs (pr= otocol data units) in
both directions

[]{#3D\"field-call.jitter.count\"}

    call.jitter.count

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of measured jitters for call= PDUs (protocol data
units) in both directions

[]{#3D\"field-call.jitter.deviation\"}

    call.jitter.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the measured jitter for call= PDUs (protocol data
units) in both directions

[]{#3D\"field-call.jitter.total\"}

    call.jitter.total

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The sum of both caller and callee average rou= nd-trip times

[]{#3D\"field-call.rtt.count\"}

    call.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of round-trip times for call= PDUs (protocol data
units) in both directions

[]{#3D\"field-call.rtt.deviation\"}

    call.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for call= PDUs (protocol data
units) in both directions

[]{#3D\"field-call.rtt.total\"}

    call.rtt.total

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The sum of both caller and callee average rou= nd-trip times

[]{#3D\"field-call.state\"}

    call.state

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    callstate

    voip

The latest call state in this conversation

[]{#3D\"field-callee\"}

    callee

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The VoIP callee id

[]{#3D\"field-callee.codec\"}

    callee.codec

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The voice codec of the callee

[]{#3D\"field-callee.ip\"}

    callee.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    voip

The IP address of the callee

[]{#3D\"field-callee.jitter\"}

    callee.jitter

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average measured jitter for a PDU (protoc= ol data unit) emitted by
the callee

[]{#3D\"field-callee.jitter.count\"}

    callee.jitter.count

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of measured jitters for PDUs (prot= ocol data units) emitted
by the callee

[]{#3D\"field-callee.jitter.deviation\"}

    callee.jitter.deviatio=
    n

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the measured jitters for PDU= s (protocol data units)
emitted by the callee

[]{#3D\"field-callee.label\"}

    callee.label

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The display name of the callee

[]{#3D\"field-callee.lost.pdus\"}

    callee.lost.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of lost callee PDUs (protocol data= units)

[]{#3D\"field-callee.lost.pdus.ratio\"}

    callee.lost.pdus.ratio<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of lost to the total number of PDUs= (protocol data units)
emitted by the callee

[]{#3D\"field-callee.mac\"}

    callee.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    voip

The MAC address of the Callee

[]{#3D\"field-callee.rtt\"}

    callee.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for PDUs (protoco= l data units) emitted by
the caller

[]{#3D\"field-callee.rtt.count\"}

    callee.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for PDUs (prot= ocol data units) emitted
by the caller

[]{#3D\"field-callee.rtt.deviation\"}

    callee.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the caller

[]{#3D\"field-callee.zone.id\"}

    callee.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    voip

The zone ID of the callee

[]{#3D\"field-callee.zone.name\"}

    callee.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    voip

The zone of the callee

[]{#3D\"field-caller\"}

    caller

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The VoIP caller id

[]{#3D\"field-caller.codec\"}

    caller.codec

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The voice codec of the caller

[]{#3D\"field-caller.ip\"}

    caller.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    voip

The IP address of the caller

[]{#3D\"field-caller.jitter\"}

    caller.jitter

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average measured jitter for a PDU (protoc= ol data unit) emitted by
the the caller

[]{#3D\"field-caller.jitter.count\"}

    caller.jitter.count

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of measured jitters for PDUs (prot= ocol data units) emitted
by the caller

[]{#3D\"field-caller.jitter.deviation\"}

    caller.jitter.deviatio=
    n

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the measured jitters for PDU= s (protocol data units)
emitted by the caller

[]{#3D\"field-caller.label\"}

    caller.label

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    voip

The display name of the caller

[]{#3D\"field-caller.lost.pdus\"}

    caller.lost.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of lost caller PDUs (protocol data= units)

[]{#3D\"field-caller.lost.pdus.ratio\"}

    caller.lost.pdus.ratio<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of lost to the total number of PDUs= (protocol data units)
emitted by the caller

[]{#3D\"field-caller.mac\"}

    caller.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    voip

The MAC address of the Caller

[]{#3D\"field-caller.rtt\"}

    caller.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for PDUs (protoco= l data units) emitted by
the callee

[]{#3D\"field-caller.rtt.count\"}

    caller.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for PDUs (prot= ocol data units emitted
by the callee

[]{#3D\"field-caller.rtt.deviation\"}

    caller.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the callee

[]{#3D\"field-caller.zone.id\"}

    caller.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    voip

The zone ID of the caller

[]{#3D\"field-caller.zone.name\"}

    caller.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    voip

The zone of the caller

[]{#3D\"field-capture.hostname\"}

    capture.hostname

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    poller

    citrix
    citrix_channels
    databases
    dns
    flows
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The probe device hostname that captured this = traffic

[]{#3D\"field-capture.id\"}

    capture.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    poller_id

    citrix
    citrix_channels
    databases
    dns
    flows
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The probe device ID that captured this traffi= c

[]{#3D\"field-cgp.client.pdus\"}

    cgp.client.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of CGP PDUs (protocol data u= nits) at applicative
level emitted by the client

[]{#3D\"field-cgp.dest.pdus\"}

    cgp.dest.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of CGP PDUs (protocol data u= nits) at applicative
level emitted by the destination

[]{#3D\"field-cgp.pdus\"}

    cgp.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of CGP PDUs (protocol data u= nits) at applicative
level in both directions

[]{#3D\"field-cgp.server.pdus\"}

    cgp.server.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of CGP PDUs (protocol data u= nits) at applicative
level emitted by the server

[]{#3D\"field-cgp.source.pdus\"}

    cgp.source.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of CGP PDUs (protocol data u= nits) at applicative
level emitted by the source

[]{#3D\"field-channel\"}

    channel

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    channel

    citrix_channels

The Citrix channel

[]{#3D\"field-chunked.transfers\"}

    chunked.transfers

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of times the HTTP \'chunked\' transf= er encoding has been
used

[]{#3D\"field-cipher\"}

    cipher

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ciphersuite

    tls

The set of cryptographic algorithms used to s= ecure this conversation

[]{#3D\"field-cipher.is_weak\"}

    cipher.is_weak

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Is the TLS cipher weak?

[]{#3D\"field-citrix.application\"}

    citrix.application

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    citrix
    citrix_channels

The published Citrix application being execut= ed

[]{#3D\"field-client.common_name\"}

    client.common_name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The Common Name of the client certificate

[]{#3D\"field-client.compressed.pdus\"}

    client.compressed.pdus<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The number of compressed client PDUs (protoco= l data units)

[]{#3D\"field-client.compressed.pdus.ratio\"}

    client.compressed=
    .pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The ratio of compressions to the total number= of PDUs (protocol data
units) emitted by the client

[]{#3D\"field-client.data\"}

    client.data

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of client data PDUs (protoco= l data units)

[]{#3D\"field-client.datasource.kind\"}

    client.datasource.kind<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcekind

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type (pcap file, netflow, n= etwork iface, rpcapd) on
which this traffic has been captured (client-side)=

[]{#3D\"field-client.datasource.name\"}

    client.datasource.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source name on which this traffic = has been captured
(client-side)

[]{#3D\"field-client.datasource.pair\"}

    client.datasource.pair<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcepair

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type and name on which this= traffic has been captured
(client-side)

[]{#3D\"field-client.diffserv\"}

    client.diffserv

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    diffserv

    icmp
    other_ip
    tcp
    udp

The client differentiated service

[]{#3D\"field-client.dtt\"}

    client.dtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The average data-transfer time for PDUs (prot= ocol data units) emitted
by the client

[]{#3D\"field-client.dtt.count\"}

    client.dtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The number of data-transfer times for PDUs (p= rotocol data units)
emitted by the client

[]{#3D\"field-client.dtt.deviation\"}

    client.dtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The deviation of the data-transfer time for P= DUs (protocol data units)
emitted by the client

[]{#3D\"field-client.dupacks\"}

    client.dupacks

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of duplicated ACK packets from the= client

[]{#3D\"field-client.dupacks.ratio\"}

    client.dupacks.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of duplicated ACKs to the total num= ber of packets emitted by
the client

[]{#3D\"field-client.emtu\"}

    client.emtu

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp
    non_ip
    other_ip
    tcp
    udp

The maximum payload in a single ethernet pack= et emmited by the client
in these conversations (this value is assumed to b= e the MTU of the
client\'s network interface, although the actual MTU value = might be
greater)

[]{#3D\"field-client.error.ip\"}

    client.error.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    icmp

The IP address of the client, as it appears i= n the headers of the ICMP
error message

[]{#3D\"field-client.error.port\"}

    client.error.port

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    icmp

The port of the client, as it appears in the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-client.error.zone.id\"}

    client.error.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    icmp

The zone ID of the client, determined using t= he TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-client.error.zone.name\"}

    client.error.zone.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    icmp

The zone of the client, determined using the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-client.expiration\"}

    client.expiration

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    time

    tls

The expiration date of the client certificate=

[]{#3D\"field-client.file\"}

    client.file

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the Pcap File used as traffic sou= rce (client-side)

[]{#3D\"field-client.fins\"}

    client.fins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of FIN packets emitted by the clie= nt

[]{#3D\"field-client.fins.ratio\"}

    client.fins.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of client FIN packets in a= connection

[]{#3D\"field-client.interface\"}

    client.interface

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured (client-side)

[]{#3D\"field-client.ip\"}

    client.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    other_ip
    smb
    tcp
    tls
    udp
    voip

The IP address of the client

[]{#3D\"field-client.ja3\"}

    client.ja3

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    tls_fingerprint

    tls

The JA3 client fingerprint

[]{#3D\"field-client.keepalives\"}

    client.keepalives

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of keep alives from the client

[]{#3D\"field-client.key.bits\"}

    client.key.bits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of bits in the client key

[]{#3D\"field-client.key.type\"}

    client.key.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    keytype

    tls

The type of the client key

[]{#3D\"field-client.mac\"}

    client.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The MAC address of the client

[]{#3D\"field-client.meta\"}

    client.meta

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of client metadata (handshak= e, change cipher spec &
alerts PDU types)

[]{#3D\"field-client.os\"}

    client.os

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    os

    tcp

The client operating system

[]{#3D\"field-client.payload\"}

    client.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The total amount of bytes of data (without he= aders) emitted by the
client

[]{#3D\"field-client.payload.pdus\"}

    client.payload.pdus

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    voip

The total number of PDUs (protocol data units= ) with payload emitted by
the client

[]{#3D\"field-client.payload.ratio\"}

    client.payload.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The ratio of payload bytes to the entire traf= fic emitted by the client

[]{#3D\"field-client.pdus\"}

    client.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    dns
    icmp
    non_ip
    other_ip
    tcp
    udp
    voip

The total number of PDUs (protocol data units= ) at applicative level
emitted by the client

[]{#3D\"field-client.port\"}

    client.port

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls
    udp
    voip

The TCP/UDP port of the client

[]{#3D\"field-client.rd\"}

    client.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average retransmission delay for PDUs emi= tted by the client

[]{#3D\"field-client.rd.count\"}

    client.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of retransmission delays for PDUs = emitted by the client

[]{#3D\"field-client.rd.deviation\"}

    client.rd.deviation

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the retransmission delay for= PDUs emitted by the
client

[]{#3D\"field-client.remote\"}

    client.remote

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured via rpcapd (client-side)

[]{#3D\"field-client.retrans.payload\"}

    client.retrans.payload<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes of data (without he= aders) in retransmitted
PDUs emitted by the client

[]{#3D\"field-client.retrans.pdus.ratio\"}

    client.retrans.pdus.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmissions to the total num= ber of PDUs (protocol
data units) with payload emitted by the client

[]{#3D\"field-client.retrans.traffic\"}

    client.retrans.traffic<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes in retransmitted PD= Us emitted by the client

[]{#3D\"field-client.retrans.traffic.ratio\"}

    client.retrans.tr=
    affic.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmitted traffic to the ent= ire traffic emitted by
the client

[]{#3D\"field-client.rsts\"}

    client.rsts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of RST packets emitted by the clie= nt

[]{#3D\"field-client.rsts.ratio\"}

    client.rsts.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of client RST packets in a= connection

[]{#3D\"field-client.rtt\"}

    client.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average round-trip time for PDUs (protoco= l data units) emitted by
the server

[]{#3D\"field-client.rtt.count\"}

    client.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of round-trip times for PDUs (prot= ocol data units) emitted
by the server

[]{#3D\"field-client.rtt.deviation\"}

    client.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the server

[]{#3D\"field-client.signalization.payload\"}

    client.signalizat=
    ion.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes of data (without he= aders) in all
signalization PDUs (protocol data units) emitted by the clien= t

[]{#3D\"field-client.signalization.pdus\"}

    client.signalization=
    .pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of signalization PDUs (proto= col data units) emitted
by the client

[]{#3D\"field-client.signalization.rd\"}

    client.signalization.r=
    d

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average retransmission delay for signaliz= ation PDUs (protocol data
units) emitted by the client

[]{#3D\"field-client.signalization.rd.count\"}

    client.signaliza=
    tion.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of retransmission delays for signa= lization PDUs (protocol
data units) emitted by the client

[]{#3D\"field-client.signalization.rd.deviation\"}

    client.signa=
    lization.rd.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the retransmission delay for= signalization PDUs
(protocol data units) emitted by the client

[]{#3D\"field-client.signalization.retrans.pdus.ratio\"}

    client=
    .signalization.retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of retransmissions to the total num= ber of signalization PDUs
(protocol data units) emitted by the client

[]{#3D\"field-client.signalization.rtt\"}

    client.signalization.=
    rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for signalization= PDUs (protocol data
units) emitted by the server

[]{#3D\"field-client.signalization.rtt.count\"}

    client.signaliz=
    ation.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for signalizat= ion PDUs (protocol data
units) emitted by the server

[]{#3D\"field-client.signalization.rtt.deviation\"}

    client.sign=
    alization.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for sign= alization PDUs (protocol
data units) emitted by the server

[]{#3D\"field-client.signalization.traffic\"}

    client.signalizat=
    ion.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes in signalization PD= Us (protocol data units)
emitted by the client

[]{#3D\"field-client.signature\"}

    client.signature

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The client signature

[]{#3D\"field-client.traffic\"}

    client.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    icmp
    non_ip
    other_ip
    tcp
    tls
    udp
    voip

The total amount of bytes emitted by the clie= nt

[]{#3D\"field-client.vlan\"}

    client.vlan

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    vlan

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The VLAN id on the client side of the transac= tion

[]{#3D\"field-client.zero_windows\"}

    client.zero_windows

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of zero-window size packets emitte= d by the client

[]{#3D\"field-client.zero_windows.ratio\"}

    client.zero_windows.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of zero-window size to the total nu= mber of packets emitted
by the client

[]{#3D\"field-client.zone.id\"}

    client.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone id of the client

[]{#3D\"field-client.zone.name\"}

    client.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone of the client

[]{#3D\"field-closes\"}

    closes

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of TCP sessions that ended properl= y (by acked FIN or RST)

[]{#3D\"field-command\"}

    command

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    databasecommand

    databases

The database command type

[]{#3D\"field-compressed.pdus\"}

    compressed.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The total number of compressed PDUs (protocol= data units) in both
directions

[]{#3D\"field-compressed.pdus.ratio\"}

    compressed.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The ratio of compressions to the total number= of PDUs (protocol data
units) in both directions

[]{#3D\"field-compressed.responses\"}

    compressed.responses

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of compressed HTTP responses

[]{#3D\"field-ct\"}

    ct

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp
    tls

The average connection time

[]{#3D\"field-ct.count\"}

    ct.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp
    tls

The number of successful handshakes

[]{#3D\"field-ct.deviation\"}

    ct.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp
    tls

The deviation of the connection time

[]{#3D\"field-data.payload\"}

    data.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of data in both dir= ections

[]{#3D\"field-database\"}

    database

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    databases

The name of the database

[]{#3D\"field-dcerpc\"}

    dcerpc

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dcerpc

    tcp
    udp

The identifier of the DCE/RPC service

[]{#3D\"field-decrypted\"}

    decrypted

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of decrypted conversations

[]{#3D\"field-dest.common_name\"}

    dest.common_name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The Common Name of the destination certificat= e

[]{#3D\"field-dest.compressed.pdus\"}

    dest.compressed.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The number of compressed destination PDUs (pr= otocol data units)

[]{#3D\"field-dest.compressed.pdus.ratio\"}

    dest.compressed.pdu=
    s.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The ratio of compressions to the total number= of PDUs (protocol data
units) emitted by the destination

[]{#3D\"field-dest.data\"}

    dest.data

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of destination data PDUs (pr= otocol data units)

[]{#3D\"field-dest.datasource.kind\"}

    dest.datasource.kind

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcekind

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type (pcap file, netflow, n= etwork iface, rpcapd) on
which this traffic has been captured (destination-= side)

[]{#3D\"field-dest.datasource.name\"}

    dest.datasource.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source name on which this traffic = has been captured
(destination-side)

[]{#3D\"field-dest.datasource.pair\"}

    dest.datasource.pair

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcepair

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type and name on which this= traffic has been captured
(destination-side)

[]{#3D\"field-dest.diffserv\"}

    dest.diffserv

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    diffserv

    icmp
    other_ip
    tcp
    udp

The destination differentiated service

[]{#3D\"field-dest.dtt\"}

    dest.dtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The average data-transfer time for PDUs (prot= ocol data units) emitted
by the destination

[]{#3D\"field-dest.dtt.count\"}

    dest.dtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The number of data-transfer times for PDUs (p= rotocol data units)
emitted by the destination

[]{#3D\"field-dest.dtt.deviation\"}

    dest.dtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The deviation of the data-transfer time for P= DUs (protocol data units)
emitted by the destination

[]{#3D\"field-dest.dupacks\"}

    dest.dupacks

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of duplicated ACK packets from the= destination

[]{#3D\"field-dest.dupacks.ratio\"}

    dest.dupacks.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of duplicated ACKs to the total num= ber of packets emitted by
the destination

[]{#3D\"field-dest.emtu\"}

    dest.emtu

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp
    non_ip
    other_ip
    tcp
    udp

The maximum payload in a single ethernet pack= et emmited by the
destination in these conversations (this value is assumed= to be the MTU
of the destination\'s network interface, although the actual = MTU value
might be greater)

[]{#3D\"field-dest.error.ip\"}

    dest.error.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    icmp

The IP address of the destination, as it appe= ars in the headers of the
ICMP error message

[]{#3D\"field-dest.error.port\"}

    dest.error.port

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    icmp

The port of the destination, as it appears in= the TCP/UDP PDU (protocol
data unit) transported by the ICMP error message=

[]{#3D\"field-dest.error.zone.id\"}

    dest.error.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    icmp

The zone ID of the destination, determined us= ing the TCP/UDP PDU
(protocol data unit) transported by the ICMP error mess= age

[]{#3D\"field-dest.error.zone.name\"}

    dest.error.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    icmp

The zone of the destination, determined using= the TCP/UDP PDU (protocol
data unit) transported by the ICMP error message=

[]{#3D\"field-dest.expiration\"}

    dest.expiration

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    time

    tls

The expiration date of the destination certif= icate

[]{#3D\"field-dest.file\"}

    dest.file

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the Pcap File used as traffic sou= rce (destination-side)

[]{#3D\"field-dest.fins\"}

    dest.fins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of FIN packets emitted by the dest= ination

[]{#3D\"field-dest.fins.ratio\"}

    dest.fins.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of destination FIN packets= in a connection

[]{#3D\"field-dest.interface\"}

    dest.interface

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured (destination-side)

[]{#3D\"field-dest.ip\"}

    dest.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    other_ip
    smb
    tcp
    tls
    udp
    voip

The IP address of the destination

[]{#3D\"field-dest.ja3\"}

    dest.ja3

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    tls_fingerprint

    tls

The JA3 destination fingerprint

[]{#3D\"field-dest.keepalives\"}

    dest.keepalives

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of keep alives from the destinatio= n

[]{#3D\"field-dest.key.bits\"}

    dest.key.bits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of bits in the destination key

[]{#3D\"field-dest.key.type\"}

    dest.key.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    keytype

    tls

The type of the destination key

[]{#3D\"field-dest.mac\"}

    dest.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The MAC address of the destination

[]{#3D\"field-dest.meta\"}

    dest.meta

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of destination metadata (han= dshake, change cipher
spec & alerts PDU types)

[]{#3D\"field-dest.os\"}

    dest.os

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    os

    tcp

The destination operating system

[]{#3D\"field-dest.payload\"}

    dest.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The total amount of bytes of data (without he= aders) emitted by the
destination

[]{#3D\"field-dest.payload.pdus\"}

    dest.payload.pdus

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    voip

The total number of PDUs (protocol data units= ) with payload emitted by
the destination

[]{#3D\"field-dest.payload.ratio\"}

    dest.payload.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The ratio of payload bytes to the entire traf= fic emitted by the
destination

[]{#3D\"field-dest.pdus\"}

    dest.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    dns
    icmp
    non_ip
    other_ip
    tcp
    udp
    voip

The total number of PDUs (protocol data units= ) at applicative level
emitted by the destination

[]{#3D\"field-dest.port\"}

    dest.port

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls
    udp
    voip

The TCP/UDP port of the destination

[]{#3D\"field-dest.rd\"}

    dest.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average retransmission delay for PDUs emi= tted by the destination

[]{#3D\"field-dest.rd.count\"}

    dest.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of retransmission delays for PDUs = emitted by the
destination

[]{#3D\"field-dest.rd.deviation\"}

    dest.rd.deviation

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the retransmission delay for= PDUs emitted by the
destination

[]{#3D\"field-dest.remote\"}

    dest.remote

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured via rpcapd (destination-side)

[]{#3D\"field-dest.retrans.payload\"}

    dest.retrans.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes of data (without he= aders) in retransmitted
PDUs emitted by the destination

[]{#3D\"field-dest.retrans.pdus.ratio\"}

    dest.retrans.pdus.rati=
    o

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmissions to the total num= ber of PDUs (protocol
data units) with payload emitted by the destination

[]{#3D\"field-dest.retrans.traffic\"}

    dest.retrans.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes in retransmitted PD= Us emitted by the
destination

[]{#3D\"field-dest.retrans.traffic.ratio\"}

    dest.retrans.traffi=
    c.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmitted traffic to the ent= ire traffic emitted by
the destination

[]{#3D\"field-dest.rsts\"}

    dest.rsts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of RST packets emitted by the dest= ination

[]{#3D\"field-dest.rsts.ratio\"}

    dest.rsts.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of destination RST packets= in a connection

[]{#3D\"field-dest.rtt\"}

    dest.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average round-trip time for PDUs (protoco= l data units) emitted by
the source

[]{#3D\"field-dest.rtt.count\"}

    dest.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of round-trip times for PDUs (prot= ocol data units) emitted
by the source

[]{#3D\"field-dest.rtt.deviation\"}

    dest.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the source

[]{#3D\"field-dest.signalization.payload\"}

    dest.signalization.=
    payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes of data (without he= aders) in all
signalization PDUs (protocol data units) emitted by the desti= nation

[]{#3D\"field-dest.signalization.pdus\"}

    dest.signalization.pdu=
    s

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of signalization PDUs (proto= col data units) emitted
by the destination

[]{#3D\"field-dest.signalization.rd\"}

    dest.signalization.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average retransmission delay for signaliz= ation PDUs (protocol data
units) emitted by the destination

[]{#3D\"field-dest.signalization.rd.count\"}

    dest.signalization=
    .rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of retransmission delays for signa= lization PDUs (protocol
data units) emitted by the destination

[]{#3D\"field-dest.signalization.rd.deviation\"}

    dest.signaliza=
    tion.rd.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the retransmission delay for= signalization PDUs
(protocol data units) emitted by the destination

[]{#3D\"field-dest.signalization.retrans.pdus.ratio\"}

    dest.sig=
    nalization.retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of retransmissions to the total num= ber of signalization PDUs
(protocol data units) emitted by the destination\<= /td\>

[]{#3D\"field-dest.signalization.rtt\"}

    dest.signalization.rtt<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for signalization= PDUs (protocol data
units) emitted by the source

[]{#3D\"field-dest.signalization.rtt.count\"}

    dest.signalizatio=
    n.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for signalizat= ion PDUs (protocol data
units) emitted by the source

[]{#3D\"field-dest.signalization.rtt.deviation\"}

    dest.signaliz=
    ation.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for sign= alization PDUs (protocol
data units) emitted by the source

[]{#3D\"field-dest.signalization.traffic\"}

    dest.signalization.=
    traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes in signalization PD= Us (protocol data units)
emitted by the destination

[]{#3D\"field-dest.signature\"}

    dest.signature

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The destination signature

[]{#3D\"field-dest.traffic\"}

    dest.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    icmp
    non_ip
    other_ip
    tcp
    tls
    udp
    voip

The total amount of bytes emitted by the dest= ination

[]{#3D\"field-dest.vlan\"}

    dest.vlan

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    vlan

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The VLAN id on the destination side of the tr= ansaction

[]{#3D\"field-dest.zero_windows\"}

    dest.zero_windows

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of zero-window size packets emitte= d by the destination

[]{#3D\"field-dest.zero_windows.ratio\"}

    dest.zero_windows.rati=
    o

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of zero-window size to the total nu= mber of packets emitted
by the destination

[]{#3D\"field-dest.zone.id\"}

    dest.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone id of the destination

[]{#3D\"field-dest.zone.name\"}

    dest.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone of the destination

[]{#3D\"field-dns.rt\"}

    dns.rt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns

The average DNS response time

[]{#3D\"field-dns.rt.deviation\"}

    dns.rt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns

The deviation of the DNS response time

[]{#3D\"field-domain\"}

    domain

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    citrix
    citrix_channels
    smb

The Windows Domain of the user

[]{#3D\"field-domain.primary\"}

    domain.primary

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http
    tls

The primary domain name (www.example.org -\>= ; example.org)

[]{#3D\"field-domain.short\"}

    domain.short

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http
    tls

The primary domain name, without TLD

[]{#3D\"field-domain.toplevel\"}

    domain.toplevel

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http
    tls

The top-level domain name (TLD)

[]{#3D\"field-dtt.count\"}

    dtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The total number of data-transfer times in bo= th directions

[]{#3D\"field-dtt.deviation\"}

    dtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The deviation of the data-transfer time in bo= th directions

[]{#3D\"field-dtt.total\"}

    dtt.total

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The sum of both client and server average dat= a-transfer times

[]{#3D\"field-dupacks\"}

    dupacks

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of duplicated ACK packets in= both directions

[]{#3D\"field-dupacks.ratio\"}

    dupacks.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of duplicated ACKs to the total num= ber of packets in both
directions

[]{#3D\"field-encryption\"}

    encryption

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    encryption

    citrix

The Citrix encryption type

[]{#3D\"field-ends\"}

    ends

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of VoIP flows that ended

[]{#3D\"field-error.alerts\"}

    error.alerts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of error alerts (everything = but close notifications)

[]{#3D\"field-error.code\"}

    error.code

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    databases

The error code, specific to some databases (M= ySQL, TDS and TNS)

[]{#3D\"field-error.hits\"}

    error.hits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of hits with a response code of at= least 400

[]{#3D\"field-error.message\"}

    error.message

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    databases

The database error message

[]{#3D\"field-error.protocol\"}

    error.protocol

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ipprotocol

    icmp

The IP protocol of the PDU (protocol data uni= t) transported by the
ICMP error message

[]{#3D\"field-error.status\"}

    error.status

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    databases

The database error status

[]{#3D\"field-errors\"}

    errors

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    dns
    smb
    voip

The number of errors

[]{#3D\"field-errors.ratio\"}

    errors.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    dns
    smb
    voip

The ratio of errors to the total number of qu= eries

[]{#3D\"field-file\"}

    file

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    path

    smb

The file path

[]{#3D\"field-file.count\"}

    file.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of processed files

[]{#3D\"field-file.id\"}

    file.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    descriptor

    smb

The CIFS file descriptor id

[]{#3D\"field-fins\"}

    fins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of FIN packets in both direc= tions

[]{#3D\"field-fins.ratio\"}

    fins.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of FIN packets in a connec= tion

[]{#3D\"field-global.dtt\"}

    global.dtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The average data-transfer time in both direct= ions

[]{#3D\"field-global.emtu\"}

    global.emtu

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp
    non_ip
    other_ip
    tcp
    udp

The maximum payload in a single ethernet pack= et in both directions

[]{#3D\"field-global.rd\"}

    global.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average retransmission delay in both dire= ctions

[]{#3D\"field-global.rtt\"}

    global.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average round-trip time in both direction= s

[]{#3D\"field-global.signalization.rd\"}

    global.signalization.r=
    d

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average retransmission delay for signaliz= ation PDUs (protocol data
units) in both directions

[]{#3D\"field-global.signalization.rtt\"}

    global.signalization.=
    rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for signalization= PDUs (protocol data
units) in both directions

[]{#3D\"field-has_contributed\"}

    has_contributed

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Did this hit contribute to the metrics of the= page it is attached to?

[]{#3D\"field-has_timeouted\"}

    has_timeouted

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    databases
    http
    smb

Did this transaction timeout?

[]{#3D\"field-has_voice\"}

    has_voice

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    voip

Was there any voice in the conversation?

[]{#3D\"field-headers\"}

    headers

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of headers in both = query and response PDUs
(protocol data units)

[]{#3D\"field-hit\"}

    hit

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    uuid

    http

This hit\'s unique identifier

[]{#3D\"field-hit.parent\"}

    hit.parent

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    uuid

    http

This hit\'s parent\'s unique identifier

[]{#3D\"field-hit.referrer\"}

    hit.referrer

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    uuid

    http

This hit\'s referrer\'s unique identifier

[]{#3D\"field-hit.rt\"}

    hit.rt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The average hit response time

[]{#3D\"field-hit.rt.count\"}

    hit.rt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of HTTP hit response times

[]{#3D\"field-hit.rt.deviation\"}

    hit.rt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The deviation of the hit response time

[]{#3D\"field-hits\"}

    hits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of HTTP hits

[]{#3D\"field-host\"}

    host

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http

The URL Host

[]{#3D\"field-icmp.code\"}

    icmp.code

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp

The ICMP message code

[]{#3D\"field-icmp.message\"}

    icmp.message

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    icmpmessage

    icmp

The ICMP message

[]{#3D\"field-icmp.type\"}

    icmp.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    icmptype

    icmp

The ICMP message type

[]{#3D\"field-ip.family\"}

    ip.family

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ipfamily

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    other_ip
    smb
    tcp
    tls
    udp
    voip

The IP address family

[]{#3D\"field-ip.protocol\"}

    ip.protocol

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ipprotocol

    other_ip
    voip

The IP protocol

[]{#3D\"field-is_ajax\"}

    is_ajax

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Is this hit requested through javascript?

[]{#3D\"field-is_chunked\"}

    is_chunked

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Does this hit use HTTP \'chunked\' transfer enc= oding?

[]{#3D\"field-is_compressed\"}

    is_compressed

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Is this hit compressed?

[]{#3D\"field-is_deepinspect\"}

    is_deepinspect

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Was page reconstruction activated for this hi= t?

[]{#3D\"field-is_main\"}

    is_main

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Is this hit the main resource of the page?

[]{#3D\"field-is_root\"}

    is_root

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    http

Is this a root hit?

[]{#3D\"field-keepalives\"}

    keepalives

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The total number of keep alives in both direc= tions

[]{#3D\"field-launch.time\"}

    launch.time

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The average launch time for Citrix applicatio= ns

[]{#3D\"field-launch.time.deviation\"}

    launch.time.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The deviation of the launch time

[]{#3D\"field-layer\"}

    layer

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    layer

    citrix
    citrix_channels
    databases
    dns
    flows
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The layer

[]{#3D\"field-login.time\"}

    login.time

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The average login time

[]{#3D\"field-login.time.count\"}

    login.time.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of logins

[]{#3D\"field-login.time.deviation\"}

    login.time.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The deviation of the login time

[]{#3D\"field-lost.pdus\"}

    lost.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of lost PDUs (protocol data = units) in both directions

[]{#3D\"field-lost.pdus.ratio\"}

    lost.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of lost to the total number of PDUs= (protocol data units) in
both directions

[]{#3D\"field-metadata.payload\"}

    metadata.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of metadata in both= directions

[]{#3D\"field-metadata.read\"}

    metadata.read

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of metadata read by= SMB commands (directory
listing commands, for example)

[]{#3D\"field-metadata.written\"}

    metadata.written

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of metadata written= by SMB commands

[]{#3D\"field-method\"}

    method

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    httpquerymethod

    http

The HTTP request method

[]{#3D\"field-module\"}

    module

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    citrix

The name of the Citrix module used by the cli= ent

[]{#3D\"field-mos\"}

    mos

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The VOIP mean opinion score

[]{#3D\"field-netflow.ip\"}

    netflow.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    icmp
    tcp
    udp

The IP address of the emitter

[]{#3D\"field-nonip.protocol\"}

    nonip.protocol

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ethernetprotocol

    non_ip

The OSI layer 2 protocol

[]{#3D\"field-origin.ip\"}

    origin.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    http

The original client\'s IP, as it appears in th= e HTTP header

[]{#3D\"field-page.errors\"}

    page.errors

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of errors in all the hits that con= tributed to these pages,
errors consisting of HTTP response codes of at lea= st 400

[]{#3D\"field-page.hits\"}

    page.hits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of hits that contributed to these = pages

[]{#3D\"field-page.load.time\"}

    page.load.time

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The average page load time

[]{#3D\"field-page.load.time.deviation\"}

    page.load.time.deviat=
    ion

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The deviation of the page load time

[]{#3D\"field-page.request.traffic\"}

    page.request.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of request traffic = (headers + payload) in
all the hits that contributed to these pages

[]{#3D\"field-page.response.traffic\"}

    page.response.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of response traffic= (headers + payload) in
all the hits that contributed to these pages

[]{#3D\"field-page.timeouts\"}

    page.timeouts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of timeouts in all the hits that c= ontributed to these pages

[]{#3D\"field-page.traffic\"}

    page.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of query and respon= se traffic (headers +
payload) in all the hits that contributed to these pa= ges

[]{#3D\"field-pages\"}

    pages

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of HTTP pages

[]{#3D\"field-payload\"}

    payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    udp
    voip

The total amount of bytes of data (without he= aders) in both directions

[]{#3D\"field-payload.pdus\"}

    payload.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    voip

The total number of PDUs (protocol data units= ) with payload in both
directions

[]{#3D\"field-payload.ratio\"}

    payload.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The ratio of payload bytes to the entire traf= fic in both directions

[]{#3D\"field-pcap\"}

    pcap

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    dns
    tcp
    voip

The link to the associated captured PCAP file= (generated according to
the configuration of zones and applications)

[]{#3D\"field-pdus\"}

    pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    dns
    icmp
    non_ip
    other_ip
    smb
    tcp
    udp
    voip

The total number of PDUs (protocol data units= ) at applicative level in
both directions

[]{#3D\"field-points\"}

    points

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The number of points

[]{#3D\"field-protostack\"}

    protostack

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    protostack

    citrix
    citrix_channels
    databases
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The protocol stack

[]{#3D\"field-queries\"}

    queries

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    dns
    smb

The number of queries

[]{#3D\"field-query\"}

    query

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    databasequery

    databases

The database query

[]{#3D\"field-query.class\"}

    query.class

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dnsclass

    dns

The class of the DNS query

[]{#3D\"field-query.name\"}

    query.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    dns

The name of the DNS query

[]{#3D\"field-query.payload\"}

    query.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    smb

The total amount of bytes of payload in query= PDUs (protocol data
units) emitted by the client

[]{#3D\"field-query.pdus\"}

    query.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    smb

The total number of query PDUs (protocol data= units) at applicative
level

[]{#3D\"field-query.tcp_pdus\"}

    query.tcp_pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of TCP packets that form up these = HTTP queries

[]{#3D\"field-query.type\"}

    query.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dnstype

    dns

The type of the DNS query

[]{#3D\"field-query.write\"}

    query.write

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of data to be writt= en

[]{#3D\"field-query_256\"}

    query_256

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    databasequery

    databases

First 256 characters of the query

[]{#3D\"field-rd.count\"}

    rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of retransmission delays in = both directions

[]{#3D\"field-rd.deviation\"}

    rd.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the retransmission delay in = both directions

[]{#3D\"field-rd.total\"}

    rd.total

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The sum of both client and server average dat= a-transfer times

[]{#3D\"field-request.content_length\"}

    request.content_length<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The average Content-Length in the headers of = these HTTP requests

[]{#3D\"field-request.content_length.count\"}

    request.content_l=
    ength.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of HTTP requests with a Content-Le= ngth header

[]{#3D\"field-request.content_pack\"}

    request.content_pack

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    path

    http

The path to the pack file that contains the H= TTP request content

[]{#3D\"field-request.content_type\"}

    request.content_type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mimetype

    http

The mime-type in the Content-Type header of t= he HTTP request

[]{#3D\"field-request.headers\"}

    request.headers

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of headers in reque= st PDUs (protocol data
units) emitted by the client

[]{#3D\"field-request.payload\"}

    request.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of payload in reque= st PDUs (protocol data
units) emitted by the client

[]{#3D\"field-request.traffic\"}

    request.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes (headers + payload)= in request PDUs (protocol
data units) emitted by the client

[]{#3D\"field-response.category\"}

    response.category

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http

The HTTP response mime-type\'s category

[]{#3D\"field-response.class\"}

    response.class

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dnsclass

    dns

The class of the DNS response

[]{#3D\"field-response.code\"}

    response.code

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dnscode

    dns

The DNS response code

[]{#3D\"field-response.content_length\"}

    response.content_lengt=
    h

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The average Content-Length in the headers of = these HTTP responses

[]{#3D\"field-response.content_length.count\"}

    response.content=
    _length.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of HTTP responses with a Content-L= ength header

[]{#3D\"field-response.content_pack\"}

    response.content_pack

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    path

    http

The path to the pack file that contains the H= TTP response content

[]{#3D\"field-response.content_type\"}

    response.content_type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mimetype

    http

The mime-type in the Content-Type header of t= he HTTP response

[]{#3D\"field-response.headers\"}

    response.headers

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes of headers in respo= nse PDUs (protocol data
units) emitted by the server

[]{#3D\"field-response.payload\"}

    response.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    http
    smb

The total amount of bytes of payload in respo= nse PDUs (protocol data
units) emitted by the server

[]{#3D\"field-response.pdus\"}

    response.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    databases
    smb

The total number of PDUs (protocol data units= ) at applicative level
emitted by the server

[]{#3D\"field-response.read\"}

    response.read

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of data read by SMB= commands

[]{#3D\"field-response.status\"}

    response.status

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    httpstatus

    http

The HTTP response code

[]{#3D\"field-response.status.category\"}

    response.status.categ=
    ory

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    httpstatuscategory

\<= /td\>

    http

The category of the response status code

[]{#3D\"field-response.tcp_pdus\"}

    response.tcp_pdus

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of TCP packets that form up these = HTTP responses

[]{#3D\"field-response.traffic\"}

    response.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The total amount of bytes (headers + payload)= in response PDUs
(protocol data units) emitted by the client

[]{#3D\"field-response.type\"}

    response.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    dnstype

    dns

The type of the DNS response

[]{#3D\"field-response.written\"}

    response.written

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The total amount of bytes of data effectively= written by SMB commands

[]{#3D\"field-resumed\"}

    resumed

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of resumed sessions

[]{#3D\"field-retrans.payload\"}

    retrans.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes of data (without he= aders) in retransmitted
PDUs in both directions

[]{#3D\"field-retrans.pdus.ratio\"}

    retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmissions to the total num= ber of PDUs (protocol
data units) with payload in both directions

[]{#3D\"field-retrans.traffic\"}

    retrans.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    icmp
    non_ip
    other_ip
    tcp
    udp
    voip

The total amount of bytes in retransmitted PD= Us in both directions

[]{#3D\"field-retrans.traffic.ratio\"}

    retrans.traffic.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmitted traffic to the ent= ire traffic in both
directions

[]{#3D\"field-rows.integrated\"}

    rows.integrated

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of integrated rows

[]{#3D\"field-rows.integrated.per_minute\"}

    rows.integrated.per=
    _minute

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of integrated rows per minute

[]{#3D\"field-rows.total\"}

    rows.total

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The total number of analyzed rows

[]{#3D\"field-rows.total.per_minute\"}

    rows.total.per_minute

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of total rows per minute

[]{#3D\"field-rows.truncated\"}

    rows.truncated

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of truncated rows

[]{#3D\"field-rows.truncated.per_minute\"}

    rows.truncated.per_m=
    inute

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    flows

The number of truncated rows per minute

[]{#3D\"field-rsts\"}

    rsts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of RST packets in both direc= tions

[]{#3D\"field-rsts.ratio\"}

    rsts.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of RST packets in a connec= tion

[]{#3D\"field-rtt.count\"}

    rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of round-trip times in both = directions

[]{#3D\"field-rtt.deviation\"}

    rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the round-trip time in both = directions

[]{#3D\"field-rtt.total\"}

    rtt.total

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The sum of both client and server average rou= nd-trip times

[]{#3D\"field-server.common_name\"}

    server.common_name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The Common Name of the server certificate

[]{#3D\"field-server.compressed.pdus\"}

    server.compressed.pdus<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The number of compressed server PDUs (protoco= l data units)

[]{#3D\"field-server.compressed.pdus.ratio\"}

    server.compressed=
    .pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The ratio of compressions to the total number= of PDUs (protocol data
units) emitted by the server

[]{#3D\"field-server.data\"}

    server.data

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of server data PDUs (protoco= l data units)

[]{#3D\"field-server.datasource.kind\"}

    server.datasource.kind<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcekind

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type (pcap file, netflow, n= etwork iface, rpcapd) on
which this traffic has been captured (server-side)=

[]{#3D\"field-server.datasource.name\"}

    server.datasource.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source name on which this traffic = has been captured
(server-side)

[]{#3D\"field-server.datasource.pair\"}

    server.datasource.pair<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcepair

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type and name on which this= traffic has been captured
(server-side)

[]{#3D\"field-server.diffserv\"}

    server.diffserv

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    diffserv

    icmp
    other_ip
    tcp
    udp

The server differentiated service

[]{#3D\"field-server.dtt\"}

    server.dtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The average data-transfer time for PDUs (prot= ocol data units) emitted
by the server

[]{#3D\"field-server.dtt.count\"}

    server.dtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The number of data-transfer times for PDUs (p= rotocol data units)
emitted by the server

[]{#3D\"field-server.dtt.deviation\"}

    server.dtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The deviation of the data-transfer time for P= DUs (protocol data units)
emitted by the server

[]{#3D\"field-server.dupacks\"}

    server.dupacks

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of duplicated ACK packets from the= server

[]{#3D\"field-server.dupacks.ratio\"}

    server.dupacks.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of duplicated ACKs to the total num= ber of packets emitted by
the server

[]{#3D\"field-server.emtu\"}

    server.emtu

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp
    non_ip
    other_ip
    tcp
    udp

The maximum payload in a single ethernet pack= et emmited by the server
in these conversations (this value is assumed to b= e the MTU of the
server\'s network interface, although the actual MTU value = might be
greater)

[]{#3D\"field-server.error.ip\"}

    server.error.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    icmp

The IP address of the server, as it appears i= n the headers of the ICMP
error message

[]{#3D\"field-server.error.port\"}

    server.error.port

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    icmp

The port of the server, as it appears in the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-server.error.zone.id\"}

    server.error.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    icmp

The zone ID of the server, determined using t= he TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-server.error.zone.name\"}

    server.error.zone.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    icmp

The zone of the server, determined using the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-server.expiration\"}

    server.expiration

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    time

    tls

The expiration date of the server certificate=

[]{#3D\"field-server.file\"}

    server.file

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the Pcap File used as traffic sou= rce (server-side)

[]{#3D\"field-server.fins\"}

    server.fins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of FIN packets emitted by the serv= er

[]{#3D\"field-server.fins.ratio\"}

    server.fins.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of server FIN packets in a= connection

[]{#3D\"field-server.interface\"}

    server.interface

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured (server-side)

[]{#3D\"field-server.ip\"}

    server.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    other_ip
    smb
    tcp
    tls
    udp
    voip

The IP address of the server

[]{#3D\"field-server.ja3\"}

    server.ja3

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    tls_fingerprint

    tls

The JA3 server fingerprint

[]{#3D\"field-server.keepalives\"}

    server.keepalives

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of keep alives from the server

[]{#3D\"field-server.key.bits\"}

    server.key.bits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of bits in the server key

[]{#3D\"field-server.key.type\"}

    server.key.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    keytype

    tls

The type of the server key

[]{#3D\"field-server.mac\"}

    server.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The MAC address of the server

[]{#3D\"field-server.meta\"}

    server.meta

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of server metadata (handshak= e, change cipher spec &
alerts PDU types)

[]{#3D\"field-server.os\"}

    server.os

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    os

    tcp

The server operating system

[]{#3D\"field-server.payload\"}

    server.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The total amount of bytes of data (without he= aders) emitted by the
server

[]{#3D\"field-server.payload.pdus\"}

    server.payload.pdus

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    voip

The total number of PDUs (protocol data units= ) with payload emitted by
the server

[]{#3D\"field-server.payload.ratio\"}

    server.payload.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The ratio of payload bytes to the entire traf= fic emitted by the server

[]{#3D\"field-server.pdus\"}

    server.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    dns
    icmp
    non_ip
    other_ip
    tcp
    udp
    voip

The total number of PDUs (protocol data units= ) at applicative level
emitted by the server

[]{#3D\"field-server.port\"}

    server.port

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls
    udp
    voip

The TCP/UDP port of the server

[]{#3D\"field-server.rd\"}

    server.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average retransmission delay for PDUs emi= tted by the server

[]{#3D\"field-server.rd.count\"}

    server.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of retransmission delays for PDUs = emitted by the server

[]{#3D\"field-server.rd.deviation\"}

    server.rd.deviation

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the retransmission delay for= PDUs emitted by the
server

[]{#3D\"field-server.remote\"}

    server.remote

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured via rpcapd (server-side)

[]{#3D\"field-server.retrans.payload\"}

    server.retrans.payload<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes of data (without he= aders) in retransmitted
PDUs emitted by the server

[]{#3D\"field-server.retrans.pdus.ratio\"}

    server.retrans.pdus.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmissions to the total num= ber of PDUs (protocol
data units) with payload emitted by the server

[]{#3D\"field-server.retrans.traffic\"}

    server.retrans.traffic<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes in retransmitted PD= Us emitted by the server

[]{#3D\"field-server.retrans.traffic.ratio\"}

    server.retrans.tr=
    affic.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmitted traffic to the ent= ire traffic emitted by
the server

[]{#3D\"field-server.rsts\"}

    server.rsts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of RST packets emitted by the serv= er

[]{#3D\"field-server.rsts.ratio\"}

    server.rsts.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of server RST packets in a= connection

[]{#3D\"field-server.rt\"}

    server.rt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    smb
    tcp
    tls

The average server response time (SRT)

[]{#3D\"field-server.rt.count\"}

    server.rt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    smb
    tcp
    tls

The number of server response times

[]{#3D\"field-server.rt.deviation\"}

    server.rt.deviation

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    smb
    tcp
    tls

The deviation of the server response time

[]{#3D\"field-server.rtt\"}

    server.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average round-trip time for PDUs (protoco= l data units) emitted by
the client

[]{#3D\"field-server.rtt.count\"}

    server.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of round-trip times for PDUs (prot= ocol data units) emitted
by the client

[]{#3D\"field-server.rtt.deviation\"}

    server.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the client

[]{#3D\"field-server.signalization.last_code\"}

    server.signaliz=
    ation.last_code

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

Last SIP or MGCP response code

[]{#3D\"field-server.signalization.payload\"}

    server.signalizat=
    ion.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes of data (without he= aders) in all
signalization PDUs (protocol data units) emitted by the serve= r

[]{#3D\"field-server.signalization.pdus\"}

    server.signalization=
    .pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of signalization PDUs (proto= col data units) emitted
by the server

[]{#3D\"field-server.signalization.rd\"}

    server.signalization.r=
    d

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average retransmission delay for signaliz= ation PDUs (protocol data
units) emitted by the server

[]{#3D\"field-server.signalization.rd.count\"}

    server.signaliza=
    tion.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of retransmission delays for signa= lization PDUs (protocol
data units) emitted by the server

[]{#3D\"field-server.signalization.rd.deviation\"}

    server.signa=
    lization.rd.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the retransmission delay for= signalization PDUs
(protocol data units) emitted by the server

[]{#3D\"field-server.signalization.retrans.pdus.ratio\"}

    server=
    .signalization.retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of retransmissions to the total num= ber of signalization PDUs
(protocol data units) emitted by the server

[]{#3D\"field-server.signalization.rt\"}

    server.signalization.r=
    t

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average server response time for signaliz= ation PDUs (protocol data
units)

[]{#3D\"field-server.signalization.rt.count\"}

    server.signaliza=
    tion.rt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of server response times for signa= lization PDUs (protocol
data units)

[]{#3D\"field-server.signalization.rt.deviation\"}

    server.signa=
    lization.rt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the server response time for= signalization PDUs
(protocol data units)

[]{#3D\"field-server.signalization.rtt\"}

    server.signalization.=
    rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for signalization= PDUs (protocol data
units) emitted by the client

[]{#3D\"field-server.signalization.rtt.count\"}

    server.signaliz=
    ation.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for signalizat= ion PDUs (protocol data
units) emitted by the client

[]{#3D\"field-server.signalization.rtt.deviation\"}

    server.sign=
    alization.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for sign= alization PDUs (protocol
data units) emitted by the client

[]{#3D\"field-server.signalization.traffic\"}

    server.signalizat=
    ion.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes in signalization PD= Us (protocol data units)
emitted by the server

[]{#3D\"field-server.signature\"}

    server.signature

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The server signature

[]{#3D\"field-server.traffic\"}

    server.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    icmp
    non_ip
    other_ip
    tcp
    tls
    udp
    voip

The total amount of bytes emitted by the serv= er

[]{#3D\"field-server.vlan\"}

    server.vlan

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    vlan

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The VLAN id on the server side of the transac= tion

[]{#3D\"field-server.zero_windows\"}

    server.zero_windows

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of zero-window size packets emitte= d by the server

[]{#3D\"field-server.zero_windows.ratio\"}

    server.zero_windows.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of zero-window size to the total nu= mber of packets emitted
by the server

[]{#3D\"field-server.zone.id\"}

    server.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone id of the server

[]{#3D\"field-server.zone.name\"}

    server.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone of the server

[]{#3D\"field-server_name\"}

    server_name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The Server Name Indication of the conversatio= n

[]{#3D\"field-signalization.pdus\"}

    signalization.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of signalization PDUs (proto= col data units) in both
directions

[]{#3D\"field-signalization.rd.count\"}

    signalization.rd.count<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of retransmission delays for= signalization PDUs
(protocol data units) in both directions

[]{#3D\"field-signalization.rd.deviation\"}

    signalization.rd.de=
    viation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the retransmission delay for= signalization PDUs
(protocol data units) in both directions

[]{#3D\"field-signalization.rd.total\"}

    signalization.rd.total<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The sum of both client and server average ret= ransmission delays for
signalization PDUs (protocol data units)

[]{#3D\"field-signalization.retrans.pdus.ratio\"}

    signalization=
    .retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of retransmissions to the total num= ber of signalization PDUs
(protocol data units) in both directions

[]{#3D\"field-signalization.rtt.count\"}

    signalization.rtt.coun=
    t

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of round-trip times for sign= alization PDUs (protocol
data units) in both directions

[]{#3D\"field-signalization.rtt.deviation\"}

    signalization.rtt.=
    deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for sign= alization PDUs (protocol
data units) in both directions

[]{#3D\"field-signalization.rtt.total\"}

    signalization.rtt.tota=
    l

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The sum of both client and server average rou= nd-trip times

[]{#3D\"field-signalization.traffic\"}

    signalization.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes in signalization PD= Us (protocol data units)
in both directions

[]{#3D\"field-smb.command\"}

    smb.command

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    smbcommand

    smb

The SMB command

[]{#3D\"field-smb.command.code\"}

    smb.command.code

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The raw SMB command

[]{#3D\"field-smb.status\"}

    smb.status

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    smbstatus

    smb

The SMB status

[]{#3D\"field-smb.subcommand\"}

    smb.subcommand

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    smbsubcommand

    smb

The SMB subcommand

[]{#3D\"field-smb.subcommand.code\"}

    smb.subcommand.code

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The raw SMB subcommand

[]{#3D\"field-smb.version\"}

    smb.version

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    smb_version

    smb

The SMB protocol version

[]{#3D\"field-software\"}

    software

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    http

The software in the Server header of the HTTP= response

[]{#3D\"field-source.common_name\"}

    source.common_name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The Common Name of the source certificate

[]{#3D\"field-source.compressed.pdus\"}

    source.compressed.pdus<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The number of compressed source PDUs (protoco= l data units)

[]{#3D\"field-source.compressed.pdus.ratio\"}

    source.compressed=
    .pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix_channels

The ratio of compressions to the total number= of PDUs (protocol data
units) emitted by the source

[]{#3D\"field-source.data\"}

    source.data

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of source data PDUs (protoco= l data units)

[]{#3D\"field-source.datasource.kind\"}

    source.datasource.kind<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcekind

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type (pcap file, netflow, n= etwork iface, rpcapd) on
which this traffic has been captured (source-side)=

[]{#3D\"field-source.datasource.name\"}

    source.datasource.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source name on which this traffic = has been captured
(source-side)

[]{#3D\"field-source.datasource.pair\"}

    source.datasource.pair<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcepair

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The packet source type and name on which this= traffic has been captured
(source-side)

[]{#3D\"field-source.diffserv\"}

    source.diffserv

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    diffserv

    icmp
    other_ip
    tcp
    udp

The source differentiated service

[]{#3D\"field-source.dtt\"}

    source.dtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The average data-transfer time for PDUs (prot= ocol data units) emitted
by the source

[]{#3D\"field-source.dtt.count\"}

    source.dtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The number of data-transfer times for PDUs (p= rotocol data units)
emitted by the source

[]{#3D\"field-source.dtt.deviation\"}

    source.dtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls

The deviation of the data-transfer time for P= DUs (protocol data units)
emitted by the source

[]{#3D\"field-source.dupacks\"}

    source.dupacks

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of duplicated ACK packets from the= source

[]{#3D\"field-source.dupacks.ratio\"}

    source.dupacks.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of duplicated ACKs to the total num= ber of packets emitted by
the source

[]{#3D\"field-source.emtu\"}

    source.emtu

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    icmp
    non_ip
    other_ip
    tcp
    udp

The maximum payload in a single ethernet pack= et emmited by the source
in these conversations (this value is assumed to b= e the MTU of the
source\'s network interface, although the actual MTU value = might be
greater)

[]{#3D\"field-source.error.ip\"}

    source.error.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    icmp

The IP address of the source, as it appears i= n the headers of the ICMP
error message

[]{#3D\"field-source.error.port\"}

    source.error.port

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    icmp

The port of the source, as it appears in the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-source.error.zone.id\"}

    source.error.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    icmp

The zone ID of the source, determined using t= he TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-source.error.zone.name\"}

    source.error.zone.name<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    icmp

The zone of the source, determined using the = TCP/UDP PDU (protocol
data unit) transported by the ICMP error message

[]{#3D\"field-source.expiration\"}

    source.expiration

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    time

    tls

The expiration date of the source certificate=

[]{#3D\"field-source.file\"}

    source.file

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the Pcap File used as traffic sou= rce (source-side)

[]{#3D\"field-source.fins\"}

    source.fins

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of FIN packets emitted by the sour= ce

[]{#3D\"field-source.fins.ratio\"}

    source.fins.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of source FIN packets in a= connection

[]{#3D\"field-source.interface\"}

    source.interface

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured (source-side)

[]{#3D\"field-source.ip\"}

    source.ip

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    ip

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    other_ip
    smb
    tcp
    tls
    udp
    voip

The IP address of the source

[]{#3D\"field-source.ja3\"}

    source.ja3

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    tls_fingerprint

    tls

The JA3 source fingerprint

[]{#3D\"field-source.keepalives\"}

    source.keepalives

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of keep alives from the source

[]{#3D\"field-source.key.bits\"}

    source.key.bits

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The number of bits in the source key

[]{#3D\"field-source.key.type\"}

    source.key.type

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    keytype

    tls

The type of the source key

[]{#3D\"field-source.mac\"}

    source.mac

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    mac

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The MAC address of the source

[]{#3D\"field-source.meta\"}

    source.meta

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The total number of source metadata (handshak= e, change cipher spec &
alerts PDU types)

[]{#3D\"field-source.os\"}

    source.os

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    os

    tcp

The source operating system

[]{#3D\"field-source.payload\"}

    source.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The total amount of bytes of data (without he= aders) emitted by the
source

[]{#3D\"field-source.payload.pdus\"}

    source.payload.pdus

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    voip

The total number of PDUs (protocol data units= ) with payload emitted by
the source

[]{#3D\"field-source.payload.ratio\"}

    source.payload.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    tcp
    tls
    udp
    voip

The ratio of payload bytes to the entire traf= fic emitted by the source

[]{#3D\"field-source.pdus\"}

    source.pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    citrix_channels
    dns
    icmp
    non_ip
    other_ip
    tcp
    udp
    voip

The total number of PDUs (protocol data units= ) at applicative level
emitted by the source

[]{#3D\"field-source.port\"}

    source.port

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    port

    citrix
    citrix_channels
    databases
    http
    smb
    tcp
    tls
    udp
    voip

The TCP/UDP port of the source

[]{#3D\"field-source.rd\"}

    source.rd

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average retransmission delay for PDUs emi= tted by the source

[]{#3D\"field-source.rd.count\"}

    source.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of retransmission delays for PDUs = emitted by the source

[]{#3D\"field-source.rd.deviation\"}

    source.rd.deviation

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the retransmission delay for= PDUs emitted by the
source

[]{#3D\"field-source.remote\"}

    source.remote

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    pktsourcename

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The name of the network interface on which th= is traffic has been
captured via rpcapd (source-side)

[]{#3D\"field-source.retrans.payload\"}

    source.retrans.payload<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes of data (without he= aders) in retransmitted
PDUs emitted by the source

[]{#3D\"field-source.retrans.pdus.ratio\"}

    source.retrans.pdus.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmissions to the total num= ber of PDUs (protocol
data units) with payload emitted by the source

[]{#3D\"field-source.retrans.traffic\"}

    source.retrans.traffic<=
    /pre>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total amount of bytes in retransmitted PD= Us emitted by the source

[]{#3D\"field-source.retrans.traffic.ratio\"}

    source.retrans.tr=
    affic.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of retransmitted traffic to the ent= ire traffic emitted by
the source

[]{#3D\"field-source.rsts\"}

    source.rsts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of RST packets emitted by the sour= ce

[]{#3D\"field-source.rsts.ratio\"}

    source.rsts.ratio

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of source RST packets in a= connection

[]{#3D\"field-source.rtt\"}

    source.rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average round-trip time for PDUs (protoco= l data units) emitted by
the destination

[]{#3D\"field-source.rtt.count\"}

    source.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of round-trip times for PDUs (prot= ocol data units) emitted
by the destination

[]{#3D\"field-source.rtt.deviation\"}

    source.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The deviation of the round-trip time for PDUs= (protocol data units)
emitted by the destination

[]{#3D\"field-source.signalization.payload\"}

    source.signalizat=
    ion.payload

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes of data (without he= aders) in all
signalization PDUs (protocol data units) emitted by the sourc= e

[]{#3D\"field-source.signalization.pdus\"}

    source.signalization=
    .pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total number of signalization PDUs (proto= col data units) emitted
by the source

[]{#3D\"field-source.signalization.rd\"}

    source.signalization.r=
    d

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average retransmission delay for signaliz= ation PDUs (protocol data
units) emitted by the source

[]{#3D\"field-source.signalization.rd.count\"}

    source.signaliza=
    tion.rd.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of retransmission delays for signa= lization PDUs (protocol
data units) emitted by the source

[]{#3D\"field-source.signalization.rd.deviation\"}

    source.signa=
    lization.rd.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the retransmission delay for= signalization PDUs
(protocol data units) emitted by the source

[]{#3D\"field-source.signalization.retrans.pdus.ratio\"}

    source=
    .signalization.retrans.pdus.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The ratio of retransmissions to the total num= ber of signalization PDUs
(protocol data units) emitted by the source

[]{#3D\"field-source.signalization.rtt\"}

    source.signalization.=
    rtt

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The average round-trip time for signalization= PDUs (protocol data
units) emitted by the destination

[]{#3D\"field-source.signalization.rtt.count\"}

    source.signaliz=
    ation.rtt.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The number of round-trip times for signalizat= ion PDUs (protocol data
units) emitted by the destination

[]{#3D\"field-source.signalization.rtt.deviation\"}

    source.sign=
    alization.rtt.deviation

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The deviation of the round-trip time for sign= alization PDUs (protocol
data units) emitted by the destination

[]{#3D\"field-source.signalization.traffic\"}

    source.signalizat=
    ion.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

The total amount of bytes in signalization PD= Us (protocol data units)
emitted by the source

[]{#3D\"field-source.signature\"}

    source.signature

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    tls

The source signature

[]{#3D\"field-source.traffic\"}

    source.traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    icmp
    non_ip
    other_ip
    tcp
    tls
    udp
    voip

The total amount of bytes emitted by the sour= ce

[]{#3D\"field-source.vlan\"}

    source.vlan

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    vlan

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The VLAN id on the source side of the transac= tion

[]{#3D\"field-source.zero_windows\"}

    source.zero_windows

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of zero-window size packets emitte= d by the source

[]{#3D\"field-source.zero_windows.ratio\"}

    source.zero_windows.=
    ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of zero-window size to the total nu= mber of packets emitted
by the source

[]{#3D\"field-source.zone.id\"}

    source.zone.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone_id

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone id of the source

[]{#3D\"field-source.zone.name\"}

    source.zone.name

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    zone

    citrix
    citrix_channels
    databases
    dns
    http
    icmp
    non_ip
    other_ip
    smb
    tcp
    tls
    udp
    voip

The zone of the source

[]{#3D\"field-successes\"}

    successes

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    databases
    dns
    smb
    voip

The number of successes

[]{#3D\"field-successes.ratio\"}

    successes.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix
    databases
    dns
    smb
    voip

The ratio of successes

[]{#3D\"field-syns\"}

    syns

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of SYN packets emitted by the clie= nt

[]{#3D\"field-syns.ratio\"}

    syns.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The average number of SYN packets in a connec= tion

[]{#3D\"field-system\"}

    system

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    databasesystem

    databases

The database system

[]{#3D\"field-tcp_pdus\"}

    tcp_pdus

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    http

The number of TCP packets that form up the HT= TP queries and responses

[]{#3D\"field-timeouts\"}

    timeouts

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    citrix

The number of flows that timeouted

[]{#3D\"field-tls.version\"}

    tls.version

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    tls_version

    tls

The TLS protocol version

[]{#3D\"field-tls.version.is_weak\"}

    tls.version.is_weak

\<= /a\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    bool

    tls

Is the TLS protocol version weak?

[]{#3D\"field-tls.version.major\"}

    tls.version.major

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The TLS protocol major version

[]{#3D\"field-tls.version.minor\"}

    tls.version.minor

\<= /th\>

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tls

The TLS protocol minor version

[]{#3D\"field-traffic\"}

    traffic

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    dns
    http
    icmp
    non_ip
    other_ip
    tcp
    tls
    udp
    voip

The total amount of bytes in both directions\<= /td\>

[]{#3D\"field-tree\"}

    tree

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    path

    smb

The tree this CIFS command relates to

[]{#3D\"field-tree.id\"}

    tree.id

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    descriptor

    smb

The id of the tree this CIFS command relates = to

[]{#3D\"field-unclosed\"}

    unclosed

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The number of TCP sessions that didn\'t proper= ly end

[]{#3D\"field-url\"}

    url

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    url

    http

The path, query and fragment parts of the URL=

[]{#3D\"field-url.base\"}

    url.base

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    url

    http

The URL without the query string and fragment=

[]{#3D\"field-url.path\"}

    url.path

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    path

    http

The URL path

[]{#3D\"field-user\"}

    user

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    string

    citrix
    citrix_channels
    databases
    smb

The user

[]{#3D\"field-user.experience\"}

    user.experience

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The end-user experience (sum of RTTs, DTTs an= d SRT)

[]{#3D\"field-user_agent\"}

    user_agent

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    useragent

    http

The user-agent

[]{#3D\"field-uuid\"}

    uuid

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    uuid

    citrix
    citrix_channels
    databases
    dns
    http
    smb
    tcp
    tls
    voip

The unique identifier of this TCP session

[]{#3D\"field-voice.count\"}

    voice.count

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    voip

Number of packets where we had voice in the c= onversation

[]{#3D\"field-warnings\"}

    warnings

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The number of warnings (mainly client-side)

[]{#3D\"field-warnings.ratio\"}

    warnings.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    smb

The ratio of warnings to the total number of = SMB queries

[]{#3D\"field-zero_windows\"}

    zero_windows

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The total number of zero-window size packets = in both directions

[]{#3D\"field-zero_windows.ratio\"}

    zero_windows.ratio

[](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/=)

    number

    tcp

The ratio of zero-window size to the total nu= mber of packets in both
directions

Types {#3D\"types-list\"}
-----

::: {.section}
Type Name
:::

JSON Type

Available Values

Custom= Values Allowed

=20 =20

    alerttypes

    array<str>

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

\-

=20 =20

    application

    str

=20 - =20

\-

=20 =20

    application_id

    int

=20 - =20

\-

=20 =20

    bool

    bool

=20 - =20

\-

=20 =20

    calldirection

    int|null

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    callstate

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    channel

    int|null

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    ciphersuite

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

\-

=20 =20

    databasecommand

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    databasequery

    str

=20 - =20

\-

=20 =20

    databasesystem

    str

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    dcerpc

    str

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    descriptor

    int

=20 - =20

\-

=20 =20

    diffserv

    int

=20 - =20

\-

=20 =20

    dnsclass

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    dnscode

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    dnstype

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    encryption

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    ethernetprotocol

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    httpquerymethod

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    httpstatus

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    httpstatuscategory

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    icmpmessage

    tuple<int, int>

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    icmptype

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    ip

    str

=20 - =20

\-

=20 =20

    ipfamily

    int|null

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    ipprotocol

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    keytype

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

\-

=20 =20

    layer

    str

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    mac

    str

=20 - =20

\-

=20 =20

    mimetype

    str

=20 - =20

\-

=20 =20

    number

    int

=20 - =20

\-

=20 =20

    os

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    path

    str|null

=20 - =20

\-

=20 =20

    pktsourcekind

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    pktsourcename

    str

=20 - =20

\-

=20 =20

    pktsourcepair

    tuple<int, str>

=20 - =20

\-

=20 =20

    poller

    str

=20 - =20

\-

=20 =20

    poller_id

    str

=20 - =20

\-

=20 =20

    port

    int

=20 - =20

\-

=20 =20

    protostack

    str

=20 - =20

\-

=20 =20

    smb_version

    int

=20 - =20

\-

=20 =20

    smbcommand

    tuple<int, int>

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    smbstatus

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    smbsubcommand

    tuple<int, int, int>

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

Yes

=20 =20

    storage

    str

=20 - =20

\-

=20 =20

    string

    str

=20 - =20

\-

=20 =20

    time

    int

=20 - =20

\-

=20 =20

    tls_fingerprint

    str

=20 - =20

\-

=20 =20

    tls_version

    int

=20
[items](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4/do=)
=20

No

=20 =20

    url

    str

=20 - =20

\-

=20 =20

    useragent

    str|null

=20 - =20

\-

=20 =20

    uuid

    str

=20 - =20

\-

=20 =20

    vlan

    int|null

=20 - =20

\-

=20 =20

    zone

    str

=20 - =20

\-

=20 =20

    zone_id

    int

=20 - =20

\-

Values {#3D\"items-list\"}
------

::: {.section}
=20 =20 =20 =20 =20 =20

### Type [alerttypes](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"alerttypes-items\"}

=20

Name
:::

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Close Notify
```

=20

    0

=20

This message notifies the recipient that the sender will not = send any
more messages on this connection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unexpected Message
```

=

=20

    1

=20

An inappropriate message was received.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad MAC Record
```

=20

    2

=20

This alert is returned if a record is received with an incorr= ect MAC.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decryption Failed
```

\<= /td\> =20

    3

=20

This alert was used in some earlier versions of TLS, and may = have
permitted certain attacks against the CBC mode.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Record Overflow
```

=20

    4

=20

A TLSCiphertext record was received that had a length more th= an
2\^14+2048 bytes, or a record decrypted to a TLSCompressed record with
mo= re than 2\^14+1024 bytes.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decompression Failure
```

=20

    5

=20

The decompression function received improper input (e.g., dat= a that
would expand to excessive length).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Handshake Failure
```

\<= /td\> =20

    6

=20

Reception of a handshake failure alert message indicates that= the
sender was unable to negotiate an acceptable set of security parameter=
s given the options available.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No Certificate
```

=20

    7

=20

This alert was used in SSLv3 but not any version of TLS.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad Certificate
```

=20

    8

=20

A certificate was corrupt, contained signatures that did not = verify
correctly, etc.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unsupported Certificate<=
/pre>
```

=20

    9

=20

A certificate was of an unsupported type.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Certificate Revoked
```

=20

    10

=20

A certificate was revoked by its signer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Certificate Expired
```

=20

    11

=20

A certificate has expired or is not currently valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Certificate Unknown
```

=20

    12

=20

Some other (unspecified) issue arose in processing the certif= icate,
rendering it unacceptable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Illegal Parameter
```

\<= /td\> =20

    13

=20

A field in the handshake was out of range or inconsistent wit= h other
fields.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unknown CA
```

=20

    14

=20

A valid certificate chain or partial chain was received, but = the
certificate was not accepted because the CA certificate could not be lo=
cated or couldn\'t be matched with a known, trusted CA.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Access Denied
```

=20

    15

=20

A valid certificate was received, but when access control was= applied,
the sender decided not to proceed with negotiation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decode Error
```

=20

    16

=20

A message could not be decoded because some field was out of = the
specified range or the length of the message was incorrect.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decrypt Error
```

=20

    17

=20

A handshake cryptographic operation failed, including being u= nable to
correctly verify a signature or validate a Finished message.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Export Restriction
```

=

=20

    18

=20

This alert was used in some earlier versions of TLS.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Protocol Version
```

=20

    19

=20

The protocol version the client has attempted to negotiate is=
recognized but not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Insufficient Security
```

=20

    20

=20

Returned instead of a handshake failure when a negotiation ha= s failed
specifically because the server requires ciphers more secure than =
those supported by the client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Internal Error
```

=20

    21

=20

An internal error unrelated to the peer or the correctness of= the
protocol (such as a memory allocation failure) makes it impossible to =
continue.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
User Cancelled
```

=20

    22

=20

This handshake is being canceled for some reason unrelated to= a
protocol failure.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No Renegotiation
```

=20

    23

=20

Sent by the client in response to a hello request or by the s= erver in
response to a client hello after initial handshaking.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unsupported Extension
```

=20

    24

=20

Sent by clients that receive an extended server hello contain= ing an
extension that they did not put in the corresponding client hello. =20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20

### Type [calldirection](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"calldirection-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unknown
```

=20

    None

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Inbound
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Outbound
```

=20

    1 - 0x1

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [callstate](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"callstate-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
In ring
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Hang down
```

=20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Dial
```

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Out ring
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Voice
```

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Hang up
```

=20

    5 - 0x5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Closed
```

=20

    6 - 0x6

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [channel](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"channel-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Category

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSCRN
```

=20

Audio and video management

=20

    0 - 0x0

=20

CTXSCRN

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXLPT1
```

=20

Printer and scanner management

=20

    1 - 0x1

=20

CTXLPT1: Printer mapping for non-spooling client (Thin client= devices)
- vdcpm30N.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXLPT2
```

=20

Printer and scanner management

=20

    2 - 0x2

=20

CTXLPT2: Printer mapping for non-spooling client (Thin client= devices)
- vdcpm30N.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSBR
```

=20

Audio and video management

=20

    3 - 0x3

=20

CTXSBR: Browser acceleration - vdtw30n.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCPM
```

=20

Printer and scanner management

=20

    4 - 0x4

=20

CTXCPM: Printer mapping for client spooler - vdcpm30N.dll =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCOM1
```

=20

Printer and scanner management

=20

    5 - 0x5

=20

CTXCOM1: Printer mapping for non-spooling client (Thin client= devices)
- vdcom30N.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCOM2
```

=20

Printer and scanner management

=20

    6 - 0x6

=20

CTXCOM2: Printer mapping for non-spooling client (Thin client= devices)
- vdcom30N.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCCM
```

=20

Peripherals forwarding (like USB)

=20

    7 - 0x7

=20

CTXCCM: Client COM port mapping - vdcom30N.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXTW
```

=20

Audio and video management

=20

    8 - 0x8

=20

CTXTW: Remote Windows screen update (ThinWire) - vdtw30n.dll\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCDM
```

=20

Peripherals forwarding (like USB)

=20

    9 - 0x9

=20

CTXCDM: Client drive mapping - vdcdm30n.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SHADOW
```

=20

Unknown

=20

    10 - 0xA

=20

SHADOW

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXOEM
```

=20

Implementation and usage defined by O.E.M.

=20

    11 - 0xB

=20

CTXOEM: Used by Original Equipment Manufacturers

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXOEM2
```

=20

Implementation and usage defined by O.E.M.

=20

    12 - 0xC

=20

CTXOEM2: Used by Original Equipment Manufacturers

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCLIP
```

=20

Audio and video management

=20

    13 - 0xD

=20

CTXCLIP: Client clipboard - vdclipn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCAM
```

=20

Audio and video management

=20

    14 - 0xE

=20

CTXCAM: Client audio mapping - vdcamN.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXDRTP
```

=20

Unknown

=20

    15 - 0xF

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXTWI
```

=20

Audio and video management

=20

    16 - 0x10

=20

CTXTWI: Seamless Windows screen update data (ThinWire)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXZLFK
```

=20

Audio and video management

=20

    17 - 0x11

=20

CTXZLFK: Local Text Echo and Keyboard Feedback / Screen laten= cy
reduction (fonts) - vdzlcn.dll, vdfon30n.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXTUI
```

=20

Audio and video management

=20

    18 - 0x12

=20

Transparent User Interface

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCTL
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    19 - 0x13

=20

CTXCTL: Citrix control virtual channel - vdctln.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSCRD
```

=20

Authentication related

=20

    20 - 0x14

=20

CTXSCRD: Smartcard - vdscardn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXEUEM
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    21 - 0x15

=20

CTXEUEM: End user experience monitoring - vdeuemn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXLIC
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    22 - 0x16

=20

CTXLIC: License management - wfica32.exe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXMM
```

=20

Audio and video management

=20

    23 - 0x17

=20

CTXMM: Windows Multimedia redirection - vdmmn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSSPI
```

=20

Authentication related

=20

    24 - 0x18

=20

CTXSSPI: Kerberos

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXTWN
```

=20

Printer and scanner management

=20

    25 - 0x19

=20

CTXTWN: TWAIN redirection - vdtwn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CITRIXD
```

=20

Unknown

=20

    26 - 0x1A

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PNPREDI
```

=20

Unknown

=20

    27 - 0x1B

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSENS
```

=20

Audio and video management

=20

    28 - 0x1C

=20

Location and sensor

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXMTCH
```

=20

Audio and video management

=20

    29 - 0x1D

=20

CTXMTCH: Multitouch

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXLFP
```

=20

Audio and video management

=20

    30 - 0x1E

=20

CTXLFP: Framehawk Display channel over UDP-like transport =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXGUSB
```

=20

Peripherals forwarding (like USB)

=20

    31 - 0x1F

=20

CTXGUSB: USB redirection - vdgusbn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXFLSH
```

=20

Audio and video management

=20

    32 - 0x20

=20

CTXFLSH: Flash redirection - vdflash.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXFLS2
```

=20

Audio and video management

=20

    33 - 0x21

=20

CTXFLS2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXD3D
```

=20

Audio and video management

=20

    34 - 0x22

=20

CTXD3D: Direct3D virtual channel adapter - vd3dn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXPN
```

=20

Unknown

=20

    35 - 0x23

=20

CTXPN: Program Neighborhood - vdpnn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXZLC
```

=20

Audio and video management

=20

    36 - 0x24

=20

CTXZLC: Screen latency reduction (screen) - vdzlcn.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXSPMK
```

=20

Unknown

=20

    37 - 0x25

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CARANOC
```

=20

Unknown

=20

    38 - 0x26

=20

CARANOC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AURTCX
```

=20

Unknown

=20

    39 - 0x27

=20

AURTCX

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IMP1166
```

=20

Unknown

=20

    40 - 0x28

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SPECIAL_THINWIRE
```

=20

Audio and video management

=20

    41 - 0x29

=20

SPECIAL\_THINWIRE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ESCAPE
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    42 - 0x2A

=20

ESCAPE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BASE
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    43 - 0x2B

=20

BASE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXVFM
```

=20

Audio and video management

=20

    44 - 0x2C

=20

CTXVFM: Video server (not ThinWire, deprecated)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXCM
```

=20

Core Citrix channels (updates, licensing, configuration, \...)=

=20

    45 - 0x2D

=20

CTXCM: Client management (auto client update) - vdcmN.dll =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXPASS
```

=20

Audio and video management

=20

    46 - 0x2E

=20

CTXPASS: Transparent key pass-through - vdkbhook.dll

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXTW1
```

=20

Audio and video management

=20

    47 - 0x2F

=20

CTXTW1: Seamless Windows screen update (ThinWire) - vdtwin.dl= l

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSPXSBE
```

=20

Unknown

=20

    48 - 0x30

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MHA_VC
```

=20

Unknown

=20

    49 - 0x31

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EVDSSO
```

=20

Unknown

=20

    50 - 0x32

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CTXMOB
```

=20

Unknown

=20

    51 - 0x33

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSPCTRL
```

=20

Unknown

=20

    52 - 0x34

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSPMIX
```

=20

Unknown

=20

    53 - 0x35

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSPSBEX
```

=20

Unknown

=20

    54 - 0x36

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSPXMIX
```

=20

Unknown

=20

    55 - 0x37

=20

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [ciphersuite](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"ciphersuite-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
null with null null
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with null MD5
```

\<= /td\> =20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with null SHA
```

\<= /td\> =20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export with RC4 40 M=
D5
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with RC4 128 MD5
```

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with RC4 128 SHA
```

=20

    5 - 0x5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export with RC2 CBC =
40 MD5
```

=20

    6 - 0x6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with IDEA CBC SHA
```

=20

    7 - 0x7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export with DES40 CB=
C SHA
```

=20

    8 - 0x8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with DES CBC SHA
```

=20

    9 - 0x9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with 3DES EDE CBC SH=
A
```

=20

    10 - 0xA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS export with DES40=
 CBC SHA
```

=20

    11 - 0xB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with DES CBC SHA<=
/pre>
```

=20

    12 - 0xC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with 3DES EDE CBC=
 SHA
```

=20

    13 - 0xD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA export with DES40=
 CBC SHA
```

=20

    14 - 0xE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with DES CBC SHA<=
/pre>
```

=20

    15 - 0xF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with 3DES EDE CBC=
 SHA
```

=20

    16 - 0x10

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS export with DES4=
0 CBC SHA
```

=20

    17 - 0x11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with DES CBC SHA=
```

=20

    18 - 0x12

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with 3DES EDE CB=
C SHA
```

=20

    19 - 0x13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA export with DES4=
0 CBC SHA
```

=20

    20 - 0x14

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with DES CBC SHA=
```

=20

    21 - 0x15

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with 3DES EDE CB=
C SHA
```

=20

    22 - 0x16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon export with RC4 =
40 MD5
```

=20

    23 - 0x17

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with RC4 128 MD5=
```

=20

    24 - 0x18

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon export with DES4=
0 CBC SHA
```

=20

    25 - 0x19

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with DES CBC SHA=
```

=20

    26 - 0x1A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with 3DES EDE CB=
C SHA
```

=20

    27 - 0x1B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with DES CBC SHA
```

=20

    30 - 0x1E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with 3DES EDE CBC S=
HA
```

=20

    31 - 0x1F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with RC4 128 SHA
```

=20

    32 - 0x20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with IDEA CBC SHA
```

=20

    33 - 0x21

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with DES CBC MD5
```

=20

    34 - 0x22

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with 3DES EDE CBC M=
D5
```

=20

    35 - 0x23

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with RC4 128 MD5
```

=20

    36 - 0x24

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 with IDEA CBC MD5
```

=20

    37 - 0x25

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with DES CBC=
 40 SHA
```

=20

    38 - 0x26

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with RC2 CBC=
 40 SHA
```

=20

    39 - 0x27

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with RC4 40 =
SHA
```

=20

    40 - 0x28

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with DES CBC=
 40 MD5
```

=20

    41 - 0x29

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with RC2 CBC=
 40 MD5
```

=20

    42 - 0x2A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KRB5 export with RC4 40 =
MD5
```

=20

    43 - 0x2B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with null SHA
```

\<= /td\> =20

    44 - 0x2C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with null SHA
```

=20

    45 - 0x2D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with null SHA
```

=20

    46 - 0x2E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 128 CBC SHA=
```

=20

    47 - 0x2F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 128 CBC =
SHA
```

=20

    48 - 0x30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 128 CBC =
SHA
```

=20

    49 - 0x31

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 128 CBC=
 SHA
```

=20

    50 - 0x32

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 128 CBC=
 SHA
```

=20

    51 - 0x33

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 128 CBC=
 SHA
```

=20

    52 - 0x34

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 256 CBC SHA=
```

=20

    53 - 0x35

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 256 CBC =
SHA
```

=20

    54 - 0x36

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 256 CBC =
SHA
```

=20

    55 - 0x37

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 256 CBC=
 SHA
```

=20

    56 - 0x38

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 256 CBC=
 SHA
```

=20

    57 - 0x39

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 256 CBC=
 SHA
```

=20

    58 - 0x3A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with null SHA256
```

=20

    59 - 0x3B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 128 CBC SHA=
256
```

=20

    60 - 0x3C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 256 CBC SHA=
256
```

=20

    61 - 0x3D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 128 CBC =
SHA256
```

=20

    62 - 0x3E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 128 CBC =
SHA256
```

=20

    63 - 0x3F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 128 CBC=
 SHA256
```

=20

    64 - 0x40

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 128 CB=
C SHA
```

=20

    65 - 0x41

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 128=
 CBC SHA
```

=20

    66 - 0x42

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 128=
 CBC SHA
```

=20

    67 - 0x43

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 12=
8 CBC SHA
```

=20

    68 - 0x44

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 12=
8 CBC SHA
```

=20

    69 - 0x45

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 12=
8 CBC SHA
```

=20

    70 - 0x46

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with DES CBC =
SHA
```

=20

    73 - 0x49

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export1024 with RC4 =
56 MD5
```

=20

    96 - 0x60

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export1024 with RC2 =
CBC 56 MD5
```

=20

    97 - 0x61

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export1024 with DES =
CBC SHA
```

=20

    98 - 0x62

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS export1024 with =
DES CBC SHA
```

=20

    99 - 0x63

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA export1024 with RC4 =
56 SHA
```

=20

    100 - 0x64

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS export1024 with =
RC4 56 SHA
```

=20

    101 - 0x65

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with RC4 128 SHA=
```

=20

    102 - 0x66

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 128 CBC=
 SHA256
```

=20

    103 - 0x67

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 256 CBC =
SHA256
```

=20

    104 - 0x68

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 256 CBC =
SHA256
```

=20

    105 - 0x69

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 256 CBC=
 SHA256
```

=20

    106 - 0x6A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 256 CBC=
 SHA256
```

=20

    107 - 0x6B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 128 CBC=
 SHA256
```

=20

    108 - 0x6C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 256 CBC=
 SHA256
```

=20

    109 - 0x6D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GOSTR341094 with 28147 C=
NT IMIT
```

=20

    128 - 0x80

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GOSTR341001 with 28147 C=
NT IMIT
```

=20

    129 - 0x81

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GOSTR341094 with null GO=
STR3411
```

=20

    130 - 0x82

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GOSTR341001 with null GO=
STR3411
```

=20

    131 - 0x83

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 256 CB=
C SHA
```

=20

    132 - 0x84

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 256=
 CBC SHA
```

=20

    133 - 0x85

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 256=
 CBC SHA
```

=20

    134 - 0x86

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 25=
6 CBC SHA
```

=20

    135 - 0x87

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 25=
6 CBC SHA
```

=20

    136 - 0x88

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 25=
6 CBC SHA
```

=20

    137 - 0x89

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with RC4 128 SHA
```

=20

    138 - 0x8A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with 3DES EDE CBC SH=
A
```

=20

    139 - 0x8B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 128 CBC SHA=
```

=20

    140 - 0x8C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 256 CBC SHA=
```

=20

    141 - 0x8D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with RC4 128 SHA=
```

=20

    142 - 0x8E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with 3DES EDE CB=
C SHA
```

=20

    143 - 0x8F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 128 CBC=
 SHA
```

=20

    144 - 0x90

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 256 CBC=
 SHA
```

=20

    145 - 0x91

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with RC4 128 SHA=
```

=20

    146 - 0x92

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with 3DES EDE CB=
C SHA
```

=20

    147 - 0x93

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 128 CBC=
 SHA
```

=20

    148 - 0x94

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 256 CBC=
 SHA
```

=20

    149 - 0x95

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with seed CBC SHA
```

=20

    150 - 0x96

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with seed CBC SHA=
```

=20

    151 - 0x97

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with seed CBC SHA=
```

=20

    152 - 0x98

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with seed CBC SH=
A
```

=20

    153 - 0x99

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with seed CBC SH=
A
```

=20

    154 - 0x9A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with seed CBC SH=
A
```

=20

    155 - 0x9B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 128 GCM SHA=
256
```

=20

    156 - 0x9C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 256 GCM SHA=
384
```

=20

    157 - 0x9D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 128 GCM=
 SHA256
```

=20

    158 - 0x9E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 256 GCM=
 SHA384
```

=20

    159 - 0x9F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 128 GCM =
SHA256
```

=20

    160 - 0xA0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with AES 256 GCM =
SHA384
```

=20

    161 - 0xA1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 128 GCM=
 SHA256
```

=20

    162 - 0xA2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with AES 256 GCM=
 SHA384
```

=20

    163 - 0xA3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 128 GCM =
SHA256
```

=20

    164 - 0xA4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with AES 256 GCM =
SHA384
```

=20

    165 - 0xA5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 128 GCM=
 SHA256
```

=20

    166 - 0xA6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with AES 256 GCM=
 SHA384
```

=20

    167 - 0xA7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 128 GCM SHA=
256
```

=20

    168 - 0xA8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 256 GCM SHA=
384
```

=20

    169 - 0xA9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 128 GCM=
 SHA256
```

=20

    170 - 0xAA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 256 GCM=
 SHA384
```

=20

    171 - 0xAB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 128 GCM=
 SHA256
```

=20

    172 - 0xAC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 256 GCM=
 SHA384
```

=20

    173 - 0xAD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 128 CBC SHA=
256
```

=20

    174 - 0xAE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 256 CBC SHA=
384
```

=20

    175 - 0xAF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with null SHA256
```

=20

    176 - 0xB0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with null SHA384
```

=20

    177 - 0xB1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 128 CBC=
 SHA256
```

=20

    178 - 0xB2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 256 CBC=
 SHA384
```

=20

    179 - 0xB3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with null SHA256=
```

=20

    180 - 0xB4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with null SHA384=
```

=20

    181 - 0xB5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 128 CBC=
 SHA256
```

=20

    182 - 0xB6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with AES 256 CBC=
 SHA384
```

=20

    183 - 0xB7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with null SHA256=
```

=20

    184 - 0xB8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with null SHA384=
```

=20

    185 - 0xB9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 128 CB=
C SHA256
```

=20

    186 - 0xBA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 128=
 CBC SHA256
```

=20

    187 - 0xBB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 128=
 CBC SHA256
```

=20

    188 - 0xBC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 12=
8 CBC SHA256
```

=20

    189 - 0xBD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 12=
8 CBC SHA256
```

=20

    190 - 0xBE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 12=
8 CBC SHA256
```

=20

    191 - 0xBF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 256 CB=
C SHA256
```

=20

    192 - 0xC0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 256=
 CBC SHA256
```

=20

    193 - 0xC1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 256=
 CBC SHA256
```

=20

    194 - 0xC2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 25=
6 CBC SHA256
```

=20

    195 - 0xC3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 25=
6 CBC SHA256
```

=20

    196 - 0xC4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 25=
6 CBC SHA256
```

=20

    197 - 0xC5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
empty renegotiation info=
 SCSV
```

=20

    255 - 0xFF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AES 128 GCM SHA256
```

=

=20

    4865 - 0x1301

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AES 256 GCM SHA384
```

=

=20

    4866 - 0x1302

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CHACHA20 POLY1305 SHA256=
```

=20

    4867 - 0x1303

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AES 128 CCM SHA256
```

=

=20

    4868 - 0x1304

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AES 128 CCM 8 SHA256
```

=20

    4869 - 0x1305

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
fallback SCSV
```

=20

    22016 - 0x5600

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with null SHA=
```

=20

    49153 - 0xC001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with RC4 128 =
SHA
```

=20

    49154 - 0xC002

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with 3DES EDE=
 CBC SHA
```

=20

    49155 - 0xC003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 128 =
CBC SHA
```

=20

    49156 - 0xC004

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 256 =
CBC SHA
```

=20

    49157 - 0xC005

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with null SH=
A
```

=20

    49158 - 0xC006

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with RC4 128=
 SHA
```

=20

    49159 - 0xC007

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with 3DES ED=
E CBC SHA
```

=20

    49160 - 0xC008

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 128=
 CBC SHA
```

=20

    49161 - 0xC009

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 256=
 CBC SHA
```

=20

    49162 - 0xC00A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with null SHA
```

=20

    49163 - 0xC00B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with RC4 128 SH=
A
```

=20

    49164 - 0xC00C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with 3DES EDE C=
BC SHA
```

=20

    49165 - 0xC00D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 128 CB=
C SHA
```

=20

    49166 - 0xC00E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 256 CB=
C SHA
```

=20

    49167 - 0xC00F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with null SHA<=
/pre>
```

=20

    49168 - 0xC010

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with RC4 128 S=
HA
```

=20

    49169 - 0xC011

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with 3DES EDE =
CBC SHA
```

=20

    49170 - 0xC012

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 128 C=
BC SHA
```

=20

    49171 - 0xC013

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 256 C=
BC SHA
```

=20

    49172 - 0xC014

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH anon with null SHA<=
/pre>
```

=20

    49173 - 0xC015

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH anon with RC4 128 S=
HA
```

=20

    49174 - 0xC016

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH anon with 3DES EDE =
CBC SHA
```

=20

    49175 - 0xC017

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH anon with AES 128 C=
BC SHA
```

=20

    49176 - 0xC018

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH anon with AES 256 C=
BC SHA
```

=20

    49177 - 0xC019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA with 3DES EDE CB=
C SHA
```

=20

    49178 - 0xC01A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA RSA with 3DES ED=
E CBC SHA
```

=20

    49179 - 0xC01B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA DSS with 3DES ED=
E CBC SHA
```

=20

    49180 - 0xC01C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA with AES 128 CBC=
 SHA
```

=20

    49181 - 0xC01D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA RSA with AES 128=
 CBC SHA
```

=20

    49182 - 0xC01E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA DSS with AES 128=
 CBC SHA
```

=20

    49183 - 0xC01F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA with AES 256 CBC=
 SHA
```

=20

    49184 - 0xC020

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA RSA with AES 256=
 CBC SHA
```

=20

    49185 - 0xC021

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRP SHA DSS with AES 256=
 CBC SHA
```

=20

    49186 - 0xC022

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 128=
 CBC SHA256
```

=20

    49187 - 0xC023

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 256=
 CBC SHA384
```

=20

    49188 - 0xC024

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 128 =
CBC SHA256
```

=20

    49189 - 0xC025

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 256 =
CBC SHA384
```

=20

    49190 - 0xC026

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 128 C=
BC SHA256
```

=20

    49191 - 0xC027

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 256 C=
BC SHA384
```

=20

    49192 - 0xC028

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 128 CB=
C SHA256
```

=20

    49193 - 0xC029

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 256 CB=
C SHA384
```

=20

    49194 - 0xC02A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 128=
 GCM SHA256
```

=20

    49195 - 0xC02B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 256=
 GCM SHA384
```

=20

    49196 - 0xC02C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 128 =
GCM SHA256
```

=20

    49197 - 0xC02D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with AES 256 =
GCM SHA384
```

=20

    49198 - 0xC02E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 128 G=
CM SHA256
```

=20

    49199 - 0xC02F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with AES 256 G=
CM SHA384
```

=20

    49200 - 0xC030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 128 GC=
M SHA256
```

=20

    49201 - 0xC031

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with AES 256 GC=
M SHA384
```

=20

    49202 - 0xC032

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with RC4 128 S=
HA
```

=20

    49203 - 0xC033

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with 3DES EDE =
CBC SHA
```

=20

    49204 - 0xC034

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 128 C=
BC SHA
```

=20

    49205 - 0xC035

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 256 C=
BC SHA
```

=20

    49206 - 0xC036

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 128 C=
BC SHA256
```

=20

    49207 - 0xC037

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 256 C=
BC SHA384
```

=20

    49208 - 0xC038

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with null SHA<=
/pre>
```

=20

    49209 - 0xC039

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with null SHA2=
56
```

=20

    49210 - 0xC03A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with null SHA3=
84
```

=20

    49211 - 0xC03B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with ARIA 128 CBC SH=
A256
```

=20

    49212 - 0xC03C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with ARIA 256 CBC SH=
A384
```

=20

    49213 - 0xC03D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with ARIA 128 CBC=
 SHA256
```

=20

    49214 - 0xC03E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with ARIA 256 CBC=
 SHA384
```

=20

    49215 - 0xC03F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with ARIA 128 CBC=
 SHA256
```

=20

    49216 - 0xC040

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with ARIA 256 CBC=
 SHA384
```

=20

    49217 - 0xC041

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with ARIA 128 CB=
C SHA256
```

=20

    49218 - 0xC042

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with ARIA 256 CB=
C SHA384
```

=20

    49219 - 0xC043

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with ARIA 128 CB=
C SHA256
```

=20

    49220 - 0xC044

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with ARIA 256 CB=
C SHA384
```

=20

    49221 - 0xC045

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with ARIA 128 CB=
C SHA256
```

=20

    49222 - 0xC046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with ARIA 256 CB=
C SHA384
```

=20

    49223 - 0xC047

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with ARIA 12=
8 CBC SHA256
```

=20

    49224 - 0xC048

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with ARIA 25=
6 CBC SHA384
```

=20

    49225 - 0xC049

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with ARIA 128=
 CBC SHA256
```

=20

    49226 - 0xC04A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with ARIA 256=
 CBC SHA384
```

=20

    49227 - 0xC04B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with ARIA 128 =
CBC SHA256
```

=20

    49228 - 0xC04C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with ARIA 256 =
CBC SHA384
```

=20

    49229 - 0xC04D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with ARIA 128 C=
BC SHA256
```

=20

    49230 - 0xC04E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with ARIA 256 C=
BC SHA384
```

=20

    49231 - 0xC04F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with ARIA 128 GCM SH=
A256
```

=20

    49232 - 0xC050

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with ARIA 256 GCM SH=
A384
```

=20

    49233 - 0xC051

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with ARIA 128 GC=
M SHA256
```

=20

    49234 - 0xC052

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with ARIA 256 GC=
M SHA384
```

=20

    49235 - 0xC053

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with ARIA 128 GCM=
 SHA256
```

=20

    49236 - 0xC054

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with ARIA 256 GCM=
 SHA384
```

=20

    49237 - 0xC055

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with ARIA 128 GC=
M SHA256
```

=20

    49238 - 0xC056

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with ARIA 256 GC=
M SHA384
```

=20

    49239 - 0xC057

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with ARIA 128 GCM=
 SHA256
```

=20

    49240 - 0xC058

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with ARIA 256 GCM=
 SHA384
```

=20

    49241 - 0xC059

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with ARIA 128 GC=
M SHA256
```

=20

    49242 - 0xC05A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with ARIA 256 GC=
M SHA384
```

=20

    49243 - 0xC05B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with ARIA 12=
8 GCM SHA256
```

=20

    49244 - 0xC05C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with ARIA 25=
6 GCM SHA384
```

=20

    49245 - 0xC05D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with ARIA 128=
 GCM SHA256
```

=20

    49246 - 0xC05E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with ARIA 256=
 GCM SHA384
```

=20

    49247 - 0xC05F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with ARIA 128 =
GCM SHA256
```

=20

    49248 - 0xC060

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with ARIA 256 =
GCM SHA384
```

=20

    49249 - 0xC061

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with ARIA 128 G=
CM SHA256
```

=20

    49250 - 0xC062

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with ARIA 256 G=
CM SHA384
```

=20

    49251 - 0xC063

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with ARIA 128 CBC SH=
A256
```

=20

    49252 - 0xC064

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with ARIA 256 CBC SH=
A384
```

=20

    49253 - 0xC065

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with ARIA 128 CB=
C SHA256
```

=20

    49254 - 0xC066

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with ARIA 256 CB=
C SHA384
```

=20

    49255 - 0xC067

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with ARIA 128 CB=
C SHA256
```

=20

    49256 - 0xC068

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with ARIA 256 CB=
C SHA384
```

=20

    49257 - 0xC069

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with ARIA 128 GCM SH=
A256
```

=20

    49258 - 0xC06A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with ARIA 256 GCM SH=
A384
```

=20

    49259 - 0xC06B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with ARIA 128 GC=
M SHA256
```

=20

    49260 - 0xC06C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with ARIA 256 GC=
M SHA384
```

=20

    49261 - 0xC06D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with ARIA 128 GC=
M SHA256
```

=20

    49262 - 0xC06E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with ARIA 256 GC=
M SHA384
```

=20

    49263 - 0xC06F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with ARIA 128 =
CBC SHA256
```

=20

    49264 - 0xC070

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with ARIA 256 =
CBC SHA384
```

=20

    49265 - 0xC071

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with CAMELLI=
A 128 CBC SHA256
```

=20

    49266 - 0xC072

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with CAMELLI=
A 256 CBC SHA384
```

=20

    49267 - 0xC073

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with CAMELLIA=
 128 CBC SHA256
```

=20

    49268 - 0xC074

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with CAMELLIA=
 256 CBC SHA384
```

=20

    49269 - 0xC075

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with CAMELLIA =
128 CBC SHA256
```

=20

    49270 - 0xC076

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with CAMELLIA =
256 CBC SHA384
```

=20

    49271 - 0xC077

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with CAMELLIA 1=
28 CBC SHA256
```

=20

    49272 - 0xC078

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with CAMELLIA 2=
56 CBC SHA384
```

=20

    49273 - 0xC079

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 128 GC=
M SHA256
```

=20

    49274 - 0xC07A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with CAMELLIA 256 GC=
M SHA384
```

=20

    49275 - 0xC07B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 12=
8 GCM SHA256
```

=20

    49276 - 0xC07C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CAMELLIA 25=
6 GCM SHA384
```

=20

    49277 - 0xC07D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 128=
 GCM SHA256
```

=20

    49278 - 0xC07E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH RSA with CAMELLIA 256=
 GCM SHA384
```

=20

    49279 - 0xC07F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 12=
8 GCM SHA256
```

=20

    49280 - 0xC080

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE DSS with CAMELLIA 25=
6 GCM SHA384
```

=20

    49281 - 0xC081

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 128=
 GCM SHA256
```

=20

    49282 - 0xC082

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH DSS with CAMELLIA 256=
 GCM SHA384
```

=20

    49283 - 0xC083

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 12=
8 GCM SHA256
```

=20

    49284 - 0xC084

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DH anon with CAMELLIA 25=
6 GCM SHA384
```

=20

    49285 - 0xC085

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with CAMELLI=
A 128 GCM SHA256
```

=20

    49286 - 0xC086

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with CAMELLI=
A 256 GCM SHA384
```

=20

    49287 - 0xC087

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with CAMELLIA=
 128 GCM SHA256
```

=20

    49288 - 0xC088

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH ECDSA with CAMELLIA=
 256 GCM SHA384
```

=20

    49289 - 0xC089

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with CAMELLIA =
128 GCM SHA256
```

=20

    49290 - 0xC08A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with CAMELLIA =
256 GCM SHA384
```

=20

    49291 - 0xC08B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with CAMELLIA 1=
28 GCM SHA256
```

=20

    49292 - 0xC08C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDH RSA with CAMELLIA 2=
56 GCM SHA384
```

=20

    49293 - 0xC08D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with CAMELLIA 128 GC=
M SHA256
```

=20

    49294 - 0xC08E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with CAMELLIA 256 GC=
M SHA384
```

=20

    49295 - 0xC08F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with CAMELLIA 12=
8 GCM SHA256
```

=20

    49296 - 0xC090

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with CAMELLIA 25=
6 GCM SHA384
```

=20

    49297 - 0xC091

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with CAMELLIA 12=
8 GCM SHA256
```

=20

    49298 - 0xC092

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with CAMELLIA 25=
6 GCM SHA384
```

=20

    49299 - 0xC093

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with CAMELLIA 128 CB=
C SHA256
```

=20

    49300 - 0xC094

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with CAMELLIA 256 CB=
C SHA384
```

=20

    49301 - 0xC095

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with CAMELLIA 12=
8 CBC SHA256
```

=20

    49302 - 0xC096

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with CAMELLIA 25=
6 CBC SHA384
```

=20

    49303 - 0xC097

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with CAMELLIA 12=
8 CBC SHA256
```

=20

    49304 - 0xC098

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with CAMELLIA 25=
6 CBC SHA384
```

=20

    49305 - 0xC099

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with CAMELLIA =
128 CBC SHA256
```

=20

    49306 - 0xC09A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with CAMELLIA =
256 CBC SHA384
```

=20

    49307 - 0xC09B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 128 CCM
```

=20

    49308 - 0xC09C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 256 CCM
```

=20

    49309 - 0xC09D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 128 CCM=
```

=20

    49310 - 0xC09E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 256 CCM=
```

=20

    49311 - 0xC09F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 128 CCM 8
```

=20

    49312 - 0xC0A0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with AES 256 CCM 8
```

=20

    49313 - 0xC0A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 128 CCM=
 8
```

=20

    49314 - 0xC0A2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with AES 256 CCM=
 8
```

=20

    49315 - 0xC0A3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 128 CCM
```

=20

    49316 - 0xC0A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 256 CCM
```

=20

    49317 - 0xC0A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 128 CCM=
```

=20

    49318 - 0xC0A6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with AES 256 CCM=
```

=20

    49319 - 0xC0A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 128 CCM 8
```

=20

    49320 - 0xC0A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with AES 256 CCM 8
```

=20

    49321 - 0xC0A9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK DHE with AES 128 CCM=
 8
```

=20

    49322 - 0xC0AA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK DHE with AES 256 CCM=
 8
```

=20

    49323 - 0xC0AB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 128=
 CCM
```

=20

    49324 - 0xC0AC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 256=
 CCM
```

=20

    49325 - 0xC0AD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 128=
 CCM 8
```

=20

    49326 - 0xC0AE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with AES 256=
 CCM 8
```

=20

    49327 - 0xC0AF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECJPAKE with AES 128 CCM=
 8
```

=20

    49407 - 0xC0FF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with CHACHA20 =
POLY1305 SHA256
```

=20

    52392 - 0xCCA8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with CHACHA2=
0 POLY1305 SHA256
```

=20

    52393 - 0xCCA9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with CHACHA20 PO=
LY1305 SHA256
```

=20

    52394 - 0xCCAA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with CHACHA20 POLY13=
05 SHA256
```

=20

    52395 - 0xCCAB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with CHACHA20 =
POLY1305 SHA256
```

=20

    52396 - 0xCCAC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with CHACHA20 PO=
LY1305 SHA256
```

=20

    52397 - 0xCCAD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with CHACHA20 PO=
LY1305 SHA256
```

=20

    52398 - 0xCCAE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 128 G=
CM SHA256
```

=20

    53249 - 0xD001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 256 G=
CM SHA384
```

=20

    53250 - 0xD002

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 128 C=
CM 8 SHA256
```

=20

    53251 - 0xD003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with AES 128 C=
CM SHA256
```

=20

    53253 - 0xD005

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with ESTREAM SALSA20=
 SHA1
```

=20

    58384 - 0xE410

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA with SALSA20 SHA1
```

=20

    58385 - 0xE411

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with ESTREAM S=
ALSA20 SHA1
```

=20

    58386 - 0xE412

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE RSA with SALSA20 S=
HA1
```

=20

    58387 - 0xE413

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with ESTREAM=
 SALSA20 SHA1
```

=20

    58388 - 0xE414

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE ECDSA with SALSA20=
 SHA1
```

=20

    58389 - 0xE415

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with ESTREAM SALSA20=
 SHA1
```

=20

    58390 - 0xE416

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PSK with SALSA20 SHA1
```

=20

    58391 - 0xE417

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with ESTREAM S=
ALSA20 SHA1
```

=20

    58392 - 0xE418

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECDHE PSK with SALSA20 S=
HA1
```

=20

    58393 - 0xE419

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with ESTREAM SAL=
SA20 SHA1
```

=20

    58394 - 0xE41A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA PSK with SALSA20 SHA=
1
```

=20

    58395 - 0xE41B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with ESTREAM SAL=
SA20 SHA1
```

=20

    58396 - 0xE41C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE PSK with SALSA20 SHA=
1
```

=20

    58397 - 0xE41D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with ESTREAM SAL=
SA20 SHA1
```

=20

    58398 - 0xE41E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHE RSA with SALSA20 SHA=
1
```

=20

    58399 - 0xE41F

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [databasecommand](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"databasecommand-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SELECT
```

=20

    256 - 0x100

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
INSERT
```

=20

    512 - 0x200

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
UPDATE
```

=20

    768 - 0x300

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DELETE
```

=20

    1024 - 0x400

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CREATE
```

=20

    1280 - 0x500

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CREATE TABLE
```

=20

    1281 - 0x501

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CREATE INDEX
```

=20

    1282 - 0x502

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CREATE VIEW
```

=20

    1283 - 0x503

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DROP
```

=20

    1536 - 0x600

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DROP TABLE
```

=20

    1537 - 0x601

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DROP INDEX
```

=20

    1538 - 0x602

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DROP VIEW
```

=20

    1539 - 0x603

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ALTER
```

=20

    1792 - 0x700

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ALTER TABLE
```

=20

    1793 - 0x701

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PREPARE
```

=20

    2048 - 0x800

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EXECUTE
```

=20

    2304 - 0x900

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BEGIN
```

=20

    61440 - 0xF000

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
COMMIT
```

=20

    61696 - 0xF100

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ROLLBACK
```

=20

    61952 - 0xF200

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FETCH
```

=20

    62208 - 0xF300

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CLOSE
```

=20

    62464 - 0xF400

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EMPTY
```

=20

    62720 - 0xF500

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20

### Type [databasesystem](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"databasesystem-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DB2 (DRDA)
```

=20

    DRDA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MongoDB
```

=20

    MongoDB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MySQL / MariaDB
```

=20

    MySQL

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PostgreSQL
```

=20

    PostgreSQL

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft SQL Server / S=
ybase
```

=20

    TDS(msg)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Oracle
```

=20

    TNS

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [dcerpc](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"dcerpc-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Category

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IUnknown Interface
```

=20

MS DCOM Services

=20

    00000000-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IClassFactory Interface
```

=20

MS DCOM Services

=20

    00000001-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IBindCtx Interface
```

=20

MS DCOM Services

=20

    0000000e-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IEnumUnknown Interface
```

=20

MS DCOM Services

=20

    00000100-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IPersist Interface
```

=20

MS DCOM Services

=20

    0000010c-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IDataObject Interface
```

=20

MS DCOM Services

=20

    0000010e-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IID_IRemUnknown Interface
```

=20

MS DCOM Services

=20

    00000131-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - ILocalSystemActivator Interface
```

=20

MS DCOM Services

=20

    00000132-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IRunDown Interface
```

=20

MS DCOM Services

=20

    00000134-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IInterfaceFromWindowProp Interface
```

=20

MS DCOM Services

=20

    00000135-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - ISCMActivator Interface
```

=20

MS DCOM Services

=20

    00000136-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IDLLHost Interface
```

=20

MS DCOM Services

=20

    00000141-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IID_IRemUnknown2 Interface
```

=20

MS DCOM Services

=20

    00000143-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - ISystemActivator Interface
```

=20

MS DCOM Services

=20

    000001a0-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - IDispatch Interface
```

=20

MS OLE Automation

=20

    00020400-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - ITypeInfo Interface
```

=20

MS OLE Automation

=20

    00020401-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - ITypeLib Interface
```

=20

MS OLE Automation

=20

    00020402-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - ITypeComp Interface
```

=20

MS OLE Automation

=20

    00020403-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - IEnumVARIANT Interface
```

=20

MS OLE Automation

=20

    00020404-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - ITypeLib2 Interface
```

=20

MS OLE Automation

=20

    00020411-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Automation=
 Protocol - ITypeInfo2 Interface
```

=20

MS OLE Automation

=20

    00020412-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IShellView Interface
```

=20

MS Explorer Browser

=20

    000214e3-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IShellFolder Interface
```

=20

MS DCOM Services

=20

    000214e6-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - ICommDlgBrowser Interface
```

=20

MS Explorer Browser

=20

    000214f1-0000-0000-c000-000000000046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdate4 Interface
```

=20

MS Update Agent

=20

    004c6a2b-0c19-4c69-9f5c-a269b2560db9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDiskMgr CLSID
```

=20

MS ISTM iSCSI

=20

    0144084b-e09e-4f45-a56b-dcdc9f379f5e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHostMgr3 Interface
```

=20

MS ISTM iSCSI

=20

    01454b97-c6a5-4685-bea8-9779c88ab990

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQOutgoingQueueManagement
```

=20

MS Message Queuing

=20

    0188401c-247a-4fed-99c6-bf14119d7055

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQCollection Interface
```

=20

MS Message Queuing

=20

    0188ac2f-ecb3-4173-9779-635ca2039c72

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostPropertyCollection I=
nterface
```

=20

MS IIS

=20

    0191775e-bcff-445a-b4f4-3bdda54e2816

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Shadow Copy Ma=
nagement Protocol - IVssEnumMgmtObject interface
```

=20

MS Volume Shadow Copy

=20

    01954e6b-9254-4e6e-808c-c9e05d007696

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IEnumWbemClassObject Interfa=
ce
```

=20

MS WMI

=20

    027947e1-d731-11ce-a357-000000000001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsRemovable Interface
```

=20

MS Virtual Disk

=20

    0316560b-5db4-4ed9-bbb5-213436ddc0d9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostElementSchemaCollect=
ion Interface
```

=20

MS IIS

=20

    0344cdda-151e-4cbf-82da-66ae61e97754

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Telnet Server =
Remote Administration Protocol (MS-TSRAP) - IID_IManageTelnetSessions Inter=
face
```

=20

MS Telnet Server

=20

    034634fd-ba3f-11d1-856a-00a0c944138c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    038374ff-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IDataCollectorCollection Interface
```

=20

MS Perf Logs & Alerts

=20

    03837502-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IPerformanceCounterDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    03837506-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - ITraceDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    0383750b-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - ITraceDataProviderCollection Interface
```

=20

MS Perf Logs & Alerts

=20

    03837510-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - ITraceDataProvider Interface
```

=20

MS Perf Logs & Alerts

=20

    03837512-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IConfigurationDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    03837514-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IAlertDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    03837516-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IApiTracingDataCollector Interface
```

=20

MS Perf Logs & Alerts

=20

    0383751a-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IDataCollectorSet Interface
```

=20

MS Perf Logs & Alerts

=20

    03837520-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IDataCollectorSetCollection Interface
```

=20

MS Perf Logs & Alerts

=20

    03837524-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IValueMapItem Interface
```

=20

MS Perf Logs & Alerts

=20

    03837533-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IValueMap Interface
```

=20

MS Perf Logs & Alerts

=20

    03837534-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - Ischedule Interface
```

=20

MS Perf Logs & Alerts

=20

    0383753a-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IScheduleCollection Interface
```

=20

MS Perf Logs & Alerts

=20

    0383753d-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IDataManager Interface
```

=20

MS Perf Logs & Alerts

=20

    03837541-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IFolderAction Interface
```

=20

MS Perf Logs & Alerts

=20

    03837543-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Lo=
gs and Alerts Protocol - IFolderActionCollection Interface
```

=20

MS Perf Logs & Alerts

=20

    03837544-098b-11d8-9414-505054503030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Universal Plug=
 and Play (UPNP) - IUPnPHttpHeaderControl Interface
```

=20

MS UPNP

=20

    0405af4f-8b5c-447c-80f2-b75984a31f3c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - ISearchRoot Interface
```

=20

MS DCOM Services

=20

    04c18ccf-1f57-4cbd-88cc-3900f5195ce3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSearcher3 Interface
```

=20

MS Update Agent

=20

    04c6895d-eaf2-4034-97f3-311de9be413a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterSetup Interface
```

=20

MS Failover Cluster

=20

    04d55210-b6ac-4248-9e69-2a569d1d2ab6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Server - Gopher Publishing Service
```

=20

MS IIS

=20

    04fcb220-fcfd-11cd-bec8-00aa0047ae4e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Securi=
ty Center
```

=20

MS Security

=20

    06bba54a-be05-49f9-b0a0-30f790261023

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IWMPContentProviderFactory Interface
```

=20

MS DCOM Services

=20

    06e333e4-667e-466d-9e34-4a8d5e36e012

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sys=
tem Attendant Service - Version 1.0
```

=20

MS Exchange

=20

    06ed1d30-d3d3-11cd-b80e-00aa004b9c30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Data Se=
rvices (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactor=
y2 Interface
```

=20

MS Remote Data Services

=20

    070669eb-b52f-11d1-9270-00c04fbbbfb3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConstantValue Interf=
ace
```

=20

MS IIS

=20

    0716caf8-7d05-4a46-8099-77594be91394

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Program Compat=
ibility Assistant Service - PcaSvc Interface
```

=20

MS Misc Services

=20

    0767a036-0d22-48aa-ba69-b619480f38cb

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileManagementJob Interface
```

=20

MS File Server

=20

    0770687e-9f36-4d6f-8778-599d188461c9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDisk Interface
```

=20

MS Virtual Disk

=20

    07e5c822-f00c-47a1-8fce-b244da56fd06

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateCollection Interface
```

=20

MS Update Agent

=20

    07f7438c-7709-4ca5-b518-91279288134e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsService Interface
```

=20

MS Virtual Disk

=20

    0818a8ef-9ba9-40d8-a6f9-e22833cc771e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - IMessenger Interface
```

=20

MS Removable Storage

=20

    081e7188-c080-4ff3-9238-29f66d6cabfd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostChildElementCollecti=
on Interface
```

=20

MS IIS

=20

    08a90f5f-0702-48d6-b45f-02a9885a9768

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostChangeHandler Interf=
ace
```

=20

MS IIS

=20

    09829352-87c2-418d-8d79-4133969a489d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Scheduler Serv=
ice - idletask operations
```

=20

MS Scheduler

=20

    0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceHba Interface
```

=20

MS Virtual Disk

=20

    0ac13689-3134-47c6-a17c-4669216801be

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Portmapper Ser=
vice - localepmp Interface
```

=20

MS Portmapper

=20

    0b0a6584-9e0f-11cf-a3cf-00805f68cb1b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Authori=
zation API Protocol (MS-RAA) - authzr Interface
```

=20

MS Security

=20

    0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Print System A=
synchronous Notification Protocol (MS-PAN) - IRPCAsyncNotify Interface
```

=20

MS Print

=20

    0b6edbfa-4a24-4fc6-8a23-942b1eca65d1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateServiceManager2 Interface
```

=20

MS Update Agent

=20

    0bb8531d-7e8d-424f-986c-a0b8f60a3e7b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdateEntryCollection Interface
```

=20

MS Update Agent

=20

    0d521700-a372-4bef-828b-3d00c10adebd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Cryptographic =
Services - ICertProtect
```

=20

MS Crypto

=20

    0d72a7d4-6148-11d1-b4aa-00c04fb66ea0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostSectionGroup Interfa=
ce
```

=20

MS IIS

=20

    0dd8a158-ebe6-4008-a1d9-b7ecc8f1104b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTabl=
eRead Interface
```

=20

MS COM+ Remote Admin

=20

    0e3d6630-b46b-11d1-9d2d-006008b0e5ca

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTabl=
eWrite Interface
```

=20

MS COM+ Remote Admin

=20

    0e3d6631-b46b-11d1-9d2d-006008b0e5ca

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Inf=
ormation Store - exchange_store_information Interface
```

=20

MS Exchange

=20

    0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Data Se=
rvices (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactor=
y Interface
```

=20

MS Remote Data Services

=20

    0eac4842-8763-11cf-a743-00aa00a3f00d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Tr=
ansaction Coordinator (DTC) - ITransaction Interface
```

=20

MS DTC

=20

    0fb15084-af41-11ce-bd2b-204c4f4f5020

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumLMMountPoint Interface
```

=20

MS ISTM iSCSI

=20

    100da538-3f4a-45ab-b852-709148152789

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - ICommDlgBrowser2 Interface
```

=20

MS Explorer Browser

=20

    10339516-2894-11d2-9039-00c04f8eeb3e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Queue Manager to Queue Manager Protocol - qm2qm Interface
```

=20

MS Message Queuing

=20

    1088a980-eae5-11d0-8d9b-00a02453c337

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsProviderInterface
```

=20

MS Virtual Disk

=20

    10c5e575-7984-4e81-a56b-431f5f92ae42

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SoftICE DriverStudio Rem=
ote Control - winice.dat
```

=20

SI DriverStudio RC

=20

    10d1800c-af75-4249-b7a2-484dec69ed3a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Inf=
ormation Store - Function I
```

=20

MS Exchange

=20

    10f24e8e-0fa6-11d2-a910-00c04f990f3b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Protected Stor=
age Service
```

=20

MS Storage

=20

    11220835-5b26-4d94-ae86-c3e475a809de

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Trusted Platfo=
rm Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardMana=
ger Interface
```

=20

MS TPM Smart Card Mgt

=20

    112b1dff-d9dc-41f7-869f-d67fee7cb591

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdate3 Interface
```

=20

MS Update Agent

=20

    112eda6b-95b3-476f-9d90-aee82c6b8181

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IEnumVdsObject Interface
```

=20

MS Virtual Disk

=20

    118610b7-8d94-4030-b5b8-500889788e4e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - LSM Notification Interface
```

=20

MS Terminal Server

=20

    11899a43-2b68-4a76-92e3-a3d6ad8c26ce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterStorage3 Interface
```

=20

MS Failover Cluster

=20

    11942d87-a1de-4e7f-83fb-a840d9c5928d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - LSMAPI - TermSrvPrivate Interface
```

=20

MS Terminal Server

=20

    11f25515-c879-400a-989e-b074d5f092fe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterStorage2 Interface
```

=20

MS Failover Cluster

=20

    12108a88-6858-4467-b92f-e6cf4568dfb6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Print System R=
emote Protocol (MS-RPRN) - Winspool Interface or IPSec Policy Agent Endpoin=
t
```

=20

MS Indeterminate

=20

    12345678-1234-abcd-ef00-0123456789ab

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Netlogon Remot=
e Protocol (MS-NRPC) - Netlogon Interface
```

=20

MS Security

=20

    12345678-1234-abcd-ef00-01234567cffb

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Local Security=
 Authority Remote Protocol - lsarpc Interface
```

=20

MS Security

=20

    12345778-1234-abcd-ef00-0123456789ab

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Security Accou=
nt Manager (SAMR) - samr Interface
```

=20

MS Security

=20

    12345778-1234-abcd-ef00-0123456789ac

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - SessEnvPublicRpc Interface
```

=20

MS Terminal Server

=20

    1257b580-ce2f-4109-82d6-a9459d0bf6bc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmActionCommand Interface
```

=20

MS File Server

=20

    12937789-e247-4917-9c20-f3ee9c7ee783

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft PSFactoryBuffe=
r Interface
```

=20

MS Svchost

=20

    1299cf18-c4f5-4b6a-bb0f-2299f0398e27

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQApplication2 Interface
```

=20

MS Message Queuing

=20

    12a30900-7300-11d2-b0e6-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Secondary Logo=
n Service
```

=20

MS Security

=20

    12b81e99-f207-4a4c-85d3-77b42f76fd14

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Secure Desktop=
 LRPC interface
```

=20

MS Secure Desktop

=20

    12e65dd8-887f-41ef-91bf-8d816c42c2e7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Intersite Mess=
aging Service - ismserv_ip
```

=20

MS Intersite Messaging

=20

    130ceefb-e466-11d1-b78b-00c04fa32883

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IVolumeClient3 Interface
```

=20

MS Disk Management

=20

    135698d2-3a37-4d26-99df-e2bb6ae3ac61

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumWTDiskLunMapping Interface
```

=20

MS ISTM iSCSI

=20

    1396de6f-a794-4b11-b93f-6b69a5b47bae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsPack2 Interface
```

=20

MS Virtual Disk

=20

    13b50bff-290a-47dd-8558-b7c58db1a71a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdate2 Interface
```

=20

MS Update Agent

=20

    144fe9b0-d23d-4a8b-8634-fb4457533b7a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Inf=
ormation Store - Function II
```

=20

MS Exchange

=20

    1453c42c-0fa6-11d2-a910-00c04f990f3b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft ExtendedError =
Remote Data Structure (MS-EERR) - ExtendedError Interface
```

=20

MS EERR

=20

    14a8831c-bc82-11d2-8a64-0008c7457e5d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceIscsi Interface
```

=20

MS Virtual Disk

=20

    14fbe036-3ed7-4e10-90e9-a5ff991aff01

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateService2 Interface
```

=20

MS Update Agent

=20

    1518b460-6518-4172-940f-c75883b24ceb

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange Direc=
tory Referral (Request For Response - RFR) - exchange_ds_rfr Interface
```

=20

MS Exchange

=20

    1544f5e0-613c-11d1-93df-00c04fd7bd09

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaBase Interface
```

=20

MS File Server

=20

    1568a795-3924-4118-b74b-68d8f0fa5daf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmStorageModuleDefinition Interface
```

=20

MS File Server

=20

    15a81350-497d-4aba-80e9-d4dbcc5521fe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceSw Interface
```

=20

MS Virtual Disk

=20

    15fc031c-0652-4306-b2c3-f558b8f837e2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Active Directo=
ry Backup and Restore Services - JetRest Interface
```

=20

MS Active Directory

=20

    16e0cf3a-a604-11d0-96b1-00a0c91ece30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Messenger Serv=
ice Remote Protocol - msgsvc operations for name management methods
```

=20

MS Messenger

=20

    17fdd703-1827-4e34-79d4-24a55c53bb37

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDisk3 Interface
```

=20

MS ISTM iSCSI

=20

    1822a95e-1c2b-4d02-ab25-cc116dd9dbde

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogSess=
ion Interface
```

=20

MS COM+ Remote Admin

=20

    182c40fa-32e4-11d0-818b-00a0c9231c29

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - Interface
```

=20

MS DCOM Services

=20

    18f70770-8e64-11cf-9af1-0020af6e72f4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumPortal Interface
```

=20

MS ISTM iSCSI

=20

    1995785d-2a1e-492f-8923-e621eaca39d9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Dat=
abase Service
```

=20

MS Exchange

=20

    1a190310-bb9c-11cd-90f8-00aa00466520

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Trusted Platfo=
rm Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardMana=
gerStatusCallback Interface
```

=20

MS TPM Smart Card Mgt

=20

    1a1bb35f-abb8-451c-a1ae-33d98f1bef4a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Secur=
ity and Acceleration (ISA) - Management Console
```

=20

MS ISA

=20

    1a77dcb2-97b3-4ffb-9ee7-8f42529841ab

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Queue Manager Remote Read Protocol - RemoteRead Interface
```

=20

MS Message Queuing

=20

    1a9134dd-7b39-45ba-ad88-44d01ca47f28

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Deploy=
ment Services Control Protocol (MS-WDSC) - WdsRpcInterface Interface
```

\<= /td\> =20

MS Deployment Services

=20

    1a927394-352e-4553-ae3f-7cf4aafca620

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service
```

=20

MS Remote Access

=20

    1aa7f844-c7f5-11d0-a376-00c04fc9da04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IFolderView2 Interface
```

=20

MS Explorer Browser

=20

    1af3a467-214f-4298-908e-06b03e0b39f9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISnsMgr Interface
```

=20

MS ISTM iSCSI

=20

    1b1c4d1c-abc4-4d3a-8c22-547fba3aa8a0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmMutableCollection Interface
```

=20

MS File Server

=20

    1bb617b8-3886-49dc-af82-a6c90fa35dda

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumeOnline Interface
```

=20

MS Virtual Disk

=20

    1be2275a-b315-4f70-9e44-879b3a2a53f2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - WBEM providers - IWbemProviderInitSink Interfa=
ce
```

=20

MS WMI

=20

    1be41571-91dd-11d1-aeb2-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - WBEM providers - IWbemProviderInit Interface
```

=20

MS WMI

=20

    1be41572-91dd-11d1-aeb2-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - POP3 - Service
```

=20

MS IIS

=20

    1be617c0-31a5-11cf-a7d8-00805f48a135

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemFetchSmartEnum Interfac=
e
```

=20

MS WMI

=20

    1c1c45ee-4395-11d2-b60b-00104b703efd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Active Directo=
ry DSROLE Service
```

=20

MS Active Directory

=20

    1cbcad78-df0b-4934-b558-87839ea501c9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalog64Bi=
tSupport Interface
```

=20

MS COM+ Remote Admin

=20

    1d118904-94b3-4a64-9fa6-ed432666a7b9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Debugging Help=
er Service
```

=20

MS Debugging

=20

    1d55b526-c137-46c5-ab79-638f2a68e869

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVDisk Interface
```

=20

MS Virtual Disk

=20

    1e062b84-e5e6-4b4b-8a25-67b81e8f13e8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - LSMAPI - TermSrvAdmin Interface
```

=20

MS Terminal Server

=20

    1e665584-40fe-4450-8f6e-802362399694

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IImport2 Int=
erface
```

=20

MS COM+ Remote Admin

=20

    1f7b1697-ecb2-4cbb-8a0e-75c427f4a6f0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Task Scheduler=
 Service Remote Protocol - ATSvc
```

=20

MS Scheduler

=20

    1ff70682-0a51-30e8-076d-740be8cee98b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - AppInfo Interface
```

=20

MS DCOM Services

=20

    201ef99a-7fa0-444c-9399-19ba84f12a1a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenTemplate Interface
```

=20

MS File Server

=20

    205bebf8-dd93-452a-95a6-32b566b35828

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service (RRAS) Management Protocol - rasrpc Interface
```

=20

MS Remote Access

=20

    20610036-fa22-11cf-9823-00a0c911e5df

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DFS Replicatio=
n Helper Protocol - IServerHealthReport2 Interface
```

=20

MS DFS Replication

=20

    20d15747-6c48-4254-a358-65039fd8c63c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Shadow Copy Ma=
nagement Protocol - IVssDifferentialSoftwareSnapshotMgmt Interface
```

=20

MS Volume Shadow Copy

=20

    214a0f28-b737-4026-b847-4f9e37d79529

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMConfig Interface
```

=20

MS System Resource

=20

    21546ae8-4da5-445e-987f-627fea39c5e8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Unified Backgr=
ound Process Manager - ubpmtaskhostchannel Interface
```

=20

MS UBPM

=20

    22716894-fd8e-4462-9783-09e6d9531f16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - AppHostAdminManager
```

=20

MS IIS

=20

    228fb8f7-fb53-4fd5-8c7b-ff59de606c5b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmObject Interface
```

=20

MS File Server

=20

    22bcef93-4a3f-4183-89f9-2f8b8a628aee

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Profil=
e Service - INotifyNetworkEvents Interface
```

=20

MS Network Profile

=20

    22d2e146-1a68-40b8-949c-8fd848b415e6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateServiceManager Interface
```

=20

MS Update Agent

=20

    23857e3c-02ba-44a3-9423-b1c900805f37

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Tracker Service Protocol - IProcessDump Interface
```

=20

MS COM+ Tracker

=20

    23c9dd26-2355-4fe2-84de-f779a238adbd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMAP4 Service
```

=20

MS IIS

=20

    2465e9e0-a873-11d0-930b-00a0c90ab17c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISnsMgr CLSID
```

=20

MS ISTM iSCSI

=20

    24f9c1a9-b22e-4e24-bec9-4af0a4d96736

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Trend Micro ServerProtec=
t
```

=20

TM SRVPROTECT

=20

    25288888-bd5b-11d1-9d53-0080c83a5c2c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Profil=
e Service - IEnumNetwork Interface
```

=20

MS Network Profile

=20

    26656eaa-54eb-4e6f-8f85-4f0ef901a406

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmReportManager Interface
```

=20

MS File Server

=20

    27b899fe-6ffa-4481-a184-d3daade8a02b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdate4 Interface
```

=20

MS Update Agent

=20

    27e94b0d-5139-49a2-9a61-93522dc54652

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IDirectoryEnum Interface
```

=20

MS ISTM iSCSI

=20

    28bc8d5e-ca4b-4f54-973c-ed9622d2b3ac

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterNetwork2 Interface
```

=20

MS Failover Cluster

=20

    2931c32c-f731-4c56-9feb-3d5f1c5e72bf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IWamAdmin Interface
```

=20

MS IIS

=20

    29822ab7-f302-11d0-9953-00c04fd919c1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IWamAdmin2 Interface
```

=20

MS IIS

=20

    29822ab8-f302-11d0-9953-00c04fd919c1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Profil=
e Service - INetworkInterface Interface
```

=20

MS Network Profile

=20

    2a1c9eb2-df62-4154-b800-63278fcb8037

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IResourceManager2 Interface
```

=20

MS System Resource

=20

    2a3eb639-d134-422d-90d8-aaa1b5216202

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Profil=
e Service - INotifyNetworkInterfaceEvents Interface
```

=20

MS Network Profile

=20

    2abc0864-9677-42e5-882a-d415c556c284

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsHbaPort Interface
```

=20

MS Virtual Disk

=20

    2abd757f-2851-4997-9a13-47d2a885d6ca

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - AppHostWritableAdminManager<=
/pre>
```

=20

MS IIS

=20

    2b72133b-3f5b-4602-8952-803546ce3344

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Tr=
ansaction Coordinator (DTC) - WinRM Interface
```

=20

MS DTC

=20

    2b7ee790-e8c8-4820-97db-cdff70129887

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemRefreshingServices Inte=
rface
```

=20

MS WMI

=20

    2c9273e0-1dc3-11d3-b364-00105a1f8177

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransaction2 Interface
```

=20

MS Message Queuing

=20

    2ce0c5b0-6e67-11d2-b0e6-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostMethodSchema Interfa=
ce
```

=20

MS IIS

=20

    2d9915fb-9d42-4328-b782-1b46819fab9e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmActionReport Interface
```

=20

MS File Server

=20

    2dbe63c4-b340-48a0-a5b0-158e07fc567e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Group Policy C=
lient Service - IGroupPolicyUtilities Interface
```

=20

MS Security

=20

    2eb08e3e-639f-4fba-97b1-14f878961076

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdatesSettings Interface
```

=20

MS Update Agent

=20

    2ee48f22-af3c-405f-8970-f71be12ee9a2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Licensing - LCRPC Operations
```

=20

MS Terminal Server

=20

    2f59a331-bf7d-48cb-9ec5-7c090d76e8b8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Dynami=
c Data Exchange Service - nddeapi
```

=20

MS Network DDE

=20

    2f5f3220-c126-1076-b549-074d078619da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Telephony Remo=
te Protocol - tapsrv Interface
```

=20

MS Telephony

=20

    2f5f6520-ca46-1067-b319-00dd010662da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Telephony Remo=
te Protocol - remotesp Interface
```

=20

MS Telephony

=20

    2f5f6521-ca47-1068-b319-00dd010662db

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Unimodem LRPC =
Endpoint
```

=20

MS Telephony

=20

    2f5f6521-cb55-1059-b446-00df0bce31db

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Firewa=
ll - FwRpc Interface
```

=20

MS Security

=20

    2fb92682-6599-42dc-ae13-bd2ca89bd11c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Li=
nk Tracking - Workstation Protocol
```

=20

MS DLT

=20

    300f3532-38cc-11d0-a3f0-0020af6b0add

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Name Resolutio=
n Proxy (NRP) RPC interface - NRP Server Endpoint - NameResolutionProxy Int=
erface
```

=20

MS Name Resolution Proxy

=20

    30adc50c-5cbc-46ce-9a0e-91914789e23c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IStatusNotify Interface
```

=20

MS ISTM iSCSI

=20

    312cc019-d5cd-4ca7-8c10-9e0a661f147e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostMappingExtension Int=
erface
```

=20

MS IIS

=20

    31a83ea0-c0e4-4a2c-8a01-353cc2a4c60a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft WinLogon - Pro=
file Mapper
```

=20

MS Security

=20

    326731e3-c1c0-4a69-ae20-7d9044a4ea5c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPropertyCondition Interface
```

=20

MS File Server

=20

    326af66f-2ac0-4f68-bf8c-4759f054fa29

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SoftICE DriverStudio Rem=
ote Control
```

=20

SI DriverStudio RC

=20

    32d90706-b698-4029-b236-e18ebff582b1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Unified Backgr=
ound Process Manager - ubpmrpc Interface
```

=20

MS UBPM

=20

    33511f95-5b84-4dcc-b6cc-3f4b21da53e1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Registr=
y Protocol / Microsoft Remote Shutdown Protocol - WinReg Interface
```

=20

MS Remote Services

=20

    338cd001-2244-31f1-aaaa-900038001003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQQueueManagement
```

=20

MS Message Queuing

=20

    33b6d07e-f27d-42fa-b2d7-bf82e11e9374

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Offline Files Provider - IOfflineFilesEventsFi=
lter Interface
```

=20

MS WMI

=20

    33fc4e1b-0716-40fa-ba65-6e62a84a846f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Licensing Logg=
ing Service - llsrpc Interface
```

=20

MS Security

=20

    342cfd40-3c6c-11ce-a893-08002b2e9c6d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumIDMethod Interface
```

=20

MS ISTM iSCSI

=20

    345b026b-5802-4e38-ac75-795e08b0b83f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft WinHttp Auto-P=
roxy Service
```

=20

MS WinHttp Auto-Proxy

=20

    3473dd4d-2e88-4006-9cba-22570909dd10

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDisk2 Interface
```

=20

MS ISTM iSCSI

=20

    348a0821-69bb-4889-a101-6a9bde6fa720

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IExplorerBrowserEvents Interface
```

=20

MS Explorer Browser

=20

    361bbdc7-e6ee-4e13-be58-58e2240c810f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Service Contro=
l Manager Remote Protocol (MS-SCMR) - svcctl Interface
```

=20

MS SCM

=20

    367abb81-9844-35f1-ad32-98f038001003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft WinLogin - Pro=
file Mapper
```

=20

MS Security

=20

    369ce4f0-0fdc-11d3-bde8-00c04f8eee78

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConfigLocation Inter=
face
```

=20

MS IIS

=20

    370af178-7758-4dad-8146-7391f6e18585

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuota Interface
```

=20

MS File Server

=20

    377f739d-9647-4b8e-97d2-5ffce6d759cd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Task Scheduler=
 Service Remote Protocol - SASec
```

=20

MS Scheduler

=20

    378e52b0-c0a9-11cf-822d-00aa0051e40f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Und=
ocumented Interface 2
```

=20

MS Exchange

=20

    37fc1b02-da36-4b27-a745-bf2f58a98ff6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsAdvancedDisk3 Interface
```

=20

MS Virtual Disk

=20

    3858c0d5-0f35-4bf5-9714-69874963bc36

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsIscsiInitiatorPortal
```

=20

MS Virtual Disk

=20

    38a0a9ab-7cc8-4693-ac07-1f28bd03c3da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Mes=
sage Transfer Agent (MTA) Service - exchange_mta_qadmin Interface
```

=20

MS Exchange

=20

    38a94e72-a9bc-11d2-8faf-00c04fa378ff

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmReportJob Interface
```

=20

MS File Server

=20

    38e87280-715c-4c7d-a280-ea1651a19fef

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Directory Serv=
ices Setup Remote Protocol (MS-DSSP)
```

=20

MS Active Directory

=20

    3919286a-b10c-11d0-9ba8-00c04fd92ef5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmDerivedObjectsResult Interface
```

=20

MS File Server

=20

    39322a2d-38ee-4d0d-8095-421a80849a82

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQManagement
```

=20

MS Message Queuing

=20

    39ce96fe-f4c5-4484-a143-4c2d5d324229

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IDMRemoteServer Interface
```

=20

MS Disk Management

=20

    3a410f21-553f-11d1-8e5e-00a0c92c9d5d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - ICategoryCollection Interface
```

=20

MS Update Agent

=20

    3a56bfb8-576c-43f7-9335-fe4838fd7e37

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsPack Interface
```

=20

MS Virtual Disk

=20

    3b69d7f5-9d94-4648-91ca-79939ba263bf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsObjectManagement3 Interface
```

\<= /td\> =20

MS Removable Storage

=20

    3bbed8d9-2c9a-4b21-8936-acb2f995be6c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DHCP Client Se=
rvice
```

=20

MS DHCP

=20

    3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DHCPv6 Client =
Service
```

=20

MS DHCP

=20

    3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTGeneral2 Interface
```

=20

MS ISTM iSCSI

=20

    3c73848a-a679-40c5-b101-c963e67f9949

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Trusted Platfo=
rm Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardMana=
ger3 Interface
```

=20

MS TPM Smart Card Mgt

=20

    3c745a97-f375-4150-be17-5950f694c699

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Rec=
ipient Update Service Interface
```

=20

MS Exchange

=20

    3cb4be69-9ba1-448c-9a44-a1f759a1878a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterFirewall Interface
```

=20

MS Failover Cluster

=20

    3cfee98c-fb4b-44c6-bd98-a1db14abca3f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Licensing
```

=20

MS Terminal Server

=20

    3d267954-eeb7-11d1-b94e-00c04fa3080d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Associates - An=
tivirus / e-Trust Antivirus / Threat Manager
```

=20

CA AntiVir

=20

    3d742890-397c-11cf-9bf1-00805f88cb72

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OLE Container =
- IAsyncOperation / IDataObjectAsyncCapability Interface
```

=20

MS OLE Container

=20

    3d8b0590-f691-11d2-8ea9-006097df5bd4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Protected Stor=
age Service - BackupKey Remote Protocol - BackupKey Interface
```

=20

MS Storage

=20

    3dde7c30-165d-11d1-ab8f-00805f14db40

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IContainerCo=
ntrol Interface
```

=20

MS COM+ Remote Admin

=20

    3f3b1b86-dbbe-11d1-9da6-00805f85cfe3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft SQL Server RPC=
```

=20

MS SQL Server

=20

    3f99b900-4d87-101b-99b7-aa0004007f07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Audio =
Service - Audio Server
```

=20

MS Audio

=20

    3faf4738-3a21-4307-b46c-fdda9bb8c0d5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumSession Interface
```

=20

MS ISTM iSCSI

=20

    40cc8569-6d23-4005-9958-e37f08ae192b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDisk2 Interface
```

=20

MS Virtual Disk

=20

    40f73c8b-687d-4a13-8d96-3d7f2e683936

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Queue Manager Management Protocol - qmmgmt Interface
```

=20

MS Message Queuing

=20

    41208ee0-e970-11d1-9b9e-00e02c064c39

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Service Contro=
l Manager - ISCM
```

=20

MS SCM

=20

    412f241e-c12a-11ce-abff-0020af6e7a17

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterUpdate Interface
```

=20

MS Failover Cluster

=20

    4142dd5d-3472-4370-8641-de7856431fb0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaTemplateManager Interface
```

=20

MS File Server

=20

    4173ac41-172d-4d52-963c-fdc7e415f717

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Ser=
ver
```

=20

MS Exchange

=20

    41f5fae1-e0ac-414c-a721-0d287466cb23

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemWCOSmartEnum Interface<=
/pre>
```

=20

MS WMI

=20

    423ec01e-2e35-11d2-b604-00104b703efd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileGroupManager Interface
```

=20

MS File Server

=20

    426677d5-018c-485c-8a51-20b86d00bdc4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaObject Interface
```

=20

MS File Server

=20

    42dc3511-61d5-48ae-b6dc-59fc00c0a8d6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumSession2 Interface
```

=20

MS ISTM iSCSI

=20

    442931d5-e522-4e64-a181-74e98a4e1748

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemContext Interface
```

=

=20

MS WMI

=20

    44aca674-e8fc-11d0-a07c-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemCallResult Interface
```

=20

MS WMI

=20

    44aca675-e8fc-11d0-a07c-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Gateway Server Protocol - TsProxyRpcInterface Interface
```

\<= /td\> =20

MS Terminal Server

=20

    44e265dd-7daf-42cd-8560-3cdb6e7a2729

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostPropertySchema
```

=

=20

MS IIS

=20

    450386db-7409-4667-935e-384dbbee2a9e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogUtil=
s Interface
```

=20

MS COM+ Remote Admin

=20

    456129e2-1078-11d2-b0f9-00805fc73204

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DNS Client Ser=
vice - Windows XP and above - DnsResolver
```

=20

MS DNS

=20

    45776b01-5956-4485-9f80-f428f7d60129

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Adminis=
trative Interface: WINS protocol - winsif Interface
```

=20

MS WINS

=20

    45f52c28-7f9f-101a-b52b-08002b2efabe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateIdentity Interface
```

=20

MS Update Agent

=20

    46297823-9940-4c09-aed9-cd3ea6d05968

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Data Se=
rvices (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactor=
y3 Interface
```

=20

MS Remote Data Services

=20

    4639db2a-bfc5-11d2-9318-00c04fbbbfb3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sys=
tem Attendant Service - Version 16.0
```

=20

MS Exchange

=20

    469d6ec0-0d87-11ce-b13f-00aa003bac6c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPropertyDefinition2 Interface
```

=20

MS File Server

=20

    47782152-d16c-4229-b4e1-0ddfe308b9f6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICapabilityS=
upport Interface
```

=20

MS COM+ Remote Admin

=20

    47cde9a1-0bf6-11d2-8016-00c04fb9988e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMCalendar Interface
```

=20

MS System Resource

=20

    481e06cf-ab04-4498-8ffe-124a0a34296d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Winlogon - IPr=
ofileDialog
```

=20

MS Security

=20

    4825ea41-51e3-4c2a-8406-8f2d2698395f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaManagerEx Interface
```

=20

MS File Server

=20

    4846cb01-d430-494f-abb4-b1054999fb09

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - LSM Session Interface
```

=20

MS Terminal Server

=20

    484809d6-4239-471b-b5bc-61df8c23ac48

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterSetup Interface
```

=20

MS Failover Cluster

=20

    491260b5-05c9-40d9-b7f2-1f7bdae0927f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - TermSrv Listener Interface
```

=20

MS Terminal Server

=20

    497d95a6-2d27-4bf5-9bbd-a6046957133c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdate3 Interface
```

=20

MS Update Agent

=20

    49ebd502-4a96-41bd-9e3e-4c5057f4250c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdates2 Interface
```

=20

MS Update Agent

=20

    4a2f5c31-cfd9-410e-b7fb-29a653973a0f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSubscription Interface
```

=20

MS COM+ Event System

=20

    4a6b0e15-2e38-11d1-9965-00c04fbbb345

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSubscription2 Interface<=
/pre>
```

=20

MS COM+ Event System

=20

    4a6b0e16-2e38-11d1-9965-00c04fbbb345

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmProperty Interface
```

=20

MS File Server

=20

    4a73fee4-4102-4fcc-9ffb-38614f9ee768

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceInitialization Interface
```

=20

MS Virtual Disk

=20

    4afc3636-db01-4052-80c3-03bbcb8d3c69

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Simple Service=
 Discovery Protocol (SSDP) Service - ssdpsrv Interface
```

=20

MS SSDP

=20

    4b112204-0e19-11d3-b42b-0000f81feb9f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Server Service=
 Remote Protocol (MS-SRVS) - srvsvc Interface
```

=20

MS Sharing

=20

    4b324fc8-1670-01d3-1278-5a47bf6ee188

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DFS Replicatio=
n Helper Protocol - IADProxy Interface
```

=20

MS DFS Replication

=20

    4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IVolumeClient2 Interface
```

=20

MS Disk Management

=20

    4bdafc52-fe6a-11d2-93f8-00105a11164a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmActionEventLog Interface
```

=20

MS File Server

=20

    4c8f96c3-5d94-4f37-a4f4-f56ab463546f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSearcher2 Interface
```

=20

MS Update Agent

=20

    4cbdcb2d-1589-4beb-bd1c-3e582ff0add0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - Remote Activation
```

=20

MS DCOM Services

=20

    4d9f4ab8-7d1c-11cf-861e-0020af6e7c57

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Li=
nk Tracking - Central Manager Protocol
```

=20

MS DLT

=20

    4da1c422-943d-11d1-acae-00c04fc2aa3f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumePlex Interface
```

=20

MS Virtual Disk

=20

    4daa0135-e1d1-40f1-aaa5-3cc1e53221c3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumeMF2 Interface
```

=20

MS Virtual Disk

=20

    4dbcee9a-6343-4651-b85f-5e75d74d983c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConfigException Inte=
rface
```

=20

MS IIS

=20

    4dfa1df3-8900-4bc7-bbb5-d1a458c52410

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSystem Interface
```

=20

MS COM+ Event System

=20

    4e14fb9f-2e22-11d1-9964-00c04fbbb345

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISnapshotMgr Interface
```

=20

MS ISTM iSCSI

=20

    4e65a71e-4ede-4886-be67-3c90a08d1f29

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Tracker Service Protocol - IComTrackingInfoEvents Inte=
rface
```

=20

MS COM+ Tracker

=20

    4e6cdcc9-fb25-4fd5-9cc5-c9f4b6559cec

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISnapshotMgr CLSID
```

=20

MS ISTM iSCSI

=20

    4e7645fa-1a95-416c-b38f-ad574a3c3e57

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsLibraryControl1 Interface
```

=20

MS Removable Storage

=20

    4e934f30-341a-11d1-8fb1-00a024cb6019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMAccounting Interface
```

=20

MS System Resource

=20

    4f7ca01c-a9e5-45b6-b142-2332a1339c1d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - NNTP Service
```

=20

MS IIS

=20

    4f82f460-0e21-11cf-909e-00805f48a135

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Fi=
le System (DFS) - netdfs Interface
```

=20

MS DFS

=20

    4fc742e0-4a10-11cf-8273-00aa004ae673

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateExceptionCollection : IDispatch Interface
```

=

=20

MS Update Agent

=20

    503626a3-8e14-4729-9355-0fe664bd2321

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Associates Brig=
htStor - Message Engine [Vulnerability 1]
```

=20

CA BrightStor

=20

    506b1890-14c8-11d1-bbc3-00805fa6962e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows DNS Se=
rver
```

=20

MS DNS

=20

    50abc2a4-574d-40b3-9d66-ee4fd5fba076

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPipelineModuleDefinition Interface
```

=20

MS File Server

=20

    515c1277-2c81-440e-8fcf-367921ed4f59

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Key Management=
 Server (KMS) - RequestActivation Interface
```

=20

MS Security

=20

    51c82175-844e-4750-b0d8-ec255555bc06

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service AsyncEMSMDB Interface
```

=20

MS Exchange

=20

    5261574a-4572-206e-b268-6b199213b4e4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDiskMgr Interface
```

=20

MS ISTM iSCSI

=20

    52ba97e7-9364-4134-b9cb-f8415213bdd8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Server Cluster=
 - Configuration Protocol (MC-CCFG) - IClusCfgAsyncEvictCleanup Interface
```

=20

MS Server Cluster

=20

    52c80b95-c1ad-4240-8d89-72e9fa84025e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Und=
ocumented Interface 4
```

=20

MS Exchange

=20

    52d3f3f5-248c-4d74-a01f-a06e41d5cd59

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDiskPartitionMF Interface
```

=20

MS Virtual Disk

=20

    538684e0-ba3d-4bc0-aca9-164aff85c2a9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - TSVIPPublic Interface
```

=20

MS Terminal Server

=20

    53b46b02-c73b-4a3e-8dee-b16b80672fc0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - WWW Publishing Service
```

=20

MS IIS

=20

    53e75790-d96b-11cd-ba18-08002b2dfead

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemLoginHelper Interface
```

=20

MS WMI

=20

    541679ab-2e5f-11d3-b34e-00104bcc4b4a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Client=
 Certificate Enrollment Protocol (MS-WCCE) - ICertRequestD2 - Interface
```

=20

MS Security

=20

    5422fd3a-d4b8-4cef-a12e-e87d4ca22e90

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateDownloadContent
```

=20

MS Update Agent

=20

    54a2cb2d-9a0c-48b6-8a50-9abb69ee2d02

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumWTDisk Interface
```

=20

MS ISTM iSCSI

=20

    56e65ea5-cdff-4391-ba76-006e42c2d746

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Licensing Logg=
ing Service - lls_license Interface
```

=20

MS Security

=20

    57674cd0-5200-11ce-a897-08002b2e9c6d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDiskMgr2 Interface
```

=20

MS ISTM iSCSI

=20

    592381e5-8d3c-42e9-b7de-4e77a1f75ae4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMMachineGroup Interface
```

=20

MS System Resource

=20

    59602eb6-57b0-4fd8-aa4b-ebf06971fe15

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Messenger Serv=
ice Remote Protocol - msgsvcsend operations for the NetrSendMessage method<=
/pre>
```

=20

MS Messenger

=20

    5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConstantValueCollect=
ion Interface
```

=20

MS IIS

=20

    5b5a68e6-8b9f-45e1-8199-a95ffccdffff

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Management Service - qmrepl Interface
```

=20

MS Message Queuing

=20

    5b5b3580-b0e0-11d1-b92d-0060081e87f0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DHCP Server - =
dhcpsrv2 Interface
```

=20

MS DHCP

=20

    5b821720-f63b-11d0-aad2-00c04fc324db

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - FTP Publishing Service
```

=20

MS IIS

=20

    5c89f409-09cc-101a-89f3-02608c4d2361

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - Legacy - WinStation_RPC Operations
```

=20

MS Terminal Server

=20

    5ca4a760-ebb1-11cf-8611-00a0245420ed

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Protected Stor=
age Service - Password Recovery
```

=20

MS Storage

=20

    5cbe92cb-f4be-45c9-9fc9-33e73e557b20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreen Interface
```

=20

MS File Server

=20

    5f6325d3-ce88-4733-84c1-2d6aefc5ea07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteSstpCertCheck
```

=20

MS Remote Access

=20

    5ff9bdf6-bd91-4d8b-a614-d6317acc8dd8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Fax Client Int=
erface
```

=20

MS Fax

=20

    6099fc12-3eff-11d0-abd0-00c04fd91a4e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteIPV6Config
```

=20

MS Remote Access

=20

    6139d8a4-e508-4ebb-bac7-d7f275145897

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdate2 Interface
```

=20

MS Update Agent

=20

    615c4269-7a48-43bd-96b7-bf6ca27d6c3e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - DShellFolderViewEvents Interface
```

=20

MS Explorer Browser

=20

    62112aa2-ebe4-11cf-a5fb-0020afe7292d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Wireless Confi=
guration Service
```

=20

MS Remote Services

=20

    621dff68-3c39-4c6c-aae3-e68e2c6503ad

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft System Event N=
otification Service - SensNotify
```

=20

MS Event

=20

    629b9f66-556c-11d1-8dd2-00aa004abd5e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Associates Brig=
htStor ARCserve Backup Tape Engine
```

=20

CA BrightStor

=20

    62b93df0-8b02-11ce-876c-00805f842837

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft System Event N=
otification Service - SensApi
```

=20

MS Event

=20

    63fbe424-2029-11d1-8db8-00aa004abd5e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumResourceGroup Interface
```

=20

MS ISTM iSCSI

=20

    640038f1-d626-40d8-b52b-09660601d045

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQOutgoingQueueManagement Interface
```

=20

MS Message Queuing

=20

    64c478fb-f9b0-4695-8a7f-439ac94326d3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Portmapper Ser=
vice - FwIdl
```

=20

MS Portmapper

=20

    64fe0b7f-9ef5-4553-a7db-9a1975777554

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostElement Interface
```

=20

MS IIS

=20

    64ff8ccc-b287-4dae-b08a-a72cbf45f453

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DNS Client Ser=
vice - Windows 2000 and before
```

=20

MS DNS

=20

    65a93890-fab9-43a3-b2a5-1e330ac28f11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft IManagedObject=
 Interface Protocol - IRemoteDispatch: IDispatch Interface
```

=20

MS IManagedObject

=20

    6619a740-8154-43be-a186-0319578e02db

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteNetworkConfig
```

=20

MS Remote Access

=20

    66a2db1b-d706-11d0-a37b-00c04fc9da04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteRouterRestart
```

=20

MS Remote Access

=20

    66a2db20-d706-11d0-a37b-00c04fc9da04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteSetDNSConfig
```

=20

MS Remote Access

=20

    66a2db21-d706-11d0-a37b-00c04fc9da04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteICFICSConfig
```

=20

MS Remote Access

=20

    66a2db22-d706-11d0-a37b-00c04fc9da04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumSnapshot Interface
```

=20

MS ISTM iSCSI

=20

    66c9b082-7794-4948-839a-d8a5a616378f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdates Interface
```

=20

MS Update Agent

=20

    673425bf-c082-4c7c-bdfd-569464b8e0ce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemContext - Unmarshaler I=
nterface
```

=20

MS WMI

=20

    674b6698-ee92-11d0-ad71-00c04fd8fdff

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumeMF3 Interface
```

=20

MS Virtual Disk

=20

    6788faf9-214e-4b85-ba59-266953616e09

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sys=
tem Attendant Service - Version 3.0
```

=20

MS Exchange

=20

    67df7c70-0f04-11ce-b13f-00aa003bac6c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service - IRemoteStringIdConfig
```

=20

MS Remote Access

=20

    67e08fc2-2984-4b62-b92e-fc1aae64bbbb

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IInputObject Interface
```

=20

MS Explorer Browser

=20

    68284faa-6a48-11d0-8c78-00c04fd918b4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmReportScheduler Interface
```

=20

MS File Server

=20

    6879caf9-6617-4484-8719-71c3d8645f94

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Cryptographic =
Services - IKeySvc2
```

=20

MS Crypto

=20

    68b58241-c259-4f03-a2e5-a2651dcbc930

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Intersite Mess=
aging Service - ismapi Interface
```

=20

MS Intersite Messaging

=20

    68dcd486-669e-11d1-ab0c-00c04fc2dcd2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsObjectInfo1 Interface
```

=20

MS Removable Storage

=20

    69ab7050-3059-11d1-8faf-00a024cb6019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdate Interface
```

=20

MS Update Agent

=20

    6a92b07a-d821-4682-b423-5c805022cc4d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdatesSettings2 Interface
```

=20

MS Update Agent

=20

    6abc136a-c3ca-4384-8171-cb2b1e59b8dc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumConnection Interface
```

=20

MS ISTM iSCSI

=20

    6aea6b26-0680-411d-8877-a148df3087d5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Firewall and A=
dvanced Security Protocol (MS-FASP) - RemoteFW Interface
```

=20

MS Security

=20

    6b5bdd1e-528c-422c-af8c-a4079be4fe48

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Common Interne=
t File System (CIFS) - Browser Auxiliary Protocol - Browser Interface
```

=

=20

MS CIFS Browser

=20

    6bffd098-a112-3610-9833-012892020162

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DHCP Server - =
dhcpsrv Interface
```

=20

MS DHCP

=20

    6bffd098-a112-3610-9833-46c3f874532d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Workstation Se=
rvice Remote Protocol - wkssvc Interface
```

=20

MS Remote Services

=20

    6bffd098-a112-3610-9833-46c3f87e345a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IContainerCo=
ntrol2 Interface
```

=20

MS COM+ Remote Admin

=20

    6c935649-30a6-4211-8687-c4c83e5fe1c7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmAction Interface
```

=20

MS File Server

=20

    6cd6408a-ae60-463b-9ef1-e117534d69dc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IServiceProvider Interface
```

=20

MS Explorer Browser

=20

    6d5140c1-7436-11ce-8034-00aa006009fa

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsAdvancedDisk Interface
```

=20

MS Virtual Disk

=20

    6e6f6b40-977c-4069-bddd-ac710059f8c0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPathMapper Interface
```

=20

MS File Server

=20

    6f4dbfff-6920-4821-a6c3-b7e94c1fd60c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDiskMgr4 Interface
```

=20

MS ISTM iSCSI

=20

    703e6b03-7ad1-4ded-ba0d-e90496ebc5de

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Directory Service Protocol - dscomm2 Interface
```

=20

MS Message Queuing

=20

    708cca10-9569-11d1-b2a5-0060977d8118

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IMSAdminBaseW Interface
```

=20

MS IIS

=20

    70b51430-b6ca-11d0-b9b9-00a0c922e750

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdate5 Interface
```

=20

MS Update Agent

=20

    70cf5c82-8642-42bb-9dbc-0cfd263c6c4f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolume2 Interface
```

=20

MS Virtual Disk

=20

    72ae6713-dcbb-4a03-b36b-371f6ac6b53d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - ISearchJob Interface
```

=20

MS Update Agent

=20

    7366ea16-7a1a-4ea2-b042-973d3e9cd99b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Tr=
ansaction Coordinator (DTC) - DTCPing Interface
```

=20

MS DTC

=20

    75687379-aaaa-44f6-9512-080ac70f8ad9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsOpenDisk Interface
```

=20

MS Virtual Disk

=20

    75c8f324-f715-4fe3-a28e-f9011b61a4a1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateService Interface
```

=20

MS Update Agent

=20

    76b3b17e-aed6-4da5-85f0-83587f81abe3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Und=
ocumented Interface 1
```

=20

MS Exchange

=20

    76c0d124-a18e-49d4-adf1-d8c6ba868ea6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Queue Manager Client Protocol - qmcomm2 Interface
```

=20

MS Message Queuing

=20

    76d12b80-3467-11d3-91ff-0090272f9ea3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Print System A=
synchronous Remote Protocol (MS-PAR) - IRemoteWinspool Interface
```

=20

MS Print

=20

    76f03f96-cdfd-44fc-a22c-64950a001209

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Directory Service Protocol - dscomm Interface
```

=20

MS Message Queuing

=20

    77df7a80-f298-11d0-8358-00a024c480a8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft OCSP Administr=
ation Protocol (MS-OCSPA) - IOCSPAdminD Interface
```

=20

MS Security

=20

    784b693d-95f3-420b-8126-365c098659f2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostMethod Interface
```

=20

MS IIS

=20

    7883ca1c-1112-4447-84c3-52fbeb38069d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Directory Repl=
ication Service (DRS) Remote Protocol - DSAOP Methods
```

=20

MS Active Directory

=20

    7c44d7d4-31d5-424c-bd5e-2b3e1f323d22

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IIISApplicationAdmin Interface
```

=20

MS IIS

=20

    7c4e1804-e342-483d-a43e-a850cfcc8d18

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemObjectSink Interface
```

=20

MS WMI

=20

    7c857801-7381-11cf-884d-00aa004b2e24

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IImageInformation Interface
```

=20

MS Update Agent

=20

    7c907864-346c-4aeb-8f3f-57da289f969f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - IRobustNtmsMediaServices1 Interface
```

=20

MS Removable Storage

=20

    7d07f313-a53f-459a-bb12-012c15b1846e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g Service
```

=20

MS Message Queuing

=20

    7e048d38-ac08-4ff1-8e6b-f35dbab88d4a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IAlternateLa=
unch Interface
```

=20

MS COM+ Remote Admin

=20

    7f43b400-1a0e-4d57-bbc9-6b0c65f7a889

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Firewa=
ll - Fw_Resource_Indication Interface
```

=20

MS Security

=20

    7f9d11bf-7fb9-436b-a812-b2d50c5d4c03

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventClass3 Interface
```

=20

MS COM+ Event System

=20

    7fb7ea43-2d76-4ea8-8cd9-3decc270295e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueManagement Interface
```

=20

MS Message Queuing

=20

    7fbe7759-5760-444d-b8a5-5e7ab9a84cce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Certificate Se=
rvices Remote Administration Protocol - ICertAdminD2 Interface
```

=20

MS Security

=20

    7fe0d935-dda6-443f-85d0-1cfb58fe41dd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Adminis=
trative Interface: WINS protocol - winsi2 Interface
```

=20

MS WINS

=20

    811109bf-a4e1-11d1-ab54-00a0c91e9b45

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft IManagedObject=
 Interface Protocol - IServicedComponentInfo Interface
```

=20

MS IManagedObject

=20

    8165b19e-8d3a-4d0b-80c8-97de310db583

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSession Interface
```

=20

MS Update Agent

=20

    816858a4-260d-4260-933a-2585f1abc76b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - ICategory Interface
```

=20

MS Update Agent

=20

    81ddc1b8-9d35-47a6-b471-5b80f519223b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumVolume Interface
```

=20

MS ISTM iSCSI

=20

    81fe3594-2495-4c91-95bb-eb5785614ec7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft EventLog Remot=
ing Service - eventlog Interface
```

=20

MS Event

=20

    82273fdc-e32a-18c3-3f78-827929dc23ea

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmActionEmail2 Interface
```

=20

MS File Server

=20

    8276702f-2532-4839-89bf-4872609a2ea4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IMSAdminBase2W Interface
```

=20

MS IIS

=20

    8298d101-f992-43b7-8eca-5052d885b995

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Inetinfo - IISAdmin Service
```

=20

MS IIS

=20

    82ad4280-036b-11cf-972c-00aa006887b0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsAdviseSink Interface
```

=20

MS Virtual Disk

=20

    8326cd1d-cf59-4936-b786-5efc08798e25

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConfigLocationCollec=
tion Interface
```

=20

MS IIS

=20

    832a32f7-b3ea-4b8c-b260-9a2923001184

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Assista=
nce Initiation Protocol - IPCHCollection Interface
```

=20

MS Remote Assistance

=20

    833e4100-aff7-4ac3-aac2-9f24c1457bce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Assista=
nce Initiation Protocol - ISAFSession Interface
```

=20

MS Remote Assistance

=20

    833e41aa-aff7-4ac3-aac2-9f24c1457bce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Assista=
nce Initiation Protocol - IPCHService Interface
```

=20

MS Remote Assistance

=20

    833e4200-aff7-4ac3-aac2-9f24c1457bce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Fun=
ction I
```

=20

MS Exchange

=20

    8384fc47-956a-4d1e-ab2a-1205014f96ec

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsSubSystemImportTarget Interface
```

=20

MS Virtual Disk

=20

    83bfb87f-43fb-4903-baa6-127f01029eec

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sys=
tem Attendant Service - Version 6.0
```

=20

MS Exchange

=20

    83d72bf0-0d89-11ce-b13f-00aa003bac6c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows File P=
rotection Service
```

=20

MS Security

=20

    83da7c00-e84f-11d2-9807-00c04f8ec850

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Adminis=
trative Interface - Network Policy Server (NPS) Protocol - IIASDataStoreCom=
Server Interface
```

=20

MS Remote Services

=20

    83e05bd5-aec1-4e58-ae50-e819c7296f67

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsUpdateAgentInfo Interface
```

=20

MS Update Agent

=20

    85713fa1-7796-4fa2-be3b-e2d6124dd373

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterLog Interface
```

=20

MS Failover Cluster

=20

    85923ca7-1b6b-4e83-a2e4-f5ba3bfbb8a3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDisk Interface
```

=20

MS ISTM iSCSI

=20

    866a78bc-a2fb-4ac4-94d5-db3041b4ed75

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Task Scheduler=
 Service Remote Protocol - ITaskSchedulerService
```

=20

MS Scheduler

=20

    86d35949-83c9-4044-b424-db363231fd0c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - IClientSink Interface
```

=20

MS Removable Storage

=20

    879c8bbe-41b0-11d1-be11-00c04fb6bf70

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - LSM Enumeration Interface
```

=20

MS Terminal Server

=20

    88143fd0-c28d-4b2b-8fef-8d882f6a9390

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolume Interface
```

=20

MS Virtual Disk

=20

    88306bb2-e71f-478c-86a2-79da200a0f11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISnapshot Interface
```

=20

MS ISTM iSCSI

=20

    883343f1-ceed-4e3a-8c1b-f0dadfce281e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Associates Brig=
htStor - Backup Agent RPC Server
```

=20

CA BrightStor

=20

    88435ee0-861a-11ce-b86b-00001b27f656

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterLog Interface
```

=20

MS Failover Cluster

=20

    88e7ac6d-c561-4f03-9a60-39dd768f867d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Shutdow=
n Protocol - InitShutdown Interface
```

=20

MS Remote Shutdown

=20

    894de0c0-0d55-11d3-a322-00c04fa321a1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsObjectManagement2 Interface
```

\<= /td\> =20

MS Removable Storage

=20

    895a2c86-270d-489d-a6c0-dc2a9b35280e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service - exchange_store_admin2 Interface
```

=20

MS Exchange

=20

    89742ace-a9ed-11cf-9c0c-08002be7ae86

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Fi=
le System Replication Protocol (DFS-R) - FrsTransport Interface
```

=20

MS File Replication

=20

    897e2e5f-93f3-4376-9c9c-fd2277495c27

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ILocalDeviceMgr Interface
```

=20

MS ISTM iSCSI

=20

    8ad608a4-6c16-4405-8879-b27910a68995

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaManager Interface
```

=20

MS File Server

=20

    8bb68c7d-19d8-4ffb-809e-be4fc1734014

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - CLSID_WbemLevel1Login
```

\<= /td\> =20

MS WMI

=20

    8bc3f05e-d86b-11d0-a075-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IKnownFolderManager Interface
```

=20

MS Explorer Browser

=20

    8be2d872-86aa-4d47-b776-32cca40c7018

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostPropertySchemaCollec=
tion Interface
```

=20

MS IIS

=20

    8bed2c68-a5fb-4b28-8581-a0dc5267419f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumVolume2 Interface
```

=20

MS ISTM iSCSI

=20

    8c58f6b3-4736-432a-891d-389de3505c7c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Application Ma=
nagement Service
```

=20

MS AMS

=20

    8c7daf44-b6dc-11d1-9a4c-0020af6e7c57

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - SMTP Service
```

=20

MS IIS

=20

    8cfb5d70-31a4-11cf-a7d8-00805f48a135

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Cryptographic =
Service
```

=20

MS Crypto

=20

    8d0ffe72-d252-11d0-bf8f-00c04fd9126b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISessionManager Interface
```

=20

MS ISTM iSCSI

=20

    8d7ae740-b9c5-49fc-a11e-89171907cb86

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Plug and Play =
Service - pnp Interface
```

=20

MS Plug and Play

=20

    8d9f4e40-a03d-11ce-8f69-08003e30051b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsSession1 Interface
```

=20

MS Removable Storage

=20

    8da03f40-3419-11d1-8fb1-00a024cb6019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IRegister In=
terface
```

=20

MS COM+ Remote Admin

=20

    8db2180e-bd29-11d1-8b7e-00c04fd7a924

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileGroup Interface
```

=20

MS File Server

=20

    8dd04909-0e34-4d55-afaa-89e1f1a1bbb9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Routing and Re=
mote Access Service (RRAS) Management Protocol - dimsvc Interface
```

=20

MS Remote Access

=20

    8f09f000-b7ed-11ce-bbd2-00001a181cad

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSearcher Interface
```

=20

MS Update Agent

=20

    8f45abf1-f9ae-4b95-a933-f0f66e5056ea

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDisk3 Interface
```

=20

MS Virtual Disk

=20

    8f4b2f5d-ec15-4357-992f-473ef10975b9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConfigManager
```

\<= /td\> =20

MS IIS

=20

    8f6d760f-f0cb-4d69-b5f6-848b33e9bdc6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft W32Time Remote=
 Protocol (MS-W32T) / Network Time Protocol Authentication Extensions (MS-S=
NTP) - W32Time Interface
```

=20

MS W32Time

=20

    8fb6d884-2388-11d0-8c35-00c04fda2795

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDiskOnline Interface
```

=20

MS Virtual Disk

=20

    90681b1d-6a7f-48e8-9061-31b7aa125322

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Tr=
ansaction Coordinator (DTC) - Connection Manager: OleTx Transports Protocol=
 - IXnRemote Operations
```

=20

MS DTC

=20

    906b0ce0-c70b-1067-b317-00dd010662da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSession3 Interface
```

=20

MS Update Agent

=20

    918efd1e-b5d8-4c90-8540-aeb9bdc56f9d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Certificate Se=
rvices - ICertPassage Remote Protocol - ICertPassage Interface
```

=20

MS Security

=20

    91ae6020-9e3c-11cf-8d7c-00aa00c091be

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateSession2 Interface
```

=20

MS Update Agent

=20

    91caf7b0-eb23-49ed-9937-c52d817f46f7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Security Confi=
guration Editor Service
```

=20

MS Security

=20

    93149ca2-973b-11d1-8c39-00c04fb984f9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Veritas Backup Exec Serv=
ice
```

=20

VR BKPSVC

=20

    93841fd0-16ce-11ce-850d-02608c44967b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service EMSMDBPOOL Interface
```

=20

MS Exchange

=20

    938fe036-ede6-4f6c-966e-a3d7300279c8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMPolicy Interface
```

=20

MS System Resource

=20

    943991a5-b3fe-41fa-9696-7f7b656ee34b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemServices Interface
```

=20

MS WMI

=20

    9556dc99-828c-11cf-a37e-00aa003240c7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft WinLogon - IRP=
CSCLogon
```

=20

MS Security

=20

    95958c94-a424-4055-b62b-b7f4d5c47770

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmCommittableCollection Interface
```

=20

MS File Server

=20

    96deb3b5-8b91-4a2a-9d93-80a35d8aa847

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IRegister2 I=
nterface
```

=20

MS COM+ Remote Admin

=20

    971668dc-c3fe-4ea1-9643-0c7230f494a1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Protocol - ITransactionStream Interface
```

=20

MS COM+

=20

    97199110-db2e-11d1-a251-0000f805ca53

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsAdvancedDisk2 Interface
```

=20

MS Virtual Disk

=20

    9723f420-9355-42de-ab66-e31bb15beeac

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Portmapper Ser=
vice
```

=20

MS Portmapper

=20

    975201b0-59ca-11d0-a8d5-00a0c90d8051

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - InetInfo Service - Version 2.0
```

=20

MS IIS

=20

    97f83d5c-1994-11d1-a90d-00c04fb960f8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IReplication=
Util Interface
```

=20

MS COM+ Remote Admin

=20

    98315903-7be5-11d2-adc1-00a02463d6e7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsCreatePartitionEx Interface
```

=20

MS Virtual Disk

=20

    9882f547-cfc3-420b-9750-00dfbec50662

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSystem2 Interface
```

\<= /td\> =20

MS COM+ Event System

=20

    99cc098f-a48a-4e9c-8e58-965c0afc19d5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service - exchange_store_admin3 Interface
```

=20

MS Exchange

=20

    99e64010-b032-11d0-97a4-00c04fd6551d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IOXIDResolver/IObjectExporter Interface
```

=

=20

MS DCOM Services

=20

    99fcfec4-5260-101b-bbcb-00aa0021347a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaTemplateImported Interface
```

=20

MS File Server

=20

    9a2bf113-a329-44cc-809a-5c00fce8da40

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemClassObject Interface
```

=20

MS WMI

=20

    9a653086-174f-11d2-b5f9-00104b703efd

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsSwProvider Interface
```

=20

MS Virtual Disk

=20

    9aa58360-ce33-4f92-b658-ed24b14425b8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateServiceCollection Interface
```

=20

MS Update Agent

=20

    9b0353aa-0e52-44ff-b8b0-1f7fa0437f88

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - Process Launcher
```

=20

MS DCOM Services

=20

    9b8699ae-0e44-47b1-8e7f-86a461d7ecdc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostAdminManager Interfa=
ce
```

=20

MS IIS

=20

    9be77978-73ed-4a9a-87fd-13f09fec1b13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsDiskPartitionMF2 Interface
```

=20

MS Virtual Disk

=20

    9cbe50ca-f2d2-4bf4-ace1-96896b729625

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Mes=
sage Transfer Agent (MTA) Service
```

=20

MS Exchange

=20

    9e8ee830-4459-11ce-979b-00aa005ffebe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Mai=
l Transfer Agent (MTA) exchange_mta Interface
```

=20

MS Exchange

=20

    9e8ee830-4559-11ce-979b-00aa005ffebe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft WinLogon - Get=
UserToken Service
```

=20

MS Security

=20

    a002b3a0-c9b7-11d1-ae88-0080c75e4ec1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Replicati=
on Service (FRS) - PerfFrs Interface
```

=20

MS File Replication

=20

    a00c021c-2be2-11d2-b678-0000f87a8f8e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSystemInitialize Interfa=
ce
```

=20

MS COM+ Event System

=20

    a0e8f27a-888c-11d1-b763-00c04fb926af

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmQuotaTemplate Interface
```

=20

MS File Server

=20

    a2efab31-295e-46bb-b976-e86d58b52e8b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemBackupRestoreEx : IWbem=
BackupRestore Interface
```

=20

MS WMI

=20

    a359dec5-e813-4834-8a2a-ba7f1d777d76

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Desktop=
 Protocol: Smart Card Virtual Channel Extension (MS-RDPESC) - type_scard_pa=
ck Interface
```

=20

MS Remote

=20

    a35af600-9cf4-11cd-a076-08002b2bd711

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateException Interface
```

=20

MS Update Agent

=20

    a376dd5e-09d4-427f-af7c-fed5b6e1c1d6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateExceptionCollection Interface
```

=20

MS Update Agent

=20

    a37d00f5-7bb0-4953-b414-f9e98326f2e8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service - exchange_store_admin1 Interface
```

=20

MS Exchange

=20

    a4f1db00-ca47-1067-b31e-00dd010662da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service EMSMDB Interface
```

=20

MS Exchange

=20

    a4f1db00-ca47-1067-b31f-00dd010662da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - InetInfo Service - Version 3.0
```

=20

MS IIS

=20

    a520d06e-11de-11d2-ab59-00c04fa3590c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumDisk2 Interface
```

=20

MS ISTM iSCSI

=20

    a5ecfc73-0013-4a9e-951c-59bf9735fdda

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterCleanup Interface
```

=20

MS Failover Cluster

=20

    a6d3e32b-9814-4409-8de3-cfa673e6d3de

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateHistoryEntryCollection Interface
```

=20

MS Update Agent

=20

    a7f04f3c-a290-435b-aadf-a116c3357a5c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTabl=
eInfo Interface
```

=20

MS COM+ Remote Admin

=20

    a8927a41-d3ce-11d1-8472-006008b0e5ca

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
mote VSS Protocol (MS-FSRVP) - FileServerVssAgent Interface
```

=20

MS File Server

=20

    a8e0653c-2744-4389-a61d-7373df8b2292

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Secur=
ity and Acceleration (ISA) - AD-LDS - ISASTGCTRL
```

=20

MS ISA

=20

    a9b96d49-2c75-4917-a178-06b6f08261cc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Inf=
ormation Store - Undocumented Interface 1
```

=20

MS Exchange

=20

    a9e05b20-6f57-4e24-a540-52412017e6ff

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - COM GUID/UUID Service - IADMCOMSINK Interface
```

=

=20

MS IIS

=20

    a9e69612-b80d-11d0-b9b9-00a0c922e750

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Domain Name Sy=
stem (DNS) Server
```

=20

MS DNS

=20

    aae9ac90-ce13-11cf-919e-08002be23c64

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISessionManager CLSID
```

=20

MS ISTM iSCSI

=20

    ad069971-edc5-4357-a132-430dad479d2b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileGroupImported Interface
```

=20

MS File Server

=20

    ad55f10b-5f11-4be7-94ef-d9ee2e470ded

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostConfigFile Interface=
```

=20

MS IIS

=20

    ada4e6fb-e025-401e-a5d0-c3134a281f07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Shadow Copy Ma=
nagement Protocol - IVssEnumObject Interface
```

=20

MS Volume Shadow Copy

=20

    ae1c7110-2f60-11d3-8a39-00c04f72d8e3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Print System A=
synchronous Notification Protocol (MS-PAN) - IRPCRemoteObject Interface
```

=20

MS Print

=20

    ae33069b-a2a8-46ee-a235-ddfd339be281

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Tr=
ansaction Coordinator (DTC) - Remote Management Interface
```

=20

MS DTC

=20

    afa8bd80-7d8a-11c9-bef4-08002b102989

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmClassificationRule Interface
```

=20

MS File Server

=20

    afc052c2-5315-45ab-841b-c6db0e120148

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Central Access=
 Policy Identifier (ID) - Retrieval Protocol (MS-CAPR) - lsacap Interface
```

=20

MS Security

=20

    afc07e2e-311c-4435-808c-c483ffeec7c9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHost Interface
```

=20

MS ISTM iSCSI

=20

    b0076fec-a921-4034-a8ba-090bc6d03bde

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsObjectManagement1 Interface
```

\<= /td\> =20

MS Removable Storage

=20

    b057dc50-3059-11d1-8faf-00a024cb6019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHostMgr Interface
```

=20

MS ISTM iSCSI

=20

    b06a64e3-814e-4ff9-afac-597ad32517c7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsIscsiInitiatorAdapter Interface
```

=20

MS Virtual Disk

=20

    b07fedd4-1682-4440-9189-a39b55194dc5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ILocalDeviceMgr2 Interface
```

=20

MS ISTM iSCSI

=20

    b0d1ac4b-f87a-49b2-938f-d439248575b2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IConnectionPointContainer Interface
```

=20

MS DCOM Services

=20

    b196b284-bab4-101a-b69c-00aa00341d07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IEnumConnectionPoints Interface
```

=20

MS DCOM Services

=20

    b196b285-bab4-101a-b69c-00aa00341d07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IConnectionPoint Interface
```

=20

MS DCOM Services

=20

    b196b286-bab4-101a-b69c-00aa00341d07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - IEnumConnections Interface (obsolete)
```

=20

MS DCOM Services

=20

    b196b287-bab4-101a-b69c-00aa00341d07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Secur=
ity and Acceleration (ISA) - Management Console (MMC)
```

=20

MS ISA

=20

    b347203c-14bb-4878-8b7a-0a12f9b8076a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdate Interface
```

=20

MS Update Agent

=20

    b383cd1a-5ce9-4504-9f63-764b1236f191

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Commerce Serve=
r Staging (CSS) - Replication Service
```

=20

MS CSS

=20

    b3df47c0-a95a-11cf-aa26-00aa00c148b9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Fun=
ction II
```

=20

MS Exchange

=20

    b4757e80-a0e4-46b4-876a-3ae4a548ee07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVdProvider
```

=20

MS Virtual Disk

=20

    b481498c-8354-45f9-84a0-0bdd2832a91f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHost2 Interface
```

=20

MS ISTM iSCSI

=20

    b4fa8e86-2517-4a88-bd67-75447219eee4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdatesSettings3 Interface
```

=20

MS Update Agent

=20

    b587f5c3-f57e-485f-bbf5-0d181c5cd0dc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Tracker Service Protocol - IGetTrackingData Interface<=
/pre>
```

=20

MS COM+ Tracker

=20

    b60040e0-bcf3-11d1-861d-0080c729264d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceUninstallDisk Interface
```

=20

MS Virtual Disk

=20

    b6b22da8-f903-4be7-b492-c09d875ac9da

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostSectionDefinitionCol=
lection Interface
```

=20

MS IIS

=20

    b7d381ee-8860-47a1-8af4-1f33b2b1f325

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostMethodInstance Inter=
face
```

=20

MS IIS

=20

    b80f3c42-60e0-4ae0-9007-f52852d3dbed

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Group Key Dist=
ribution Protocol (MS-GKDI) - ISDKey Interface
```

=20

MS Active Directory

=20

    b9785960-524f-11df-8b6d-83dcded72085

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Management API - ClusAPI Interface
```

=20

MS Failover Cluster

=20

    b97db8b2-4c63-11cf-bff6-08002be23f2f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Portmapper Ser=
vice - IROT Interface
```

=20

MS Portmapper

=20

    b9e79e60-3d52-11ce-aaa1-00006901293f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Top=
ology Information Server Interface
```

=20

MS Exchange

=20

    b9fadb8d-53a1-41d7-b763-88d884b6b829

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTGeneral CLSID
```

=20

MS ISTM iSCSI

=20

    baa4a577-202d-49c7-a6bb-10ee914ee199

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmClassifierModuleDefinition Interface
```

=20

MS File Server

=20

    bb36ea26-6318-4b8c-8592-f72dd602e7a5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsNotifySink Interface
```

=20

MS Removable Storage

=20

    bb39332c-bfee-4380-ad8a-badc8aff5bb6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumDisk Interface
```

=20

MS ISTM iSCSI

=20

    bb39e296-ad26-42c5-9890-5325333bb11e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Active Directo=
ry Technical Specification - Claims Interface
```

=20

MS Active Directory

=20

    bba9cb76-eb0c-462c-aa1b-5d8c34415701

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateDownloadContentCollection  Interface
```

=20

MS Update Agent

=20

    bc5513c8-b3b8-4bf7-a4d4-361c0d8c88ba

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMResourceGroup Interface
```

=20

MS System Resource

=20

    bc681469-9dd9-4bf4-9b3d-709f69efe431

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IIISCertObj Interface
```

=20

MS IIS

=20

    bd0c73bc-805b-4043-9c30-9a28d64dd7d2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Fun=
ction III
```

=20

MS Exchange

=20

    bd5790c9-d855-42b0-990f-3dfed8c184b3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Terminal Serve=
r Services - Runtime Interface - TermSrv Interface
```

=20

MS Terminal Server

=20

    bde95fdf-eee0-45de-9e12-e5a61cd0d4fe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateHistoryEntry Interface
```

=20

MS Update Agent

=20

    be56a644-af0e-4e0e-a311-c1d8e695cbff

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQManagement Interface
```

=20

MS Message Queuing

=20

    be5f0241-e489-4957-8cc4-a452fcf3e23e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenException Interface
```

=20

MS File Server

=20

    bee7ce02-df77-4515-9389-78f01c5afc1a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Inf=
ormation Store - Undocumented Interface 2
```

=20

MS Exchange

=20

    bf6dd426-77b4-44b3-984e-d413fc075562

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Admin Service
```

=20

MS IIS

=20

    bfa951d1-2f0e-11d3-bfd1-00c04fa3490a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ISessionManager2 Interface
```

=20

MS ISTM iSCSI

=20

    c10a76d8-1fe4-4c2f-b70d-665265215259

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdate5 Interface
```

=20

MS Update Agent

=20

    c1c2f21a-d2f4-4902-b5c6-8a081c19a890

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IImport Inte=
rface
```

=20

MS COM+ Remote Admin

=20

    c2be6970-df9e-11d1-8b87-00c04fd7a924

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateHistoryEntry2 Interface
```

=20

MS Update Agent

=20

    c2bfb780-4539-4132-ab8c-0a8772013ab6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Adminis=
trative Interface - Network Policy Server (NPS) Protocol - IIASDataStoreCom=
Server2 Interface
```

=20

MS Remote Services

=20

    c323be28-e546-4c23-a81b-d6ad8d8fac7b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Audio =
Service - Audio Remote Procedure Call (RPC)
```

=20

MS Audio

=20

    c386ca3e-9061-4a72-821e-498d83be188f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft IManagedObject=
 Interface Protocol - IManagedObject : IUnknown Interface
```

=20

MS IManagedObject

=20

    c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - CLSID_WbemBackupRestore
```

=20

MS WMI

=20

    c49e32c6-bc8b-11d2-85d4-00105a1f8304

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemBackupRestoreEx Interfa=
ce
```

=20

MS WMI

=20

    c49e32c7-bc8b-11d2-85d4-00105a1f8304

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DFS Replicatio=
n Helper Protocol - IADProxy2 Interface
```

=20

MS DFS Replication

=20

    c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostSectionDefinition In=
terface
```

=20

MS IIS

=20

    c5c04795-321c-4014-8fd6-d44658799393

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IResourceManager Interface
```

=20

MS System Resource

=20

    c5cebee2-9df5-4cdd-a08c-c2471bc144b4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Encrypting Fil=
e System Remote (EFSR) Protocol - lsarpc Interface
```

=20

MS Security

=20

    c681d488-d850-11d0-8c52-00c04fd90f7e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Portmapper Ser=
vice - IMachineActivatorControl Interface
```

=20

MS Portmapper

=20

    c6f3ee72-ce7e-11d1-b71e-00c04fc3111a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogUtil=
s2 interface
```

=20

MS COM+ Remote Admin

=20

    c726744e-5735-4f08-8286-c510ee638fb6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterStorage2 Interface
```

=20

MS Failover Cluster

=20

    c72b09db-4d53-4f41-8dcc-2d752ab56f7c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - exc=
hange_unknown Interface
```

=20

MS Exchange

=20

    c840a7dc-42c0-1a10-b4b9-08002b2fe182

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostElementCollection
```

=20

MS IIS

=20

    c8550bff-5281-4b1e-ac34-99b6fa38464d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - ICommDlgBrowser3 Interface
```

=20

MS Explorer Browser

=20

    c8ad25a1-3294-41ee-8165-71174bd01c57

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Web Distribute=
d Authoring and Versioning (WebDAV) Client Service - davclntrpc Interface
```

=20

MS WDAV

=20

    c8cb7687-e6d3-11d2-a958-00c04f682e16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Protected Stor=
age Service - IPStoreProv
```

=20

MS Storage

=20

    c9378ff1-16f7-11d0-a0b2-00aa0061426a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateDownloadContent2 Interface
```

=20

MS Update Agent

=20

    c97ad11b-f257-420b-9d9f-377f733f6f68

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmRule Interface
```

=20

MS File Server

=20

    cb0df960-16f5-4495-9079-3f9360d831df

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Service Witnes=
s Protocol - Witness Interface
```

=20

MS Witness

=20

    ccd8c074-d0e5-4a40-92b4-d074faa6ba28

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IFolderView Interface
```

=20

MS Explorer Browser

=20

    cde725b0-ccc9-4519-917e-325d72fab4ce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IExport Inte=
rface
```

=20

MS COM+ Remote Admin

=20

    cfadac84-e12c-11d1-b34c-00c04f990d54

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenTemplateManager Interface
```

=20

MS File Server

=20

    cfe36cba-1949-4e74-a14f-f1d580ceaf13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsMediaServices1 Interface
```

=20

MS Removable Storage

=20

    d02e4be0-3419-11d1-8fb1-00a024cb6019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Replicati=
on Service (FRS) - NtFrsApi Interface
```

=20

MS File Replication

=20

    d049b186-814f-11d1-9a3c-00c04fc9b232

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IVolumeClient Interface
```

=20

MS Disk Management

=20

    d2d79df5-3400-11d0-b40b-00aa005ff586

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IDMNotify Interface
```

=20

MS Disk Management

=20

    d2d79df7-3400-11d0-b40b-00aa005ff586

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmClassificationManager Interface
```

=20

MS File Server

=20

    d2dc89da-ee91-48a0-85d8-cc72a56f7d04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft IPSEC Policy A=
gent
```

=20

MS Security

=20

    d335b8f6-cb31-11d0-b0f9-006097ba4e54

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Procedu=
re Call (RPC) Locator Service - NsiC
```

=20

MS Locator

=20

    d3fbb514-0e3b-11cb-8fad-08002b1d29c3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - ISearchResult
```

=20

MS Update Agent

=20

    d40cff62-e08c-4498-941a-01e25f0fd33c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemLoginClientID Interface=
```

=20

MS WMI

=20

    d4781cd6-e5d3-44df-ad94-930efe48a887

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsAsync Interface
```

=20

MS Virtual Disk

=20

    d5d23b6d-5a55-4492-9889-397a3c2d2dbc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterCleanup Interface
```

=20

MS Failover Cluster

=20

    d6105110-8917-41a5-aa32-8e0aa2933dc9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - Removable Storage Manager Class
```

=20

MS Removable Storage

=20

    d61a27c6-8f53-11d0-bfa0-00a024151983

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmActionEmail Interface
```

=20

MS File Server

=20

    d646567d-26ae-4caa-9f84-4e0aad207fca

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Conne=
ction Firewall
```

=20

MS ICFW

=20

    d674a233-5829-49dd-90f0-60cf9ceb7129

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumeShrink Interface
```

=20

MS Virtual Disk

=20

    d68168c9-82a2-4f85-b6e9-74707c49a58f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTDiskMgr3 Interface
```

=20

MS ISTM iSCSI

=20

    d6bd6d63-e8cb-4905-ab34-8a278c93197a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostMethodCollection Int=
erface
```

=20

MS IIS

=20

    d6c7cd8f-bb8d-4f96-b591-d3a5f1320269

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Procedu=
re Call (RPC) Locator Service - NsiS
```

=20

MS Locator

=20

    d6d70ef0-0e3b-11cb-acc3-08002b1d29c3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Procedu=
re Call (RPC) Locator Service - NsiM
```

=20

MS Locator

=20

    d6d70ef0-0e3b-11cb-acc3-08002b1d29c4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IWTGeneral Interface
```

=20

MS ISTM iSCSI

=20

    d71b2cae-33e8-4567-ae96-3ccf31620be2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQPrivateEvent Interface
```

=20

MS Message Queuing

=20

    d7ab3341-c9d3-11d1-bb47-0080c7c5a2c0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQuery Interface
```

=20

MS Message Queuing

=20

    d7d6e072-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQQuery
```

=20

MS Message Queuing

=20

    d7d6e073-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQMessage Interface
```

=20

MS Message Queuing

=20

    d7d6e074-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQMessage
```

=20

MS Message Queuing

=20

    d7d6e075-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueue Interface
```

=20

MS Message Queuing

=20

    d7d6e076-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQEvent Interface
```

=20

MS Message Queuing

=20

    d7d6e077-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - DMSMQEventEvents Interface
```

=20

MS Message Queuing

=20

    d7d6e078-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQQueue
```

=20

MS Message Queuing

=20

    d7d6e079-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQEvent
```

=20

MS Message Queuing

=20

    d7d6e07a-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfo Interface
```

=20

MS Message Queuing

=20

    d7d6e07b-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQQueueInfo
```

=20

MS Message Queuing

=20

    d7d6e07c-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfos Interface
```

=20

MS Message Queuing

=20

    d7d6e07d-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQQueueInfos
```

=20

MS Message Queuing

=20

    d7d6e07e-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransaction Interface
```

=20

MS Message Queuing

=20

    d7d6e07f-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQTransaction Interface
```

=20

MS Message Queuing

=20

    d7d6e080-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQCoordinatedTransactionDispenser Interface
```

=20

MS Message Queuing

=20

    d7d6e081-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQCoordinatedTransactionDispenser
```

=20

MS Message Queuing

=20

    d7d6e082-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransactionDispenser Interface
```

=20

MS Message Queuing

=20

    d7d6e083-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQTransactionDispenser
```

=20

MS Message Queuing

=20

    d7d6e084-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQApplication Interface
```

=20

MS Message Queuing

=20

    d7d6e085-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQApplication
```

=20

MS Message Queuing

=20

    d7d6e086-dccd-11d0-aa4b-0060970debae

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Domain Name Sy=
stem (DNS) Server - Interface version 5.0
```

=20

MS DNS

=20

    d7f9e1c0-2247-11d1-ba89-00c04fd91268

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmReport Interface
```

=20

MS File Server

=20

    d8cc81d9-46b8-4fa4-bfa5-4aa9dec9b638

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Shutdow=
n Protocol - WindowsShutdown Interface
```

=20

MS Remote Shutdown

=20

    d95afe70-a6d5-4259-822e-2c84da1ddb0d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQMessage2 Interface
```

=20

MS Message Queuing

=20

    d9933be0-a567-11d2-b0f3-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsHwProvider Interface
```

=20

MS Virtual Disk

=20

    d99bdaae-b13a-4178-9fdb-e27f16b4603e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Client=
 Certificate Enrollment Protocol (MS-WCCE) - ICertRequestD - Interface
```

=20

MS Security

=20

    d99e6e70-fc88-11d0-b498-00a0c90312f3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Certificate Se=
rvices Remote Administration Protocol - ICertAdminD Interface
```

=20

MS Security

=20

    d99e6e71-fc88-11d0-b498-00a0c90312f3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IInstallationBehavior Interface
```

=20

MS Update Agent

=20

    d9a59339-e245-4dbd-9686-4d5763e39624

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Sto=
re Service - Admin Interface
```

=20

MS Exchange

=20

    da107c01-2b50-44d7-9d5f-bfd4fd8e95ed

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Performance Co=
unter Query Protocol (MS-PCQ) - PerflibV2 Interface
```

=20

MS Performance

=20

    da5a86c5-12c2-4943-ab30-7f74a813d853

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Removable Stor=
age Manager (RSM) Remote Protocol - INtmsLibraryControl2 Interface
```

=20

MS Removable Storage

=20

    db90832f-6910-4d46-9f5e-9fd6bfa73903

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemClassObject : Iunknown =
Interface
```

=20

MS WMI

=20

    dc12a681-737f-11cf-884d-00aa004b2e24

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Associates Brig=
htStor - Message Engine [Vulnerability 2]
```

=20

CA BrightStor

=20

    dc246bf0-7a7a-11ce-9f88-00805fe43838

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHostMgr2 Interface
```

=20

MS ISTM iSCSI

=20

    dd6f0a28-248f-4dd3-afe9-71aed8f685c4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IUpdateServiceRegistration Interface
```

=20

MS Update Agent

=20

    dde02280-12b3-4e0b-937b-6747f6acb286

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostCollectionSchema Int=
erface
```

=20

MS IIS

=20

    de095db1-5368-4d11-81f6-efef619b7bcf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Disk Managemen=
t Remote Protocol - IVolumeClient4 Interface
```

=20

MS Disk Management

=20

    deb01010-3a37-4d26-99df-e2bb6ae3ac61

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Encrypting Fil=
e System Remote (EFSR) Protocol - efsrpc Interface
```

=20

MS Security

=20

    df1941c5-fe89-4e79-bf10-463657acf44d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IExplorerBrowser Interface
```

=20

MS Explorer Browser

=20

    dfd3b6b5-c10c-4be9-85f6-a66969f402f6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceLoader Interface
```

=20

MS Virtual Disk

=20

    e0393303-90d4-4a97-ab71-e9b671ee2729

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Explorer - Bro=
wser - IExplorerPaneVisibility Interface
```

=20

MS Explorer Browser

=20

    e07010ec-bc17-44c0-97b0-46c7c95b9edc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenTemplateImported Interface
```

=20

MS File Server

=20

    e1010359-3e5d-4ecd-9fe4-ef48622fdf30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumHost Interface
```

=20

MS ISTM iSCSI

=20

    e141fd54-b79e-4938-a6bb-d523c3d49ff1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHostMgr CLSID
```

=20

MS ISTM iSCSI

=20

    e14efe0b-fd3b-41ea-8e3b-88930445b944

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - ClusterNetwork2 Interface
```

=20

MS Failover Cluster

=20

    e1568352-586d-43e4-933f-8e6dc4de317a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - Endpoint Mapper Service (EPM)
```

=20

MS DCOM Services

=20

    e1af8308-5d1f-11c9-91a4-08002b14a0fa

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumSnsServer Interface
```

=20

MS ISTM iSCSI

=20

    e2842c88-07c3-4eb0-b1a9-d3d95e76fef2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Procedu=
re Call Location Services Extensions (MS-RPCL) - Deprecated - LocToLoc Inte=
rface
```

=20

MS Locator

=20

    e33c0cc4-0482-101a-bc0c-02608c6ba218

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Directory Repl=
ication Service (DRS) Remote Protocol - DRSUAPI Methods
```

=20

MS Active Directory

=20

    e3514235-4b06-11d1-ab04-00c04fc2dcd2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterUpdate Interface
```

=20

MS Failover Cluster

=20

    e3c9b851-c442-432b-8fc6-a7faafc09d3b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Background Int=
elligent Transfer Service (BITS) - Peer Authentication Protocol - BitsPeerA=
uth Interface
```

=20

MS BITS

=20

    e3d0d746-d2af-40fd-8a7a-0d7078bb7092

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Distributed Co=
mponent Object Model (DCOM) - ILocalObjectExporter Interface
```

=20

MS DCOM Services

=20

    e60c73e6-88f9-11cf-9af1-0020af6e72f4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ILocalDeviceMgr3 Interface
```

=20

MS ISTM iSCSI

=20

    e645744b-cae5-4712-acaf-13057f7195af

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft DFS Replicatio=
n Helper Protocol - IServerHealthReport Interface
```

=20

MS DFS Replication

=20

    e65e8028-83e8-491b-9af7-aaf6bd51a0ce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Client Service=
 for NetWare - NWWKS
```

=20

MS Network

=20

    e67ab081-9844-3521-9d32-834f038001c0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostPathMapper Interface=
```

=20

MS IIS

=20

    e7927575-5cc3-403b-822e-328a6b904bee

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IAutomaticUpdatesResults Interface
```

=20

MS Update Agent

=20

    e7a4d634-7942-4dd9-a111-82228ba33901

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - ResourceManager Class
```

=20

MS System Resource

=20

    e8bcffac-b864-4574-b2e8-f1fb21dfdc18

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - ServiceControl
```

=20

MS IIS

=20

    e8fb8620-588f-11d2-9d61-00c04f79c5fe

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPropertyDefinitionValue Interface
```

=20

MS File Server

=20

    e946d148-bd67-4178-8e22-1c44925ed710

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft SHAREDFAX Fax =
Server and FaxObs Server Interfaces
```

=20

MS Fax

=20

    ea0a3165-4834-11d2-a6f8-00c04fa346cc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostPropertyException In=
terface
```

=20

MS IIS

=20

    eafe4895-a929-41ea-b14d-613e23f62b71

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQuery2 Interface
```

=20

MS Message Queuing

=20

    eba96b0e-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfos2 Interface
```

=20

MS Message Queuing

=20

    eba96b0f-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQCoordinatedTransactionDispenser2 Interface
```

\<= /td\> =20

MS Message Queuing

=20

    eba96b10-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransactionDispenser2 Interface
```

=20

MS Message Queuing

=20

    eba96b11-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQEvent2 Interface
```

=20

MS Message Queuing

=20

    eba96b12-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransaction3 Interface
```

=20

MS Message Queuing

=20

    eba96b13-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQCoordinatedTransactionDispenser3 Interface
```

\<= /td\> =20

MS Message Queuing

=20

    eba96b14-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQTransactionDispenser3 Interface
```

=20

MS Message Queuing

=20

    eba96b15-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQDestination Interface
```

=20

MS Message Queuing

=20

    eba96b16-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQPrivateDestination Interface
```

=20

MS Message Queuing

=20

    eba96b17-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQDestination
```

=20

MS Message Queuing

=20

    eba96b18-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQuery3 Interface
```

=20

MS Message Queuing

=20

    eba96b19-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQMessage3 Interface
```

=20

MS Message Queuing

=20

    eba96b1a-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueue3 Interface
```

=20

MS Message Queuing

=20

    eba96b1b-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQEvent3 Interface
```

=20

MS Message Queuing

=20

    eba96b1c-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfo3 Interface
```

=20

MS Message Queuing

=20

    eba96b1d-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfos3 Interface
```

=20

MS Message Queuing

=20

    eba96b1e-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQApplication3 Interface
```

=20

MS Message Queuing

=20

    eba96b1f-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueue4 Interface
```

=20

MS Message Queuing

=20

    eba96b20-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfo4 Interface
```

=20

MS Message Queuing

=20

    eba96b21-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfos4 Interface
```

=20

MS Message Queuing

=20

    eba96b22-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQMessage4 Interface
```

=20

MS Message Queuing

=20

    eba96b23-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQuery4 Interface
```

=20

MS Message Queuing

=20

    eba96b24-2168-11d3-898c-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Active Directo=
ry Backup and Restore Services - JetBack Interface
```

=20

MS Active Directory

=20

    ecec0d70-a603-11d0-96b1-00a0c91ece30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostProperty Interface
```

=20

MS IIS

=20

    ed35f7a1-5024-4e7b-a44d-07ddaf4b524d

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IWindowsDriverUpdateEntry Interface
```

=20

MS Update Agent

=20

    ed8bfe40-a60b-42ea-9652-817dfcfa23ec

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmPropertyDefinition Interface
```

=20

MS File Server

=20

    ede0150f-e9a3-419c-877c-01fe5d24c5d3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsVolumeMF Interface
```

=20

MS Virtual Disk

=20

    ee2d5ded-6236-4169-931d-b9778ce03dc6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileManagementJobManager Interface
```

=20

MS File Server

=20

    ee321ecb-d95e-48e9-907c-c7685a013235

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueue2 Interface
```

=20

MS Message Queuing

=20

    ef0574e0-06d8-11d3-b100-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostElementSchema Interf=
ace
```

=20

MS IIS

=20

    ef13d885-642c-4709-99ec-b89561c6bc69

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Update Agent M=
anagement Protocol - IStringCollection Interface
```

=20

MS Update Agent

=20

    eff90582-2ddc-480f-a06d-60f3fbc362c3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IEnumCachedInitiator Interface
```

=20

MS ISTM iSCSI

=20

    f093fe3d-8131-4b73-a742-ef54c20b337b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Remote Assista=
nce Initiation Protocol - IRASrv Interface
```

=20

MS Remote Assistance

=20

    f120a684-b926-447f-9df4-c966cb785648

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Remote Administration Protocol Protocol - IExport2 Int=
erface
```

=20

MS COM+ Remote Admin

=20

    f131ea3e-b7be-480e-a60d-51cb2785779e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - ILocalDeviceMgr CLSID
```

=20

MS ISTM iSCSI

=20

    f1d3a46c-2e1b-4d84-97da-b3742ad67871

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Failover Clust=
er: Setup and Validation Protocol - IClusterFirewall Interface
```

=20

MS Failover Cluster

=20

    f1d6c29c-8fbe-4691-8724-f6d8deaeafc8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemRemoteRefresher Interfa=
ce
```

=20

MS WMI

=20

    f1e9c5b2-f59b-11d2-b362-00105a1f8177

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Und=
ocumented Interface 5
```

=20

MS Exchange

=20

    f1f21151-7185-4170-ac8d-9bb077c29bd3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Und=
ocumented Interface 3
```

=20

MS Exchange

=20

    f224209f-9076-40f7-98ad-5416dbfa178e

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows Manage=
ment Instrumentation (WMI) - Remote Protocol - IWbemLevel1Login Interface
```

=20

MS WMI

=20

    f309ad18-d86a-11d0-a075-00c04fb68820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMProtocol Interface
```

=20

MS System Resource

=20

    f31931a9-832d-481c-9503-887a0e6a79f0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenBase Interface
```

=20

MS File Server

=20

    f3637e80-5b22-4a2b-a637-bbb642b41cfc

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmSetting Interface
```

=20

MS File Server

=20

    f411d4fd-14be-4260-8c40-03b7c95e608a

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEnumEventObject Interface Int=
erface
```

=20

MS COM+ Event System

=20

    f4a07d63-2e25-11d1-9964-00c04fbbb345

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Cryptographic =
Services - ICatDBSvc
```

=20

MS Crypto

=20

    f50aac00-c7f3-428e-a022-a6b71bfb9d43

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Replicati=
on Service (FRS) - exchange_drs - frsrpc Interface
```

=20

MS File Replication

=20

    f5cc59b4-4264-101a-8c59-08002b2f8426

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange Name =
Service Provider Interface (NSPI) Proxy - exchange_nsp Interface
```

=20

MS Exchange

=20

    f5cc5a18-4264-101a-8c59-08002b2f8426

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Act=
ive Directory Extended Directory Service (XDS) - exchange_xds Interface
```

=20

MS Exchange

=20

    f5cc5a7c-4264-101a-8c59-08002b2f8426

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - IMSAdminBaseW - IMSAdminBase3W Interface
```

=20

MS IIS

=20

    f612954d-3b0b-4c56-9563-227b7be624b4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft EventLog Remot=
ing Protocol Version 6.0 - IEventService Interface
```

=20

MS Event

=20

    f6beaff7-1e19-4fbb-9f8f-b89e2018337c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - MSMQCollection
```

=20

MS Message Queuing

=20

    f72b9031-2f0c-43e8-924e-e6052cdc493f

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmCollection Interface
```

=20

MS File Server

=20

    f76fbf3b-8ddd-4b42-b05a-cb1c3ff1fee8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmAutoApplyQuota Interface
```

=20

MS File Server

=20

    f82e5729-6aba-4740-bfc7-c7f58f75fb7b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventObjectCollection Interfa=
ce
```

=20

MS COM+ Event System

=20

    f89ac270-d4eb-11d1-b682-00805fc79216

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Exchange - Exc=
hange System Attendant Cluster Interface (exchange_sysatt_cluster)
```

=20

MS Exchange

=20

    f930c514-1215-11d3-99a5-00a0c9b61b04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Internet Infor=
mation Services (IIS) - Application Host COM - IAppHostWritableAdminManager=
 Interface
```

=20

MS IIS

=20

    fa7660f6-7b3f-4237-a8bf-ed0ad0dcbbd9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Shadow Copy Ma=
nagement Protocol - IVssSnapshotMgmt Interface
```

=20

MS Volume Shadow Copy

=20

    fa7df749-66e7-4986-a27f-e2f04ae53772

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventClass Interface
```

=20

MS COM+ Event System

=20

    fb2b72a0-7a68-11d1-88f9-0080c7d771bf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventClass2 Interface
```

=20

MS COM+ Event System

=20

    fb2b72a1-7a68-11d1-88f9-0080c7d771bf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Component Obje=
ct Model Plus (COM+) Event System Protocol - IEventSubscription3 Interface<=
/pre>
```

=20

MS COM+ Event System

=20

    fbc1d17d-c498-43a0-81af-423ddd530af6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Management Service
```

=20

MS Message Queuing

=20

    fc13257d-5567-4dea-898d-c6f9c48415a0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Virtual Disk S=
ervice (VDS) Protocol - IVdsServiceSAN Interface
```

=20

MS Virtual Disk

=20

    fc5d23e8-a88b-41a5-8de0-2d2f73c5a630

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Windows System=
 Resource Manager (WSRM) Protocol - IWRMRemoteSessionMgmt Interface
```

=20

MS System Resource

=20

    fc910418-55ca-45ef-b264-83d4ce7d30e0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - ActiveX Client - IMSMQQueueInfo2 Interface
```

=20

MS Message Queuing

=20

    fd174a80-89cf-11d2-b0f2-00e02c074f6b

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Message Queuin=
g - Queue Manager Client Protocol - qmcomm Interface
```

=20

MS Message Queuing

=20

    fdb3a030-065f-11d1-bb9b-00a024ea5525

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Trusted Platfo=
rm Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardMana=
ger2 Interface
```

=20

MS TPM Smart Card Mgt

=20

    fdf8a2b9-02de-47f4-bc26-aa85ab5e5267

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft iSCSI Software=
 Target Management Protocol - IHost3 Interface
```

=20

MS ISTM iSCSI

=20

    fe7f99f9-1dfb-4afb-9d00-6a8dd0aabf2c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Telnet Server =
Remote Administration Protocol (MS-TSRAP) - CLSID_EnumTelnetClientsSvr Inte=
rface
```

=20

MS Telnet Server

=20

    fe9e48a4-a014-11d1-855c-00a0c944138c

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft File Server Re=
source Manager Protocol - IFsrmFileScreenManager Interface
```

=20

MS File Server

=20

    ff4fa04e-5a94-4bda-a3a0-d5b4d3c52eba

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20

### Type [dnsclass](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"dnsclass-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IN
```

=20

    1 - 0x1

=20

Internet

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CS
```

=20

    2 - 0x2

=20

CSNET class (Obsolete - used only for examples)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CH
```

=20

    3 - 0x3

=20

CHAOS class

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HS
```

=20

    4 - 0x4

=20

Hesiod

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [dnscode](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"dnscode-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No DNS Response
```

=20

    -1 - 0x-1

=20

No DNS Response

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NoError
```

=20

    0 - 0x0

=20

No Error

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FormErr
```

=20

    1 - 0x1

=20

Format Error

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ServFail
```

=20

    2 - 0x2

=20

Server Failure

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NXDomain
```

=20

    3 - 0x3

=20

Non-Existent Domain

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NotImp
```

=20

    4 - 0x4

=20

Not Implemented

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Refused
```

=20

    5 - 0x5

=20

Query Refused

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
YXDomain
```

=20

    6 - 0x6

=20

Name Exists when it should not

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
YXRRSet
```

=20

    7 - 0x7

=20

RR Set Exists when it should not

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NXRRSet
```

=20

    8 - 0x8

=20

RR Set that should exist does not

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NotAuth
```

=20

    9 - 0x9

=20

Server Not Authoritative for zone

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NotZone
```

=20

    10 - 0xA

=20

Name not contained in zone

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadSig/BadVers
```

=20

    16 - 0x10

=20

TSIG Signature Failure OR Bad OPT version

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadKey
```

=20

    17 - 0x11

=20

Key not recognized

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadTime
```

=20

    18 - 0x12

=20

Signature out of time window

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadMode
```

=20

    19 - 0x13

=20

Bad TKEY Mode

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadName
```

=20

    20 - 0x14

=20

Duplicate key name

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadAlg
```

=20

    21 - 0x15

=20

Algorithm not supported

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BadTrunc
```

=20

    22 - 0x16

=20

Bad Truncation

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [dnstype](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"dnstype-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RESERVED
```

=20

    0 - 0x0

=20

reserved type, sometimes mistakenly used by Microsoft protoco= ls

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
A
```

=20

    1 - 0x1

=20

a host address

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NS
```

=20

    2 - 0x2

=20

an authoritative name server

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MD
```

=20

    3 - 0x3

=20

a mail destination (Obsolete - use MX)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MF
```

=20

    4 - 0x4

=20

a mail forwarder (Obsolete - use MX)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CNAME
```

=20

    5 - 0x5

=20

the canonical name for an alias

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SOA
```

=20

    6 - 0x6

=20

marks the start of a zone of authority

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MB
```

=20

    7 - 0x7

=20

a mailbox domain name (EXPERIMENTAL)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MG
```

=20

    8 - 0x8

=20

a mail group member (EXPERIMENTAL)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MR
```

=20

    9 - 0x9

=20

a mail rename domain name (EXPERIMENTAL)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NULL
```

=20

    10 - 0xA

=20

a null RR (EXPERIMENTAL)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
WKS
```

=20

    11 - 0xB

=20

a well known service description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PTR
```

=20

    12 - 0xC

=20

a domain name pointer

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HINFO
```

=20

    13 - 0xD

=20

host information

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MINFO
```

=20

    14 - 0xE

=20

mailbox or mail list information

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MX
```

=20

    15 - 0xF

=20

mail exchange

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TXT
```

=20

    16 - 0x10

=20

text strings

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RP
```

=20

    17 - 0x11

=20

for Responsible Person

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AFSDB
```

=20

    18 - 0x12

=20

for AFS Data Base location

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
X25
```

=20

    19 - 0x13

=20

for X.25 PSDN address

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISDN
```

=20

    20 - 0x14

=20

for ISDN address

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RT
```

=20

    21 - 0x15

=20

for Route Through

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NSAP
```

=20

    22 - 0x16

=20

for NSAP address, NSAP style A record

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NSAP-PTR
```

=20

    23 - 0x17

=20

for domain name pointer, NSAP style

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SIG
```

=20

    24 - 0x18

=20

for security signature

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KEY
```

=20

    25 - 0x19

=20

for security key

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PX
```

=20

    26 - 0x1A

=20

X.400 mail mapping information

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GPOS
```

=20

    27 - 0x1B

=20

Geographical Position

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AAAA
```

=20

    28 - 0x1C

=20

a IP6 host address

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
LOC
```

=20

    29 - 0x1D

=20

Location Information

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NXT
```

=20

    30 - 0x1E

=20

Next Domain - OBSOLETE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EID
```

=20

    31 - 0x1F

=20

Endpoint Identifier

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NIMLOC/NB
```

=20

    32 - 0x20

=20

Nimrod Locator OR Netbios

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SRV/NBSTAT
```

=20

    33 - 0x21

=20

Server Selection OR Netbios Stats

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ATMA
```

=20

    34 - 0x22

=20

ATM Address

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NAPTR
```

=20

    35 - 0x23

=20

Naming Authority Pointer

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KX
```

=20

    36 - 0x24

=20

Key Exchanger

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CERT
```

=20

    37 - 0x25

=20

CERT

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
A6
```

=20

    38 - 0x26

=20

A6 (Experimental)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DNAME
```

=20

    39 - 0x27

=20

DNAME

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SINK
```

=20

    40 - 0x28

=20

SINK

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OPT
```

=20

    41 - 0x29

=20

OPT

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
APL
```

=20

    42 - 0x2A

=20

APL

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DS
```

=20

    43 - 0x2B

=20

Delegation Signer

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SSHFP
```

=20

    44 - 0x2C

=20

SSH Key Fingerprint

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPSECKEY
```

=20

    45 - 0x2D

=20

IPSECKEY

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RRSIG
```

=20

    46 - 0x2E

=20

RRSIG

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NSEC
```

=20

    47 - 0x2F

=20

NSEC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DNSKEY
```

=20

    48 - 0x30

=20

DNSKEY

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DHCID
```

=20

    49 - 0x31

=20

DHCID

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NSEC3
```

=20

    50 - 0x32

=20

NSEC3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NSEC3PARAM
```

=20

    51 - 0x33

=20

NSEC3PARAM

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HIP
```

=20

    55 - 0x37

=20

Host Identity Protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NINFO
```

=20

    56 - 0x38

=20

NINFO

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RKEY
```

=20

    57 - 0x39

=20

RKEY

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TALINK
```

=20

    58 - 0x3A

=20

Trust Anchor LINK

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CDS
```

=20

    59 - 0x3B

=20

Child DS

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SPF
```

=20

    99 - 0x63

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
UINFO
```

=20

    100 - 0x64

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
UID
```

=20

    101 - 0x65

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GID
```

=20

    102 - 0x66

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
UNSPEC
```

=20

    103 - 0x67

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TKEY
```

=20

    249 - 0xF9

=20

Transaction Key

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TSIG
```

=20

    250 - 0xFA

=20

Transaction Signature

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IXFR
```

=20

    251 - 0xFB

=20

incremental transfer

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AXFR
```

=20

    252 - 0xFC

=20

transfer of an entire zone

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MAILB
```

=20

    253 - 0xFD

=20

mailbox-related RRs (MB, MG or MR)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MAILA
```

=20

    254 - 0xFE

=20

mail agent RRs (Obsolete - see MX)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
*
```

=20

    255 - 0xFF

=20

A request for all records

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
URI
```

=20

    256 - 0x100

=20

URI

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CAA
```

=20

    257 - 0x101

=20

Certification Authority Authorization

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TA
```

=20

    32768 - 0x8000

=20

DNSSEC Trust Authorities

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DLV
```

=20

    32769 - 0x8001

=20

DNSSEC Lookaside Validation

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [encryption](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"encryption-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Off
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Off stream
```

=20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Basic
```

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Basic stream
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Rc5
```

=20

    4 - 0x4

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [ethernetprotocol](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"ethernetprotocol-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XEROX PUP
```

=20

    512 - 0x200

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PUP Addr Trans
```

=20

    513 - 0x201

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nixdorf (conflicts with =
802.3 Length Field)
```

=20

    1024 - 0x400

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet II
```

=20

    1528 - 0x5F8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XEROX NS IDP
```

=20

    1536 - 0x600

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XNS Address Translation<=
/pre>
```

=20

    1537 - 0x601

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DLog
```

=20

    1632 - 0x660

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DLog
```

=20

    1633 - 0x661

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv4
```

=20

    2048 - 0x800

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Valid Systems
```

=20

    2049 - 0x801

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NBS Internet
```

=20

    2050 - 0x802

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ECMA Internet
```

=20

    2051 - 0x803

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Chaosnet
```

=20

    2052 - 0x804

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
X.25 Level 3
```

=20

    2053 - 0x805

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ARP
```

=20

    2054 - 0x806

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XNS Compatability
```

\<= /td\> =20

    2055 - 0x807

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Frame Relay ARP
```

=20

    2056 - 0x808

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Symbolics Private
```

\<= /td\> =20

    2076 - 0x81C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wake-on-LAN (WOL)
```

\<= /td\> =20

    2114 - 0x842

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    2184 - 0x888

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    2185 - 0x889

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    2186 - 0x88A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
WiMax Mac to Mac Packet<=
/pre>
```

=20

    2288 - 0x8F0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
G8BPQ AX.25 over Etherne=
t
```

=20

    2303 - 0x8FF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass net debug=
r
```

=20

    2304 - 0x900

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xerox IEEE802.3 PUP
```

=20

    2560 - 0xA00

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PUP Addr Trans
```

=20

    2561 - 0xA01

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Banyan VINES
```

=20

    2989 - 0xBAD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VINES Loopback
```

=20

    2990 - 0xBAE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VINES Echo
```

=20

    2991 - 0xBAF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Berkeley Trailer nego
```

=20

    4096 - 0x1000

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Berkeley Trailer encap/I=
P
```

=20

    4097 - 0x1001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DCA - Multicast
```

=20

    4660 - 0x1234

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Valid Systems
```

=20

    5632 - 0x1600

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TRAIL - MS Network Monit=
or Summary Packet
```

=20

    6532 - 0x1984

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artificial Horizons
```

=20

    6537 - 0x1989

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datapoint Corporation
```

=20

    6549 - 0x1995

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cisco Group Multicast Pr=
otocol (CGMP)
```

=20

    8193 - 0x2001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GigaSMART Headers
```

\<= /td\> =20

    8933 - 0x22E5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multiple Stream Reservat=
ion Protocol (MSRP)
```

=20

    8938 - 0x22EA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Audio Video Bridging Tra=
nsport Protocol (AVBTP)
```

=20

    8944 - 0x22F0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Robust Header Compressio=
n (ROHC)
```

=20

    8945 - 0x22F1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Transparent Interconnect=
ion of Lots of Links (TRILL)
```

=20

    8947 - 0x22F3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intermediate System to I=
ntermediate System
```

=20

    8948 - 0x22F4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intel Centrino Promiscuo=
us Packets
```

=20

    9298 - 0x2452

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Virtual Circuit=
 Datagram
```

=20

    15360 - 0x3C00

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP System Control =
Datagram
```

=20

    15361 - 0x3C01

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Connect Request=
 (Virtual CCT)
```

=20

    15362 - 0x3C02

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Connect Respons=
e
```

=20

    15363 - 0x3C03

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Connect Complet=
e
```

=20

    15364 - 0x3C04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Close Request (=
Virtual CCT)
```

=20

    15365 - 0x3C05

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Close Response<=
/pre>
```

=20

    15366 - 0x3C06

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Datagram
```

\<= /td\> =20

    15367 - 0x3C07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Datagram Broadc=
ast
```

=20

    15368 - 0x3C08

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Claim NetBIOS N=
ame
```

=20

    15369 - 0x3C09

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Delete Netbios =
Name
```

=20

    15370 - 0x3C0A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Remote Adaptor =
Status Request
```

=20

    15371 - 0x3C0B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Remote Adaptor =
Response
```

=20

    15372 - 0x3C0C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com NBP Reset
```

=20

    15373 - 0x3C0D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet Powerlink (EPL =
v1)
```

=20

    15935 - 0x3E3F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PCS Basic Block Protocol=
```

=20

    16962 - 0x4242

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Modes Little=
 Big LAN Diagnostic
```

=20

    16972 - 0x424C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
THD - Diddle
```

=20

    17185 - 0x4321

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Modes Little=
 Big LAN
```

=20

    19522 - 0x4C42

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BBN Simnet
```

=20

    21000 - 0x5208

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Unassigned
```

=20

    24576 - 0x6000

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Maintenance Operatio=
n Protocol (MOP)
```

=20

    24577 - 0x6001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Maintenance Operatio=
n Protocol (MOP)
```

=20

    24578 - 0x6002

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DECNET Phase IV
```

=20

    24579 - 0x6003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Local Area Transport=
 (LAT)
```

=20

    24580 - 0x6004

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Diagnostic Protocol<=
/pre>
```

=20

    24581 - 0x6005

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Customer Protocol
```

=20

    24582 - 0x6006

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Local Area VAX Clust=
er (LAVC)
```

=20

    24583 - 0x6007

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC AMBER
```

=20

    24584 - 0x6008

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC MUMPS
```

=20

    24585 - 0x6009

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com Corporation
```

=20

    24592 - 0x6010

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com Corporation
```

=20

    24593 - 0x6011

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com Corporation
```

=20

    24594 - 0x6012

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com Corporation
```

=20

    24595 - 0x6013

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com Corporation
```

=20

    24596 - 0x6014

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Trans Ether Bridging
```

=20

    25944 - 0x6558

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Raw Frame Relay
```

=20

    25945 - 0x6559

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass download<=
/pre>
```

=20

    28672 - 0x7000

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass NIUs
```

=20

    28673 - 0x7001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass dia/loop<=
/pre>
```

=20

    28674 - 0x7002

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass (NMC to/f=
rom UB Bridge)
```

=20

    28675 - 0x7003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ungermann-Bass Bridge Sp=
anning Tree
```

=20

    28676 - 0x7004

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OS/9 Microware
```

=20

    28679 - 0x7007

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OS/9 Net
```

=20

    28681 - 0x7009

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28704 - 0x7020

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28705 - 0x7021

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28706 - 0x7022

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28707 - 0x7023

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28708 - 0x7024

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28709 - 0x7025

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28710 - 0x7026

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28711 - 0x7027

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28712 - 0x7028

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sintrom (was LRT - Engla=
nd)
```

=20

    28713 - 0x7029

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Proteon
```

=20

    28720 - 0x7030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Prime NTS (Network Termi=
nal Service)
```

=20

    28721 - 0x7031

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cabletron
```

=20

    28724 - 0x7034

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cronus VLN
```

=20

    32771 - 0x8003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cronus Direct
```

=20

    32772 - 0x8004

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HP Probe
```

=20

    32773 - 0x8005

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nestar
```

=20

    32774 - 0x8006

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AT&T
```

=20

    32776 - 0x8008

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Excelan
```

=20

    32784 - 0x8010

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SGI diagnostics
```

=20

    32787 - 0x8013

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SGI network games
```

\<= /td\> =20

    32788 - 0x8014

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SGI reserved
```

=20

    32789 - 0x8015

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SGI bounce server
```

\<= /td\> =20

    32790 - 0x8016

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apollo Domain
```

=20

    32793 - 0x8019

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Tymshare
```

=20

    32815 - 0x802F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Tigan, Inc.
```

=20

    32816 - 0x8030

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reverse ARP
```

=20

    32821 - 0x8035

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Aeonic Systems
```

=20

    32822 - 0x8036

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPX (Novell Netware)
```

=20

    32823 - 0x8037

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC LANBridge Management=
```

=20

    32824 - 0x8038

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC DSM/DDP
```

=20

    32825 - 0x8039

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Argonaut Console
```

=20

    32826 - 0x803A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC VAXELN
```

=20

    32827 - 0x803B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC DNS Naming Service
```

=20

    32828 - 0x803C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Ethernet CSMA/CD Enc=
ryption Protocol
```

=20

    32829 - 0x803D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Distributed Time Ser=
vice
```

=20

    32830 - 0x803E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC LAN Traffic Monitor =
Protocol
```

=20

    32831 - 0x803F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC PATHWORKS DECnet NET=
BIOS Emulation
```

=20

    32832 - 0x8040

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Local Area System Tr=
ansport
```

=20

    32833 - 0x8041

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC unassigned
```

=20

    32834 - 0x8042

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Planning Research Corp.<=
/pre>
```

=20

    32836 - 0x8044

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AT&T
```

=20

    32838 - 0x8046

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AT&T
```

=20

    32839 - 0x8047

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DEC Availability Manager=
```

=20

    32840 - 0x8048

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ExperData
```

=20

    32841 - 0x8049

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VMTP (Versatile Message =
Transaction Protocol)
```

=20

    32859 - 0x805B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Stanford V Kernel prod.<=
/pre>
```

=20

    32860 - 0x805C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Evans & Sutherland
```

=20

    32861 - 0x805D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Little Machines
```

=20

    32864 - 0x8060

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Counterpoint Computers
```

=20

    32866 - 0x8062

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Univ. of Mass. @ Amherst=
```

=20

    32869 - 0x8065

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Univ. of Mass. @ Amherst=
```

=20

    32870 - 0x8066

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Veeco Integrated Auto.
```

=20

    32871 - 0x8067

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
General Dynamics
```

=20

    32872 - 0x8068

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AT&T
```

=20

    32873 - 0x8069

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Autophon
```

=20

    32874 - 0x806A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ComDesign
```

=20

    32876 - 0x806C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computgraphic Corp.
```

=20

    32877 - 0x806D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32878 - 0x806E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32879 - 0x806F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32880 - 0x8070

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32881 - 0x8071

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32882 - 0x8072

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32883 - 0x8073

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32884 - 0x8074

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32885 - 0x8075

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32886 - 0x8076

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landmark Graphics Corpor=
ation
```

=20

    32887 - 0x8077

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Matra
```

=20

    32890 - 0x807A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Dansk Data Elektronik
```

=20

    32891 - 0x807B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Merit Internodal
```

=20

    32892 - 0x807C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Vitalink Communications<=
/pre>
```

=20

    32893 - 0x807D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Vitalink Communications<=
/pre>
```

=20

    32894 - 0x807E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Vitalink Communications<=
/pre>
```

=20

    32895 - 0x807F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Vitalink TransLAN III
```

=20

    32896 - 0x8080

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Counterpoint Computers
```

=20

    32897 - 0x8081

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Counterpoint Computers
```

=20

    32898 - 0x8082

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Counterpoint Computers
```

=20

    32899 - 0x8083

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    32904 - 0x8088

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    32906 - 0x808A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethertalk (AppleTalk ove=
r Ethernet)
```

=20

    32923 - 0x809B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32924 - 0x809C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32925 - 0x809D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32926 - 0x809E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Spider Systems Ltd.
```

=20

    32927 - 0x809F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nixdorf Computers
```

\<= /td\> =20

    32931 - 0x80A3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32932 - 0x80A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32933 - 0x80A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32934 - 0x80A6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32935 - 0x80A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32936 - 0x80A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32937 - 0x80A9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32938 - 0x80AA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32939 - 0x80AB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32940 - 0x80AC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32941 - 0x80AD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32942 - 0x80AE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32943 - 0x80AF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32944 - 0x80B0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32945 - 0x80B1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32946 - 0x80B2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Siemens Gammasonics Inc.=
```

=20

    32947 - 0x80B3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DCA Data Exchange Cluste=
r
```

=20

    32960 - 0x80C0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DCA Data Exchange Cluste=
r
```

=20

    32961 - 0x80C1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DCA Data Exchange Cluste=
r
```

=20

    32962 - 0x80C2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DCA Data Exchange Cluste=
r
```

=20

    32963 - 0x80C3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Banyan Systems
```

=20

    32964 - 0x80C4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Banyan Systems
```

=20

    32965 - 0x80C5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Pacer Software
```

=20

    32966 - 0x80C6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Applitek Corporation
```

=20

    32967 - 0x80C7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intergraph Corporation
```

=20

    32968 - 0x80C8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intergraph Corporation
```

=20

    32969 - 0x80C9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intergraph Corporation
```

=20

    32970 - 0x80CA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intergraph Corporation
```

=20

    32971 - 0x80CB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intergraph Corporation
```

=20

    32972 - 0x80CC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Harris Corporation
```

=

=20

    32973 - 0x80CD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Harris Corporation
```

=

=20

    32974 - 0x80CE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taylor Instrument
```

\<= /td\> =20

    32975 - 0x80CF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taylor Instrument
```

\<= /td\> =20

    32976 - 0x80D0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taylor Instrument
```

\<= /td\> =20

    32977 - 0x80D1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taylor Instrument
```

\<= /td\> =20

    32978 - 0x80D2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Rosemount Corporation
```

=20

    32979 - 0x80D3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Rosemount Corporation
```

=20

    32980 - 0x80D4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IBM SNA Service on Ether=
```

=20

    32981 - 0x80D5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Varian Associates
```

\<= /td\> =20

    32989 - 0x80DD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Transparent Remote File =
System (TRFS)
```

=20

    32990 - 0x80DE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Transparent Remote File =
System (TRFS)
```

=20

    32991 - 0x80DF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Allen-Bradley
```

=20

    32992 - 0x80E0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Allen-Bradley
```

=20

    32993 - 0x80E1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Allen-Bradley
```

=20

    32994 - 0x80E2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Allen-Bradley
```

=20

    32995 - 0x80E3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32996 - 0x80E4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32997 - 0x80E5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32998 - 0x80E6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    32999 - 0x80E7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33000 - 0x80E8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33001 - 0x80E9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33002 - 0x80EA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33003 - 0x80EB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33004 - 0x80EC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33005 - 0x80ED

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33006 - 0x80EE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33007 - 0x80EF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datability
```

=20

    33008 - 0x80F0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Retix
```

=20

    33010 - 0x80F2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
AppleTalk AARP (Kinetics=
)
```

=20

    33011 - 0x80F3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Kinetics
```

=20

    33012 - 0x80F4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Kinetics
```

=20

    33013 - 0x80F5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apollo Computer
```

=20

    33015 - 0x80F7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wellfleet Communications=
```

=20

    33023 - 0x80FF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IEEE 802.1Q VLAN-tagged<=
/pre>
```

=20

    33024 - 0x8100

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wellfleet Communications=
```

=20

    33025 - 0x8101

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wellfleet - BOFL (Breath=
 Of Life)
```

=20

    33026 - 0x8102

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wellfleet Communications=
```

=20

    33027 - 0x8103

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Symbolics Private
```

\<= /td\> =20

    33031 - 0x8107

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Symbolics Private
```

\<= /td\> =20

    33032 - 0x8108

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Symbolics Private
```

\<= /td\> =20

    33033 - 0x8109

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Talaris
```

=20

    33067 - 0x812B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Hayes Microcomputers
```

=20

    33072 - 0x8130

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VG Laboratory Systems
```

=20

    33073 - 0x8131

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bridge Communications
```

=20

    33074 - 0x8132

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Juniper NetScreen Redund=
ancy Protocol (NSRP v2)
```

=20

    33075 - 0x8133

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bridge Communications
```

=20

    33076 - 0x8134

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bridge Communications
```

=20

    33077 - 0x8135

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bridge Communications
```

=20

    33078 - 0x8136

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPX - NetWare
```

=20

    33079 - 0x8137

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPX - Novell
```

=20

    33080 - 0x8138

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KTI
```

=20

    33081 - 0x8139

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KTI
```

=20

    33082 - 0x813A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KTI
```

=20

    33083 - 0x813B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KTI
```

=20

    33084 - 0x813C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
KTI
```

=20

    33085 - 0x813D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
M/MUMPS Data Sharing
```

=20

    33087 - 0x813F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Amoeba 4 RPC - Vrije Uni=
versiteit (NL)
```

=20

    33093 - 0x8145

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Fast Local Internet Prot=
ocol (FLIP)
```

=20

    33094 - 0x8146

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Vrije Universiteit (NL)<=
/pre>
```

=20

    33095 - 0x8147

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Logicraft
```

=20

    33096 - 0x8148

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Network Computing Device=
s
```

=20

    33097 - 0x8149

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Alpha Micro
```

=20

    33098 - 0x814A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SNMP over Eth.
```

=20

    33100 - 0x814C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BIIN
```

=20

    33101 - 0x814D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BIIN 814F Technically El=
ite Concepts
```

=20

    33102 - 0x814E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Technically Elite Concep=
ts
```

=20

    33103 - 0x814F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Rational Corp
```

=20

    33104 - 0x8150

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33105 - 0x8151

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33106 - 0x8152

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33107 - 0x8153

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Protocol Pty Lt=
d
```

=20

    33116 - 0x815C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Protocol Pty Lt=
d
```

=20

    33117 - 0x815D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Protocol Pty Lt=
d
```

=20

    33118 - 0x815E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33124 - 0x8164

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33125 - 0x8165

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33126 - 0x8166

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XTP
```

=20

    33149 - 0x817D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SGI/Time Warner Propriet=
ary
```

=20

    33150 - 0x817E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
High-Performance Paralle=
l Interface-Framing (HIPPI-FP)
```

=20

    33152 - 0x8180

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
High-Performance Paralle=
l Interface-Scheduled Transfer (HIPPI-STP)
```

=20

    33153 - 0x8181

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved for HIPPI-6400<=
/pre>
```

=20

    33154 - 0x8182

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved for HIPPI-6400<=
/pre>
```

=20

    33155 - 0x8183

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33156 - 0x8184

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33157 - 0x8185

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33158 - 0x8186

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33159 - 0x8187

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33160 - 0x8188

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33161 - 0x8189

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33162 - 0x818A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33163 - 0x818B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Silicon Graphics Proprie=
tary
```

=20

    33164 - 0x818C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Motorola Computer
```

\<= /td\> =20

    33165 - 0x818D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PowerLAN / NetBIOS/NetBE=
UI (PC)
```

=20

    33169 - 0x8191

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33178 - 0x819A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33179 - 0x819B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33180 - 0x819C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33181 - 0x819D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33182 - 0x819E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33183 - 0x819F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33184 - 0x81A0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33185 - 0x81A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33186 - 0x81A2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Qualcomm
```

=20

    33187 - 0x81A3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ARAI Bunkichi
```

=20

    33188 - 0x81A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RAD Network Devices
```

=20

    33189 - 0x81A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RAD Network Devices
```

=20

    33198 - 0x81AE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    33207 - 0x81B7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    33208 - 0x81B8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Xyplex
```

=20

    33209 - 0x81B9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33228 - 0x81CC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33229 - 0x81CD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33230 - 0x81CE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33231 - 0x81CF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33232 - 0x81D0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33233 - 0x81D1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33234 - 0x81D2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33235 - 0x81D3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33236 - 0x81D4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Apricot Computers
```

\<= /td\> =20

    33237 - 0x81D5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33238 - 0x81D6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33239 - 0x81D7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33240 - 0x81D8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33241 - 0x81D9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33242 - 0x81DA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33243 - 0x81DB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33244 - 0x81DC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Artisoft Lantastic
```

=

=20

    33245 - 0x81DD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33254 - 0x81E6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33255 - 0x81E7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33256 - 0x81E8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33257 - 0x81E9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33258 - 0x81EA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33259 - 0x81EB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33260 - 0x81EC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33261 - 0x81ED

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33262 - 0x81EE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Polygon
```

=20

    33263 - 0x81EF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Comsat Labs
```

=20

    33264 - 0x81F0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Comsat Labs
```

=20

    33265 - 0x81F1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Comsat Labs
```

=20

    33266 - 0x81F2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SAIC
```

=20

    33267 - 0x81F3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SAIC
```

=20

    33268 - 0x81F4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SAIC
```

=20

    33269 - 0x81F5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VG Analytical
```

=20

    33270 - 0x81F6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VG Analytical
```

=20

    33271 - 0x81F7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VG Analytical
```

=20

    33272 - 0x81F8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cabletron InterSwitch Me=
ssage Protocol
```

=20

    33277 - 0x81FD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cabletron InterSwitch Me=
ssage Protocol
```

=20

    33279 - 0x81FF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
QNX QNet Software System=
s Ltd.
```

=20

    33283 - 0x8203

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
QNX QNet Software System=
s Ltd.
```

=20

    33284 - 0x8204

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
QNX QNet Software System=
s Ltd.
```

=20

    33285 - 0x8205

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ascom Banking Systems
```

=20

    33313 - 0x8221

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ascom Banking Systems
```

=20

    33314 - 0x8222

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Advanced Encryption Syst=
em
```

=20

    33342 - 0x823E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Advanced Encryption Syst=
em
```

=20

    33343 - 0x823F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Advanced Encryption Syst=
em
```

=20

    33344 - 0x8240

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33379 - 0x8263

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33380 - 0x8264

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33381 - 0x8265

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33382 - 0x8266

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33383 - 0x8267

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33384 - 0x8268

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33385 - 0x8269

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Charles River Data Syste=
m
```

=20

    33386 - 0x826A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Athena Programming
```

=

=20

    33407 - 0x827F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Athena Programming
```

=

=20

    33408 - 0x8280

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Athena Programming
```

=

=20

    33409 - 0x8281

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Athena Programming
```

=

=20

    33410 - 0x8282

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Institute for Industrial=
 Information Tech. Ltd
```

=20

    33434 - 0x829A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Institute for Industrial=
 Information Tech. Ltd
```

=20

    33435 - 0x829B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33436 - 0x829C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33437 - 0x829D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33438 - 0x829E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33439 - 0x829F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33440 - 0x82A0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33441 - 0x82A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33442 - 0x82A2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33443 - 0x82A3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33444 - 0x82A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33445 - 0x82A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33446 - 0x82A6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33447 - 0x82A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33448 - 0x82A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33449 - 0x82A9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33450 - 0x82AA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Taurus Controls
```

=20

    33451 - 0x82AB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Accton Technologies
```

=20

    33680 - 0x8390

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Talaris Multicast
```

\<= /td\> =20

    34091 - 0x852B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Kalpana
```

=20

    34178 - 0x8582

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34452 - 0x8694

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34453 - 0x8695

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34454 - 0x8696

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34455 - 0x8697

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34456 - 0x8698

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34457 - 0x8699

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34458 - 0x869A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34459 - 0x869B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34460 - 0x869C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Idea Courier
```

=20

    34461 - 0x869D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Network Tech
```

=20

    34462 - 0x869E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Network Tech
```

=20

    34463 - 0x869F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Network Tech
```

=20

    34464 - 0x86A0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Computer Network Tech
```

=20

    34465 - 0x86A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34467 - 0x86A3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34468 - 0x86A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34469 - 0x86A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34470 - 0x86A6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34471 - 0x86A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34472 - 0x86A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34473 - 0x86A9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34474 - 0x86AA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34475 - 0x86AB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Communications
```

=20

    34476 - 0x86AC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SECTRA
```

=20

    34523 - 0x86DB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6
```

=20

    34525 - 0x86DD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Delta Controls
```

=20

    34526 - 0x86DE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ATOMIC
```

=20

    34527 - 0x86DF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landis & Gyr Powers<=
/pre>
```

=20

    34528 - 0x86E0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Landis & Gyr Powers<=
/pre>
```

=20

    34543 - 0x86EF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Motorola
```

=20

    34560 - 0x8700

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Motorola
```

=20

    34576 - 0x8710

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cisco Wireless Lan Conte=
xt Control Protocol (WLCCP)
```

=20

    34605 - 0x872D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Control Technology Inc. =
- RDP Without IP
```

=20

    34617 - 0x8739

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Control Technology Inc. =
- Multicast 
```

=20

    34618 - 0x873A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Control Technology Inc. =
- Proprietary
```

=20

    34619 - 0x873B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Control Technology Inc. =
- Proprietary
```

=20

    34620 - 0x873C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TCP/IP Compression
```

=

=20

    34667 - 0x876B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IP Autonomous Systems
```

=20

    34668 - 0x876C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Secure Data
```

=20

    34669 - 0x876D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Symbol Technologies
```

=20

    34688 - 0x8780

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Motorola Protocol, Roami=
ng  Updates between Access Points 
```

=20

    34689 - 0x8781

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Motorola Protocol, Acces=
s Point Adoption, extended VLANs and Clustering
```

=20

    34691 - 0x8783

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet Flow Control / =
Ethernet Passive Optical Network (EPON)
```

=20

    34824 - 0x8808

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet OAM Protocol IE=
EE 802.3ah (a.k.a.: Slow Protocols)
```

=20

    34825 - 0x8809

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Point-to-Point Protocol =
(PPP)
```

=20

    34827 - 0x880B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
General Switch Managemen=
t Protocol (GSMP)
```

=20

    34828 - 0x880C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cirrus CobraNet
```

=20

    34841 - 0x8819

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Hitachi Cable (Optoelect=
ronic Systems Laboratory)
```

=20

    34848 - 0x8820

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Web-cache Coordination P=
rotocol
```

=20

    34878 - 0x883E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multi-Protocol Label Swi=
tching (MPLS) Unicast 
```

=20

    34887 - 0x8847

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multi-Protocol Label Swi=
tching (MPLS) Multicast
```

=20

    34888 - 0x8848

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Axis Communications AB -=
 Proprietary
```

=20

    34902 - 0x8856

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Foundry Proprietary Prot=
ocol
```

=20

    34906 - 0x885A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multicast Channel Alloca=
tion Protocol (MCAP)
```

=20

    34913 - 0x8861

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PPP Over Ethernet (PPPoE=
) Discovery Stage
```

=20

    34915 - 0x8863

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PPP Over Ethernet (PPPoE=
) Session Stage
```

=20

    34916 - 0x8864

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Intel ANS (NIC Teaming)<=
/pre>
```

=20

    34925 - 0x886D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Microsoft Network Load B=
alancing Hearbeat
```

=20

    34927 - 0x886F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Jumbo Frames
```

=20

    34928 - 0x8870

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HomePlug 1.0 MME
```

=20

    34939 - 0x887B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Byte Stream Protocol for=
 IP based micro-mobility bearer interfaces (A10)
```

=20

    34945 - 0x8881

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Frame-based ATM Transpor=
t over Ethernet
```

=20

    34948 - 0x8884

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HP LanProbe Test
```

=20

    34952 - 0x8888

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EAP over LAN - Authentic=
ation (IEEE 802.1X)
```

=20

    34958 - 0x888E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PROFIBUS PROFINET Protoc=
ol
```

=20

    34962 - 0x8892

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Realtek Remote Control P=
rotocol (RRCP)
```

=20

    34969 - 0x8899

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HyperSCSI (SCSI over Eth=
ernet)
```

=20

    34970 - 0x889A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CSM_ENCAPS Protocol - Mi=
ndspeed Technologies
```

=20

    34971 - 0x889B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Telkonet Powerline Ether=
net
```

=20

    34977 - 0x88A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ATA over Ethernet (AoE)<=
/pre>
```

=20

    34978 - 0x88A2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EtherCAT Protocol
```

\<= /td\> =20

    34980 - 0x88A4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Huawei Technologies / Cl=
uster
```

=20

    34983 - 0x88A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Provider Bridging (IEEE =
802.1ad) & Shortest Path Bridging IEEE 802.1aq
```

=20

    34984 - 0x88A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet Powerlink, Comm=
unication Profile for Real-Time Ethernet (RTE)
```

=20

    34987 - 0x88AB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
XiMeta Technology Americ=
as Inc. Proprietary 
```

=20

    34989 - 0x88AD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Boardwalk
```

=20

    34990 - 0x88AE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
WLAN Authentication Infr=
astructure (WAI) Authentication Protocol
```

=20

    34996 - 0x88B4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IEEE 802a OUI Extended E=
thertype
```

=20

    34999 - 0x88B7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Generic substation Event=
s - International Electrotechnical Commission - Electrical Substation Autom=
ation (IEC-61850)
```

=20

    35000 - 0x88B8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sampled Value Services -=
 International Electrotechnical Commission
```

=20

    35002 - 0x88BA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Light Weight Access Poin=
t Protocol (LWAPP)
```

=20

    35003 - 0x88BB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Robust Security Network =
(RSN) Pre-Authentication - 802.11i 
```

=20

    35015 - 0x88C7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Transparent Inter Proces=
s Communication Protocol (TIPC)
```

=20

    35018 - 0x88CA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Link Layer Discovery Pro=
tocol (LLDP)
```

=20

    35020 - 0x88CC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SERCOS III Real-time Pro=
tocol for Motion Control
```

=20

    35021 - 0x88CD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3rd Generation Partnersh=
ip Project 2 (3GPP2) for CDMA2000 Access Network Interfaces
```

=20

    35026 - 0x88D2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Circuit Emulation Servic=
es over Ethernet (MEF 8)
```

=20

    35032 - 0x88D8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Link Layer Topology Disc=
overy (LLTD)
```

=20

    35033 - 0x88D9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wireless Access in a Veh=
icle Environment - WAVE Short Message Protocol (WSMP)
```

=20

    35036 - 0x88DC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VMware LabManager
```

\<= /td\> =20

    35038 - 0x88DE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HomePlug AV
```

=20

    35041 - 0x88E1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Media Redundancy Protoco=
l (IEC62439-2)
```

=20

    35043 - 0x88E3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
MAC security (IEEE 802.1=
AE)
```

=20

    35045 - 0x88E5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Provider Backbone Bridge=
 Mac-in-Mac - IEEE 802.1ah
```

=20

    35047 - 0x88E7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethernet Local Managemen=
t Interface (E-LMI)
```

=20

    35054 - 0x88EE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multiple VLAN Registrati=
on Protocol (MVRP) - IEEE 802.1ak
```

=20

    35061 - 0x88F5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multiple MAC Registratio=
n Protocol (MMRP) - IEEE 802.1ak
```

=20

    35062 - 0x88F6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Precision Time Protocol =
over Eth. (PTP v2) - IEEE-1588
```

=20

    35063 - 0x88F7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Network Controller Sideb=
and Interface (NCSI)
```

=20

    35064 - 0x88F8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Parallel Redundancy Prot=
ocol (IEC62439 Part 3)
```

=20

    35067 - 0x88FB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nokia Siemens Networks F=
low Layer Internal Protocol (FLIP)
```

=20

    35073 - 0x8901

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IEEE 802.1ag Connectivit=
y Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
```

=

=20

    35074 - 0x8902

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cisco FabricPath Switchi=
ng - Frame Encapsulation - DCE
```

=20

    35075 - 0x8903

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Fiber Channel over Ether=
net (FCoE)
```

=20

    35078 - 0x8906

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Wireless LAN - Data Enca=
psulation (IEEE-802.11)
```

=20

    35085 - 0x890D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ENEA LINX (Inter Process=
 Communication) IPC Protocol over Ethernet
```

=20

    35089 - 0x8911

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Fiber Channel over Ether=
net (FCoE)- Initialization Protocol
```

=20

    35092 - 0x8914

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Infiniband Remote Direct=
 Memory Access (RDMA) over Converged Ethernet (RoCE)
```

=20

    35093 - 0x8915

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Media Independent Handov=
er Protocol
```

=20

    35095 - 0x8917

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TTEthernet Protocol Cont=
rol Frame
```

=20

    35101 - 0x891D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
High-availability Seamle=
ss Redundancy (IEC-62439)
```

=20

    35119 - 0x892F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Invisible Software
```

=

=20

    35478 - 0x8A96

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Invisible Software
```

=

=20

    35479 - 0x8A97

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Loopback (Configuration =
Layer 2 Test Protocol)
```

=20

    36864 - 0x9000

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com (Formerly Bridge Co=
mmunications), XNS Systems Management
```

=20

    36865 - 0x9001

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com (Formerly Bridge Co=
mmunications), TCP/IP Systems Management
```

=20

    36866 - 0x9002

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3Com (Formerly Bridge Co=
mmunications), Loopback Detection
```

=20

    36867 - 0x9003

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RTnet: Real-Time Media A=
ccess Control (RTMAC)
```

=20

    36897 - 0x9021

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RTnet: Real-Time Configu=
ration Protocol (RTCFG)
```

=20

    36898 - 0x9022

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Q-in-Q / VLAN-tagged fra=
me
```

=20

    37120 - 0x9100

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Q-in-Q / VLAN-tagged fra=
me
```

=20

    37376 - 0x9200

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DECNET - Used by VAX 622=
0 DEBNI
```

=20

    43690 - 0xAAAA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Veritas Low Latency Tran=
sport (LLT)
```

=20

    51966 - 0xCAFE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Digium Time Division Mul=
tiplexing (TDM) over Ethernet (TDMoE)
```

=20

    53261 - 0xD00D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ethertype Distributed Sw=
itch Architecture (DSA)
```

=20

    56026 - 0xDADA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Sonix Arpeggio
```

=20

    64245 - 0xFAF5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Cisco Multilayer Directo=
r Switches (MDS)
```

=20

    64764 - 0xFCFC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BBN VITAL-LanBridge cach=
e wakeups
```

=20

    65280 - 0xFF00

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65281 - 0xFF01

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65282 - 0xFF02

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65283 - 0xFF03

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65284 - 0xFF04

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65285 - 0xFF05

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65286 - 0xFF06

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65287 - 0xFF07

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65288 - 0xFF08

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65289 - 0xFF09

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65290 - 0xFF0A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65291 - 0xFF0B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65292 - 0xFF0C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65293 - 0xFF0D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ISC Bunker Ramo
```

=20

    65294 - 0xFF0E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved
```

=20

    65535 - 0xFFFF

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [httpquerymethod](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"httpquerymethod-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
GET
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HEAD
```

=20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
POST
```

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CONNECT
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PUT
```

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OPTIONS
```

=20

    5 - 0x5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TRACE
```

=20

    6 - 0x6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DELETE
```

=20

    7 - 0x7

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [httpstatus](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"httpstatus-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No response
```

=20

    None

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Continue
```

=20

    100 - 0x64

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Switching Protocols
```

=20

    101 - 0x65

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Processing
```

=20

    102 - 0x66

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Early Hints
```

=20

    103 - 0x67

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OK
```

=20

    200 - 0xC8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Created
```

=20

    201 - 0xC9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Accepted
```

=20

    202 - 0xCA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Non-Authoritative Inform=
ation
```

=20

    203 - 0xCB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No Content
```

=20

    204 - 0xCC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reset Content
```

=20

    205 - 0xCD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Partial Content
```

=20

    206 - 0xCE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multi-Status
```

=20

    207 - 0xCF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Already Reported
```

=20

    208 - 0xD0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IM Used
```

=20

    226 - 0xE2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multiple Choices
```

=20

    300 - 0x12C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Moved Permanently
```

\<= /td\> =20

    301 - 0x12D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Found
```

=20

    302 - 0x12E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
See Other
```

=20

    303 - 0x12F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Not Modified
```

=20

    304 - 0x130

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Use Proxy
```

=20

    305 - 0x131

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Switch Proxy
```

=20

    306 - 0x132

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Temporary Redirect
```

=

=20

    307 - 0x133

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Permanent Redirect
```

=

=20

    308 - 0x134

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad Request
```

=20

    400 - 0x190

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unauthorized
```

=20

    401 - 0x191

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Payment Required
```

=20

    402 - 0x192

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Forbidden
```

=20

    403 - 0x193

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Not Found
```

=20

    404 - 0x194

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Method Not Allowed
```

=

=20

    405 - 0x195

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Not Acceptable
```

=20

    406 - 0x196

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Proxy Authentication Req=
uired
```

=20

    407 - 0x197

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Request Timeout
```

=20

    408 - 0x198

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Conflict
```

=20

    409 - 0x199

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gone
```

=20

    410 - 0x19A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Length Required
```

=20

    411 - 0x19B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Precondition Failed
```

=20

    412 - 0x19C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Request Entity Too Large=
```

=20

    413 - 0x19D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Request-URI Too Long
```

=20

    414 - 0x19E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unsupported Media Type
```

=20

    415 - 0x19F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Requested Range Not Sati=
sfiable
```

=20

    416 - 0x1A0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Expectation Failed
```

=

=20

    417 - 0x1A1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
I'm a teapot
```

=20

    418 - 0x1A2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Misdirected Request
```

=20

    421 - 0x1A5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unprocessable Entity
```

=20

    422 - 0x1A6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Locked
```

=20

    423 - 0x1A7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Failed Dependency
```

\<= /td\> =20

    424 - 0x1A8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Upgrade Required
```

=20

    426 - 0x1AA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Precondition Required
```

=20

    428 - 0x1AC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Too Many Requests
```

\<= /td\> =20

    429 - 0x1AD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Request Header Fields To=
o Large
```

=20

    431 - 0x1AF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unavailable For Legal Re=
asons
```

=20

    451 - 0x1C3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Internal Server Error
```

=20

    500 - 0x1F4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Not Implemented
```

=20

    501 - 0x1F5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad Gateway
```

=20

    502 - 0x1F6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Service Unavailable
```

=20

    503 - 0x1F7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Gateway Timeout
```

=20

    504 - 0x1F8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HTTP Version Not Support=
ed
```

=20

    505 - 0x1F9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Variant Also Negotiates<=
/pre>
```

=20

    506 - 0x1FA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Insufficient Storage
```

=20

    507 - 0x1FB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Loop Detected
```

=20

    508 - 0x1FC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Not Extended
```

=20

    510 - 0x1FE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Network Authentication R=
equired
```

=20

    511 - 0x1FF

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [httpstatuscategory](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"httpstatuscategory-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No response
```

=20

    None

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Informational (1xx)
```

=20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OK (2xx)
```

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Multiple Choices (3xx)
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad Request (4xx)
```

\<= /td\> =20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Internal Server Error (5=
xx)
```

=20

    5 - 0x5

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [icmpmessage](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"icmpmessage-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Echo Reply
```

=20

    0:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Network Unreachable
```

=20

    3:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Host Unreachable
```

=20

    3:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Protocol Unreachable
```

=20

    3:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Port Unreachable
```

=20

    3:3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Fragmentation Needed and=
 Don't Fragment was Set
```

=20

    3:4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Source Route Failed
```

=20

    3:5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Destination Network Unkn=
own
```

=20

    3:6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Destination Host Unknown=
```

=20

    3:7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Source Host Isolated
```

=20

    3:8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Communication with Desti=
nation Network is Administratively Prohibited
```

=20

    3:9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Communication with Desti=
nation Host is Administratively Prohibited
```

=20

    3:10

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Destination Network Unre=
achable for Type of Service
```

=20

    3:11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Destination Host Unreach=
able for Type of Service
```

=20

    3:12

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Communication Administra=
tively Prohibited
```

=20

    3:13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Host Precedence Violatio=
n
```

=20

    3:14

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Precedence cutoff in eff=
ect
```

=20

    3:15

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Source Quench
```

=20

    4:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Redirect Datagram for th=
e Network (or subnet)
```

=20

    5:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Redirect Datagram for th=
e Host
```

=20

    5:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Redirect Datagram for th=
e Type of Service and Network
```

=20

    5:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Redirect Datagram for th=
e Type of Service and Host
```

=20

    5:3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Alternate Address for Ho=
st
```

=20

    6:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Echo
```

=20

    8:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Normal router advertisem=
ent
```

=20

    9:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Does not route common tr=
affic
```

=20

    9:16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Router Selection
```

=20

    10:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Time to Live exceeded in=
 Transit
```

=20

    11:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Fragment Reassembly Time=
 Exceeded
```

=20

    11:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Pointer indicates the er=
ror
```

=20

    12:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Missing a Required Optio=
n
```

=20

    12:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad Length
```

=20

    12:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Timestamp
```

=20

    13:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Timestamp Reply
```

=20

    14:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Request
```

=20

    15:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Reply
```

\<= /td\> =20

    16:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Address Mask Request
```

=20

    17:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Address Mask Reply
```

=

=20

    18:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Security)<=
/pre>
```

=20

    19:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    20:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    21:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    22:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    23:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    24:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    25:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    26:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    27:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    28:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

    29:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Traceroute
```

=20

    30:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datagram Conversion Erro=
r
```

=20

    31:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Host Redirect
```

=20

    32:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Where-Are-You
```

=

=20

    33:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 I-Am-Here
```

=20

    34:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Registration Requ=
est
```

=20

    35:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Registration Repl=
y
```

=20

    36:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SKIP
```

=20

    39:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Bad SPI
```

=20

    40:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Authentication Failed
```

=20

    40:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decompression Failed
```

=20

    40:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Decryption Failed
```

\<= /td\> =20

    40:3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Need Authentication
```

=20

    40:4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Need Authorization
```

=

=20

    40:5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Echo Request
```

\<= /td\> =20

    128:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Echo Reply
```

=20

    129:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Query
```

=20

    130:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Report
```

=20

    131:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Done
```

=20

    132:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Router Solicitation=
```

=20

    133:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Router Advertisemen=
t
```

=20

    134:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Neighbor Solicitati=
on
```

=20

    135:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Neighbor Advertisem=
ent
```

=20

    136:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Redirect Message
```

=20

    137:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Command
```

=20

    138:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Result
```

=20

    138:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reset
```

=20

    138:255

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Subject
```

=20

    139:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Subject or Empty
```

=20

    139:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Ipv4 Subject
```

=20

    139:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Successful
```

=20

    140:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Refused
```

=20

    140:1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unknown
```

=20

    140:2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Inverse Neighbor Di=
scovery Solicitation Message
```

=20

    141:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Inverse Neighbor Di=
scovery Advertisement Message
```

=20

    142:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Home Agent Address =
Discovery Request Message
```

=20

    144:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Home Agent Address =
Discovery Reply Message
```

=20

    145:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Mobile Prefix Solic=
itation
```

=20

    146:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Mobile Prefix Adver=
tisement
```

=20

    147:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Certification Path =
Solicitation Message
```

=20

    148:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Certification Path =
Advertisement Message
```

=20

    149:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router Ad=
vertisement
```

=20

    151:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router So=
licitation
```

=20

    152:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router Te=
rmination
```

=20

    153:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FMIPv6 Messages
```

=20

    154:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RFC3692-style Experiment=
 1
```

=20

    253:0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RFC3692-style Experiment=
 2
```

=20

    254:0

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [icmptype](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"icmptype-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Category

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Echo Reply
```

=20

Message

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Destination Unreachable<=
/pre>
```

=20

Error

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Source Quench
```

=20

Error

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Redirect
```

=20

Message

=20

    5 - 0x5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Alternate Host Address
```

=20

Message

=20

    6 - 0x6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Echo
```

=20

Message

=20

    8 - 0x8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Router Advertisement
```

=20

Error

=20

    9 - 0x9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Router Selection
```

=20

Error

=20

    10 - 0xA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Time Exceeded
```

=20

Error

=20

    11 - 0xB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Parameter Problem
```

\<= /td\> =20

Error

=20

    12 - 0xC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Timestamp
```

=20

Message

=20

    13 - 0xD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Timestamp Reply
```

=20

Message

=20

    14 - 0xE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Request
```

=20

Message

=20

    15 - 0xF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Information Reply
```

\<= /td\> =20

Message

=20

    16 - 0x10

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Address Mask Request
```

=20

Message

=20

    17 - 0x11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Address Mask Reply
```

=

=20

Message

=20

    18 - 0x12

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Security)<=
/pre>
```

=20

Error

=20

    19 - 0x13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    20 - 0x14

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    21 - 0x15

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    22 - 0x16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    23 - 0x17

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    24 - 0x18

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    25 - 0x19

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    26 - 0x1A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    27 - 0x1B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    28 - 0x1C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Reserved (for Robustness=
 Experiment)
```

=20

Error

=20

    29 - 0x1D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Traceroute
```

=20

Error

=20

    30 - 0x1E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Datagram Conversion Erro=
r
```

=20

Error

=20

    31 - 0x1F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Host Redirect
```

=20

Error

=20

    32 - 0x20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Where-Are-You
```

=

=20

Error

=20

    33 - 0x21

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 I-Am-Here
```

=20

Error

=20

    34 - 0x22

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Registration Requ=
est
```

=20

Message

=20

    35 - 0x23

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mobile Registration Repl=
y
```

=20

Message

=20

    36 - 0x24

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Skip
```

=20

Error

=20

    39 - 0x27

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Photuris
```

=20

Error

=20

    40 - 0x28

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Echo Request
```

\<= /td\> =20

Message

=20

    128 - 0x80

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Echo Reply
```

=20

Message

=20

    129 - 0x81

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Query
```

=20

Message

=20

    130 - 0x82

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Report
```

=20

Message

=20

    131 - 0x83

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Listener =
Done
```

=20

Message

=20

    132 - 0x84

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Router Solicitation=
```

=20

Message

=20

    133 - 0x85

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Router Advertisemen=
t
```

=20

Message

=20

    134 - 0x86

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Neighbor Solicitati=
on
```

=20

Message

=20

    135 - 0x87

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Neighbor Advertisem=
ent
```

=20

Message

=20

    136 - 0x88

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Redirect Message
```

=20

Message

=20

    137 - 0x89

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Router Renumbering<=
/pre>
```

=20

Message

=20

    138 - 0x8A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ICMPv6 Node Information =
Query
```

=20

Message

=20

    139 - 0x8B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ICMPv6 Node Information =
Response
```

=20

Message

=20

    140 - 0x8C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Inverse Neighbor Di=
scovery Solicitation Message
```

=20

Message

=20

    141 - 0x8D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Inverse Neighbor Di=
scovery Advertisement Message
```

=20

Message

=20

    142 - 0x8E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Home Agent Address =
Discovery Request Message
```

=20

Message

=20

    144 - 0x90

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Home Agent Address =
Discovery Reply Message
```

=20

Message

=20

    145 - 0x91

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Mobile Prefix Solic=
itation
```

=20

Message

=20

    146 - 0x92

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Mobile Prefix Adver=
tisement
```

=20

Message

=20

    147 - 0x93

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Certification Path =
Solicitation Message
```

=20

Message

=20

    148 - 0x94

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Certification Path =
Advertisement Message
```

=20

Message

=20

    149 - 0x95

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router Ad=
vertisement
```

=20

Message

=20

    151 - 0x97

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router So=
licitation
```

=20

Message

=20

    152 - 0x98

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6 Multicast Router Te=
rmination
```

=20

Message

=20

    153 - 0x99

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FMIPv6 Messages
```

=20

Message

=20

    154 - 0x9A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RFC3692-style Experiment=
 1
```

=20

Error

=20

    253 - 0xFD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RFC3692-style Experiment=
 2
```

=20

Error

=20

    254 - 0xFE

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20

### Type [ipfamily](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"ipfamily-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
No IP Address
```

=20

    None

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv4
```

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
IPv6
```

=20

    6 - 0x6

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [ipprotocol](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"ipprotocol-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
icmp
```

=20

    1 - 0x1

=20

Internet control message protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
igmp
```

=20

    2 - 0x2

=20

Internet group management

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ggp
```

=20

    3 - 0x3

=20

Gateway-gateway protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipencap
```

=20

    4 - 0x4

=20

Ip encapsulated in ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
st
```

=20

    5 - 0x5

=20

St datagram mode

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
tcp
```

=20

    6 - 0x6

=20

Transmission control protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
cbt
```

=20

    7 - 0x7

=20

Cbt

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
egp
```

=20

    8 - 0x8

=20

Exterior gateway protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
igp
```

=20

    9 - 0x9

=20

Any private interior gateway (used by cisco for igrp)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
bbn-rcc-mon
```

=20

    10 - 0xA

=20

Bbn rcc monitoring

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
nvp-ii
```

=20

    11 - 0xB

=20

Network voice protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
pup
```

=20

    12 - 0xC

=20

Parc universal packet protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
argus
```

=20

    13 - 0xD

=20

Argus

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
emcom
```

=20

    14 - 0xE

=20

Emcon

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
xnet
```

=20

    15 - 0xF

=20

Cross net debugger

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
chaos
```

=20

    16 - 0x10

=20

Chaos

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
udp
```

=20

    17 - 0x11

=20

User datagram protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mux
```

=20

    18 - 0x12

=20

Multiplexing

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
dcn-meas
```

=20

    19 - 0x13

=20

Dcn measurement subsystems

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
hmp
```

=20

    20 - 0x14

=20

Host monitoring protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
prm
```

=20

    21 - 0x15

=20

Packet radio measurement

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
xns-idp
```

=20

    22 - 0x16

=20

Xerox ns idp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
trunk-1
```

=20

    23 - 0x17

=20

Trunk-1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
trunk-2
```

=20

    24 - 0x18

=20

Trunk-2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
leaf-1
```

=20

    25 - 0x19

=20

Leaf-1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
leaf-2
```

=20

    26 - 0x1A

=20

Leaf-2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
rdp
```

=20

    27 - 0x1B

=20

Reliable data protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
irtp
```

=20

    28 - 0x1C

=20

Internet reliable transaction

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
iso-tp4
```

=20

    29 - 0x1D

=20

Iso transport protocol class 4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
netblt
```

=20

    30 - 0x1E

=20

Bulk data transfer protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mfe-nsp
```

=20

    31 - 0x1F

=20

Mfe network services protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
merit-inp
```

=20

    32 - 0x20

=20

Merit internodal protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
dccp
```

=20

    33 - 0x21

=20

Datagram congestion control protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
3pc
```

=20

    34 - 0x22

=20

Third party connect protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
idpr
```

=20

    35 - 0x23

=20

Inter-domain policy routing protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
xtp
```

=20

    36 - 0x24

=20

Xpress transfer protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ddp
```

=20

    37 - 0x25

=20

Datagram delivery protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
idpr-cmtp
```

=20

    38 - 0x26

=20

Idpr control message transport

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
tp++
```

=20

    39 - 0x27

=20

Tp++ transport protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
il
```

=20

    40 - 0x28

=20

Il transport protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6
```

=20

    41 - 0x29

=20

Ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sdrp
```

=20

    42 - 0x2A

=20

Source demand routing protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6-route
```

=20

    43 - 0x2B

=20

Routing header for ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6-frag
```

=20

    44 - 0x2C

=20

Fragment header for ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
idrp
```

=20

    45 - 0x2D

=20

Inter-domain routing protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
rsvp
```

=20

    46 - 0x2E

=20

Reservation protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
gre
```

=20

    47 - 0x2F

=20

General routing encapsulation

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
dsr
```

=20

    48 - 0x30

=20

Dynamic source routing protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
bna
```

=20

    49 - 0x31

=20

Bna

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
esp
```

=20

    50 - 0x32

=20

Encap security payload

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ah
```

=20

    51 - 0x33

=20

Authentication header

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
i-nlsp
```

=20

    52 - 0x34

=20

Integrated net layer security tuba

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
swipe
```

=20

    53 - 0x35

=20

Ip with encryption

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
narp
```

=20

    54 - 0x36

=20

Nbma address resolution protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mobile
```

=20

    55 - 0x37

=20

Ip mobility

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
tlsp
```

=20

    56 - 0x38

=20

Transport layer security protocol using kryptonet key managem= ent

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
skip
```

=20

    57 - 0x39

=20

Skip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6-icmp
```

=20

    58 - 0x3A

=20

Icmp for ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6-nonxt
```

=20

    59 - 0x3B

=20

No next header for ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipv6-opts
```

=20

    60 - 0x3C

=20

Destination options for ipv6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
anyhost
```

=20

    61 - 0x3D

=20

Any host internal protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
cftp
```

=20

    62 - 0x3E

=20

Cftp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
anylan
```

=20

    63 - 0x3F

=20

Any local network

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sat-expak
```

=20

    64 - 0x40

=20

Satnet and backroom expak

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
kryptolan
```

=20

    65 - 0x41

=20

Kryptolan

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
rvd
```

=20

    66 - 0x42

=20

Mit remote virtual disk protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ippc internet
```

=20

    67 - 0x43

=20

Internet pluribus packet core

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
anydfs
```

=20

    68 - 0x44

=20

Any distributed file system

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sat-mon
```

=20

    69 - 0x45

=20

Satnet monitoring

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
visa
```

=20

    70 - 0x46

=20

Visa protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipcv
```

=20

    71 - 0x47

=20

Internet packet core utility

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
cpnx
```

=20

    72 - 0x48

=20

Computer protocol network executive

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
rspf
```

=20

    73 - 0x49

=20

Radio shortest path first (officially cphb, computer protocol= heart
beat

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
br-sat-mon
```

=20

    76 - 0x4C

=20

Backroom satnet monitoring

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sun-nd
```

=20

    77 - 0x4D

=20

Sun nd protocol-temporary

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
wb-mon
```

=20

    78 - 0x4E

=20

Wideband monitoring

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
wb-expak
```

=20

    79 - 0x4F

=20

Wideband expak

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
iso-ip
```

=20

    80 - 0x50

=20

Iso internet protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
vmtp
```

=20

    81 - 0x51

=20

Versatile message transport

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
secure-vmtp
```

=20

    82 - 0x52

=20

Versatile message transport

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
vines
```

=20

    83 - 0x53

=20

Vines

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ttp
```

=20

    84 - 0x54

=20

Ttp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
msfnet-igp
```

=20

    85 - 0x55

=20

Msfnet-igp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
dgp
```

=20

    86 - 0x56

=20

Dissimilar gateway protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
tcf
```

=20

    87 - 0x57

=20

Tcf

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
eigrp
```

=20

    88 - 0x58

=20

Enhanced interior routing protocol (cisco)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ospf
```

=20

    89 - 0x59

=20

Open shortest path first igp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sprite-rpc
```

=20

    90 - 0x5A

=20

Sprite rpc protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
larp
```

=20

    91 - 0x5B

=20

Locus address resolution protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mtp
```

=20

    92 - 0x5C

=20

Multicast transport protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ax.25
```

=20

    93 - 0x5D

=20

Ax.25 frames

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipip
```

=20

    94 - 0x5E

=20

Ip-within-ip encapsulation protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
micp
```

=20

    95 - 0x5F

=20

Mobile internetworking control pro.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
scc-sp
```

=20

    96 - 0x60

=20

Semaphore communications sec. pro.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
etherip
```

=20

    97 - 0x61

=20

Ethernet-within-ip encapsulation

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
anyprivenc
```

=20

    98 - 0x62

=20

Any private encryption scheme

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
gmtp
```

=20

    100 - 0x64

=20

Gmtp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ifmp
```

=20

    101 - 0x65

=20

Ipsilon flow management protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
pnni
```

=20

    102 - 0x66

=20

Pnni over ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
pim
```

=20

    103 - 0x67

=20

Protocol independent multicast

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
aris
```

=20

    104 - 0x68

=20

Aris

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
scps
```

=20

    105 - 0x69

=20

Scps

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
qnx
```

=20

    106 - 0x6A

=20

Qnx

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
a/n
```

=20

    107 - 0x6B

=20

Active networks

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipcomp
```

=20

    108 - 0x6C

=20

Ip payload compression protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
snp
```

=20

    109 - 0x6D

=20

Sitara networks protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
compaq-peer
```

=20

    110 - 0x6E

=20

Compaq peer protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ipx-in-ip
```

=20

    111 - 0x6F

=20

Ipx in ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
vrrp
```

=20

    112 - 0x70

=20

Virtual router redundancy protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
pgm
```

=20

    113 - 0x71

=20

Pgm reliable transport protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
any0hop
```

=20

    114 - 0x72

=20

Any 0-hop protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
l2tp
```

=20

    115 - 0x73

=20

Layer two tunneling protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ddx
```

=20

    116 - 0x74

=20

D-ii data exchange (ddx)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
iatp
```

=20

    117 - 0x75

=20

Interactive agent transfer protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
stp
```

=20

    118 - 0x76

=20

Schedule transfer protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
srp
```

=20

    119 - 0x77

=20

Spectralink radio protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
uti
```

=20

    120 - 0x78

=20

Uti

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
smp
```

=20

    121 - 0x79

=20

Simple message protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sm
```

=20

    122 - 0x7A

=20

Sm

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ptp
```

=20

    123 - 0x7B

=20

Performance transparency protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
isis
```

=20

    124 - 0x7C

=20

Isis over ipv4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
fire
```

=20

    125 - 0x7D

=20

Fire

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
crtp
```

=20

    126 - 0x7E

=20

Combat radio transport protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
crudp
```

=20

    127 - 0x7F

=20

Combat radio user datagram

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sscopmce
```

=20

    128 - 0x80

=20

Sscopmce

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
iplt
```

=20

    129 - 0x81

=20

Iplt

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sps
```

=20

    130 - 0x82

=20

Secure packet shield

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
pipe
```

=20

    131 - 0x83

=20

Private ip encapsulation within ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
sctp
```

=20

    132 - 0x84

=20

Stream control transmission protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
fc
```

=20

    133 - 0x85

=20

Fibre channel

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
rsvp-e2e-ignore
```

=20

    134 - 0x86

=20

Rsvp-e2e-ignore

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mobilityheader
```

=20

    135 - 0x87

=20

Mobility header

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
udplite
```

=20

    136 - 0x88

=20

Udp-lite

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
mpls-in-ip
```

=20

    137 - 0x89

=20

Mpls-in-ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
manet
```

=20

    138 - 0x8A

=20

Manet protocols

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
hip
```

=20

    139 - 0x8B

=20

Host identity protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
shim6
```

=20

    140 - 0x8C

=20

Shim6 protocol

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
testing1
```

=20

    253 - 0xFD

=20

Use for experimentation and testing

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
testing2
```

=20

    254 - 0xFE

=20

Use for experimentation and testing

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [keytype](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"keytype-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RSA
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EC
```

=20

    1 - 0x1

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [layer](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"layer-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Citrix
```

=20

    citrix

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Citrix Channels
```

=20

    citrix_channels

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
DNS
```

=20

    dns

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HTTP
```

=20

    http

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
ICMP
```

=20

    icmp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Non IP
```

=20

    non_ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Other IP
```

=20

    other_ip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
CIFS
```

=20

    smb

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Databases
```

=20

    databases

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TCP
```

=20

    tcp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
UDP
```

=20

    udp

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
VoIP
```

=20

    voip

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TLS
```

=20

    tls

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20

### Type [os](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"os-items\"}

=20

Name

=20

Category

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Unknown
```

=20

Unknown

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:3.x
```

=20

linux

=20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.6.x
```

=20

linux

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.4.x
```

=20

linux

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.2.x
```

=20

linux

=20

    4 - 0x4

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.0
```

=20

linux

=20

    5 - 0x5

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:3.x (loopback)
```

=20

linux

=20

    6 - 0x6

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.6.x (loopback)
```

=20

linux

=20

    7 - 0x7

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.4.x (loopback)
```

=20

linux

=20

    8 - 0x8

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.2.x (loopback)
```

=20

linux

=20

    9 - 0x9

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.6.x (google craw=
ler)
```

=20

linux

=20

    10 - 0xA

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:Android
```

=20

mobile

=20

    11 - 0xB

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:3.x (generic)
```

=20

linux

=20

    12 - 0xC

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.4.x-2.6.x (gener=
ic)
```

=20

linux

=20

    13 - 0xD

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.2.x-3.x (generic=
)
```

=20

linux

=20

    14 - 0xE

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.2.x-3.x (generic=
, no ts)
```

=20

linux

=20

    15 - 0xF

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.2.x-3.x (generic=
, barebone)
```

=20

linux

=20

    16 - 0x10

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:XP
```

=20

windows

=20

    17 - 0x11

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:7 or 8
```

=20

windows

=20

    18 - 0x12

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:7 (Websense craw=
ler)
```

=20

windows

=20

    19 - 0x13

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:NT kernel 5.x (g=
eneric)
```

=20

windows

=20

    20 - 0x14

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:NT kernel 6.x (g=
eneric)
```

=20

windows

=20

    21 - 0x15

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:NT kernel (gener=
ic)
```

=20

windows

=20

    22 - 0x16

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mac OS X:10.x
```

=20

macos

=20

    23 - 0x17

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
iOS:iPhone or iPad
```

=

=20

mobile

=20

    24 - 0x18

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mac OS X (generic)
```

=

=20

macos

=20

    25 - 0x19

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD:9.x
```

=20

bsd

=20

    26 - 0x1A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD:8.x
```

=20

bsd

=20

    27 - 0x1B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD (generic)
```

\<= /td\> =20

bsd

=20

    28 - 0x1C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenBSD:3.x
```

=20

bsd

=20

    29 - 0x1D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenBSD:4.x-5.x
```

=20

bsd

=20

    30 - 0x1E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Solaris:8
```

=20

solaris

=20

    31 - 0x1F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Solaris:10
```

=20

solaris

=20

    32 - 0x20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenVMS:8.x
```

=20

other

=20

    33 - 0x21

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenVMS:7.x
```

=20

other

=20

    34 - 0x22

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NeXTSTEP
```

=20

other

=20

    35 - 0x23

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Tru64:4.x
```

=20

other

=20

    36 - 0x24

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NMap:SYN scan
```

=20

Unknown

=20

    37 - 0x25

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NMap:OS detection
```

\<= /td\> =20

Unknown

=20

    38 - 0x26

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
p0f:sendsyn utility
```

=20

Unknown

=20

    39 - 0x27

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Blackberry
```

=20

mobile

=20

    40 - 0x28

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nintendo:3DS
```

=20

other

=20

    41 - 0x29

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Nintendo:Wii
```

=20

other

=20

    42 - 0x2A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
BaiduSpider
```

=20

other

=20

    43 - 0x2B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:3.x (syn+ack)
```

=20

linux

=20

    44 - 0x2C

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.4-2.6 (syn+ack)<=
/pre>
```

=20

linux

=20

    45 - 0x2D

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.4.x (syn+ack)
```

=20

linux

=20

    46 - 0x2E

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Linux:2.6.x (syn+ack)
```

=20

linux

=20

    47 - 0x2F

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:XP (syn+ack)
```

=20

windows

=20

    48 - 0x30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Windows:7 or 8 (syn+ack)=
```

=20

windows

=20

    49 - 0x31

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD:9.x (syn+ack)
```

=20

bsd

=20

    50 - 0x32

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD:8.x (syn+ack)
```

=20

bsd

=20

    51 - 0x33

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
FreeBSD:8.x-9.x (syn+ack=
)
```

=20

bsd

=20

    52 - 0x34

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenBSD:5.x (syn+ack)
```

=20

bsd

=20

    53 - 0x35

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Mac OS X:10.x (syn+ack)<=
/pre>
```

=20

macos

=20

    54 - 0x36

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Solaris:6 (syn+ack)
```

=20

solaris

=20

    55 - 0x37

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Solaris:8 (syn+ack)
```

=20

solaris

=20

    56 - 0x38

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Solaris:10 (syn+ack)
```

=20

solaris

=20

    57 - 0x39

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
HP-UX:11.x (syn+ack)
```

=20

other

=20

    58 - 0x3A

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
OpenVMS:7.x (syn+ack)
```

=20

other

=20

    59 - 0x3B

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Tru64:4.x (syn+ack)
```

=20

other

=20

    60 - 0x3C

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20

### Type [pktsourcekind](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"pktsourcekind-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Missing
```

=20

    0 - 0x0

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
Network Interface
```

\<= /td\> =20

    1 - 0x1

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPCAPD Remote Capture
```

=20

    2 - 0x2

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
PCAP File
```

=20

    3 - 0x3

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NetFlow
```

=20

    4 - 0x4

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20

### Type [smbcommand](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"smbcommand-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_create_directory=
```

=20

    1:0

=20

Create a new directory on the server, relative to a connected= share.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_delete_directory=
```

=20

    1:1

=20

Delete an empty directory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_open
```

=20

    1:2

=20

Open an existing regular file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_create
```

=20

    1:3

=20

Create and open a new file or open and truncate an existing f= ile to
zero length.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_close
```

=20

    1:4

=20

Close an instance of an object associated with a valid FID. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_flush
```

=20

    1:5

=20

Request that the server flush data and allocation information= for a
specified file or for all open files under the session.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_delete
```

=20

    1:6

=20

Delete one or more regular files.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_rename
```

=20

    1:7

=20

Change the name of one or more files or directories

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_query_informatio=
n
```

=20

    1:8

=20

Obtain attribute information about a file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_set_information<=
/pre>
```

=20

    1:9

=20

Change the attribute information of a regular file or directo= ry.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read
```

=20

    1:10

=20

Read bytes from a regular file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write
```

=20

    1:11

=20

Write bytes to a regular file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_lock_byte_range<=
/pre>
```

=20

    1:12

=20

Explicitly lock a contiguous range of bytes in an open regula= r file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_unlock_byte_rang=
e
```

=20

    1:13

=20

Explicitly unlock a contiguous range of bytes in an open regu= lar file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_create_temporary=
```

=20

    1:14

=20

Create a file for temporary use by the client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_create_new
```

=

=20

    1:15

=20

Create a new file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_check_directory<=
/pre>
```

=20

    1:16

=20

Verify that a specified path resolves to a valid directory on= the
server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_process_exit
```

=20

    1:17

=20

Sent by the client to indicate the catastrophic failure of a = client
process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_seek
```

=20

    1:18

=20

Position a file pointer within a regular file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_lock_and_read
```

=20

    1:19

=20

Explicitly lock and read bytes from a regular file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_and_unlock=
```

=20

    1:20

=20

Write to a range of bytes and then unlock them.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read_raw
```

=20

    1:26

=20

Request raw data from the file or named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read_mpx
```

=20

    1:27

=20

This is a specialized read command intended to maximize the p=
erformance of reading large blocks of data from a regular file while
allowi= ng for other operations to take place between the client and the
server. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read_mpx_seconda=
ry
```

=20

    1:28

=20

This command is no longer used in conjunction with the SMB\_CO=
M\_READ\_MPX command.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_raw
```

\<= /td\> =20

    1:29

=20

This is a specialized write command intended to maximize perf= ormance
when writing large blocks of data to an open regular file, a named =
pipe, a device, or spooled output.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_mpx
```

\<= /td\> =20

    1:30

=20

SMB\_COM\_WRITE\_MPX is used to maximize performance when writin= g a
large block of data from the client to the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_mpx_second=
ary
```

=20

    1:31

=20

This command is no longer used in conjunction with the SMB\_CO=
M\_WRITE\_MPX command.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_complete
```

=20

    1:32

=20

This command is sent by the server as the final response of a= n
SMB\_COM\_WRITE\_RAW command sequence.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_query_server
```

=20

    1:33

=20

This command was introduced in the NT LAN Manager dialect, an= d was
reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_set_information2=
```

=20

    1:34

=20

Set attribute information about an open file. This command al= lows the
client to set more attribute information for the file than the SMB=
\_COM\_SET\_INFORMATION command.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_query_informatio=
n2
```

=20

    1:35

=20

Obtain attribute information about an open file. This command= provides
more information about the file than the SMB\_COM\_QUERY\_INFORMATIO= N
command.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_locking_andx
```

=20

    1:36

=20

Explicitly lock and/or unlock a contiguous range of bytes in = a regular
file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_transaction
```

=20

    1:37

=20

This command serves as the transport for the Transaction Subp= rotocol
Commands. These commands operate on mailslots and named pipes, whic= h
are interprocess communication endpoints within the CIFS file system.
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_transaction_seco=
ndary
```

=20

    1:38

=20

The SMB\_COM\_TRANSACTION\_SECONDARY command is used to complete= a data
transfer initiated by an SMB\_COM\_TRANSACTION Request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_ioctl
```

=20

    1:39

=20

This command delivers a device- or file-specific IOCTL reques= t to a
server, and a device- or file-specific IOCTL response to the request=
er.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_ioctl_secondary<=
/pre>
```

=20

    1:40

=20

This command is a companion to SMB\_COM\_IOCTL.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_copy
```

=20

    1:41

=20

Perform server-side file copies

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_move
```

=20

    1:42

=20

Move files on the server

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_echo
```

=20

    1:43

=20

Sent by the client to test the transport layer connection wit= h the
server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_and_close<=
/pre>
```

=20

    1:44

=20

Write to a range of bytes and then close the file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_open_andx
```

\<= /td\> =20

    1:45

=20

Open a new file or open an existing regular file and chain ad= ditional
messages along with the request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read_andx
```

\<= /td\> =20

    1:46

=20

Read bytes from a regular file, a named pipe, or a directly a= ccessible
device such as a serial port (COM) or printer port (LPT).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_andx
```

=

=20

    1:47

=20

Write bytes to a regular file, a named pipe, or a directly ac= cessible
I/O device such as a serial port (COM) or printer port (LPT).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_new_file_size
```

=20

    1:48

=20

This command was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_close_and_tree_d=
isc
```

=20

    1:49

=20

This command was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_transaction2
```

=20

    1:50

=20

Provide support for a richer set of server-side file system s= emantics.
The \"Trans2 subcommands\", as they are called, allow clients to se= t
and retrieve Extended Attribute key/value pairs, make use of long file
na= mes, and perform directory searches, among other tasks.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_transaction2_sec=
ondary
```

=20

    1:51

=20

The SMB\_COM\_TRANSACTION2\_SECONDARY command is used to complet= e a
data transfer initiated by an SMB\_COM\_TRANSACTION2 request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_find_close2
```

=20

    1:52

=20

Close a search handle that was created by a TRANS2\_FIND\_FIRST= 2
subcommand.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_find_notify_clos=
e
```

=20

    1:53

=20

Close a directory search handle that was created by a TRANS2\_=
FIND\_NOTIFY\_FIRST subcommand request to the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_tree_connect
```

=20

    1:112

=20

Establish a client connection to a server share.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_tree_disconnect<=
/pre>
```

=20

    1:113

=20

Disconnect client access to a server resource.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_negociate
```

\<= /td\> =20

    1:114

=20

Initiate an SMB connection between the client and the server.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_session_setup_an=
dx
```

=20

    1:115

=20

Configure an SMB session.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_logoff_andx
```

=20

    1:116

=20

Log off the user connection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_tree_connect_and=
x
```

=20

    1:117

=20

Establish a client connection to a server share.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_security_package=
_andx
```

=20

    1:126

=20

Negotiate security packages and related information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_query_informatio=
n_disk
```

=20

    1:128

=20

Obtain the capacity and remaining free space on the volume ho= sting the
subtree indicated by the tree\_id.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_search
```

=20

    1:129

=20

Search a directory for files or other objects that have names= matching
a given wildcard template.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_find
```

=20

    1:130

=20

This command is identical in structure and purpose to SMB\_COM=
\_SEARCH. The only difference is that SMB\_COM\_FIND is paired with the
SMB\_CO= M\_FIND\_CLOSE command, which allows the client to explicitly
close a search = operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_find_unique
```

=20

    1:131

=20

The use of this command, as opposed to SMB\_COM\_SEARCH or SMB\_=
COM\_FIND, indicates to the server that it need not maintain a search
contex= t or any other state. The SMB\_COM\_FIND\_UNIQUE command is
single-use. No fol= low-up commands are permitted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_find_close
```

=

=20

    1:132

=20

This command is used to close a directory search opened by SM=
B\_COM\_FIND.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_nt_transact
```

=20

    1:160

=20

SMB\_COM\_NT\_TRANSACT subcommands extend the file system featur= e
access offered by SMB\_COM\_TRANSACTION2, and also allow for the
transfer o= f very large parameter and data blocks.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_nt_transact_seco=
ndary
```

=20

    1:161

=20

The SMB\_COM\_NT\_TRANSACT\_SECONDARY command is used to complete= a
data transfer initiated by an SMB\_COM\_NT\_TRANSACT request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_nt_create_andx
```

=20

    1:162

=20

This command is used to create and open a new file, or to ope= n an
existing file, or to open and truncate an existing file to zero length=
, or to create a directory, or to create a connection to a named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_nt_cancel
```

\<= /td\> =20

    1:164

=20

Request that a currently pending request be canceled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_nt_rename
```

\<= /td\> =20

    1:165

=20

Create hard links on the remote server, to perform an in-plac= e file
rename, and to move a file within its existing path hierarchy.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_open_print_file<=
/pre>
```

=20

    1:192

=20

Create a print queue spool file. The file will be queued to t= he
printer when closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_print_file=
```

=20

    1:193

=20

Write data to an open print queue spool file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_close_print_file=
```

=20

    1:194

=20

Closes the specified print queue spool file, causing the serv= er to
queue the file for printing.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_get_print_file
```

=20

    1:195

=20

Generate a list of items currently in a print queue associate= d with
the specified tree\_id.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_read_bulk
```

\<= /td\> =20

    1:216

=20

This command was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_bulk
```

=

=20

    1:217

=20

This command was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_write_bulk_data<=
/pre>
```

=20

    1:218

=20

This command was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_invalid
```

=20

    1:254

=20

Reserved value that specifically indicates an invalid command= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_com_no_andx_command<=
/pre>
```

=20

    1:255

=20

In the earliest SMB Protocol specifications (see \[IBM-SMB\]), = this
command code was reserved for proprietary protocol extensions.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_negotiate
```

=

=20

    2:0

=20

Notify the server what dialects of the SMB 2 Protocol the cli= ent
understands.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_session_setup
```

=20

    2:1

=20

Request a new authenticated session within a new or existing = SMB 2
Protocol transport connection to the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_logoff
```

=20

    2:2

=20

Request termination of a particular session.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_tree_connect
```

=20

    2:3

=20

Request access to a particular share on the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_tree_disconnect=
```

=20

    2:4

=20

Request that the tree connect that is specified be disconnect= ed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_create
```

=20

    2:5

=20

Request either creation of or access to a file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_close
```

=20

    2:6

=20

Close an instance of a file that was opened previously with a=
successful SMB2 CREATE Request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_flush
```

=20

    2:7

=20

Request that a server flush all cached file information for a= specified
open of a file to the persistent store that backs the file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_read
```

=20

    2:8

=20

Request a read operation on the file that is specified by the= FileId.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_write
```

=20

    2:9

=20

Write data to the file or named pipe on the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_lock
```

=20

    2:10

=20

Either lock or unlock portions of a file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_ioctl
```

=20

    2:11

=20

Issue an implementation-specific file system control or devic= e control
(FSCTL/IOCTL) command across the network.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_cancel
```

=20

    2:12

=20

Cancel a previously sent message on the same SMB2 transport c=
onnection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_echo
```

=20

    2:13

=20

Determine whether a server is processing requests.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_query_directory=
```

=20

    2:14

=20

Obtain a directory enumeration on a directory open.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_change_notify
```

=20

    2:15

=20

request change notifications on a directory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_query_info
```

=20

    2:16

=20

Request information on a file, named pipe, or underlying volu= me.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_set_info
```

\<= /td\> =20

    2:17

=20

Set information on a file or underlying object store.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB2_com_oplock_break
```

=20

    2:18

=20

Sent by the server when the underlying object store indicates= that an
opportunistic lock (oplock) is being broken, representing a change= in
the oplock level.

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [smbstatus](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"smbstatus-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Category

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_ok
```

=20

Success

=20

    0 - 0x0

=20

The operation completed successfully.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abandoned
```

=20

Success

=20

    128 - 0x80

=20

The caller attempted to wait for a mutex that has been abando= ned.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_user_apc
```

=

=20

Success

=20

    192 - 0xC0

=20

A user-mode APC was delivered before the given Interval expir= ed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_kernel_apc
```

=20

Success

=20

    256 - 0x100

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_alerted
```

\<= /td\> =20

Success

=20

    257 - 0x101

=20

The delay completed because the thread was alerted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_timeout
```

\<= /td\> =20

Success

=20

    258 - 0x102

=20

The given Timeout interval expired.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pending
```

\<= /td\> =20

Success

=20

    259 - 0x103

=20

The operation that was requested is pending completion.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reparse
```

\<= /td\> =20

Success

=20

    260 - 0x104

=20

A reparse should be performed by the Object Manager because t= he name
of the file resulted in a symbolic link.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_more_entries
```

=20

Success

=20

    261 - 0x105

=20

Returned by enumeration APIs to indicate more information is = available
to successive calls.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_all_assign=
ed
```

=20

Success

=20

    262 - 0x106

=20

Indicates not all privileges or groups that are referenced ar= e
assigned to the caller. This allows, for example, all privileges to be
di= sabled without having to know exactly which privileges are assigned.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_some_not_mappe=
d
```

=20

Success

=20

    263 - 0x107

=20

Some of the information to be translated has not been transla= ted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_oplock_break_i=
n_progress
```

=20

Success

=20

    264 - 0x108

=20

An open/create operation completed while an opportunistic loc= k
(oplock) break is underway.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_volume_mounted=
```

=20

Success

=20

    265 - 0x109

=20

A new volume has been mounted by a file system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_rxact_committe=
d
```

=20

Success

=20

    266 - 0x10A

=20

This success level status indicates that the transaction stat= e already
exists for the registry subtree but that a transaction commit was=
previously aborted. The commit has now been completed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_notify_cleanup=
```

=20

Success

=20

    267 - 0x10B

=20

Indicates that a notify change request has been completed due= to
closing the handle that made the notify change request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_notify_enum_d=
ir
```

=20

Warning

=20

    268 - 0x10C

=20

Indicates that a notify change request is being completed and= that the
information is not being returned in the caller\'s buffer. The cal= ler
now needs to enumerate the files to find the changes.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_quotas_for_=
account
```

=20

Success

=20

    269 - 0x10D

=20

{No Quotas} No system quota limits are specifically set for t= his
account.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_primary_transp=
ort_connect_failed
```

=20

Success

=20

    270 - 0x10E

=20

{Connect Failure on Primary Transport} An attempt was made to= connect
to the remote server on the primary transport, but the connection =
failed. The computer WAS able to connect on a secondary transport.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_page_fault_tra=
nsition
```

=20

Success

=20

    272 - 0x110

=20

The page fault was a transition fault.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_page_fault_dem=
and_zero
```

=20

Success

=20

    273 - 0x111

=20

The page fault was a demand zero fault.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_page_fault_cop=
y_on_write
```

=20

Success

=20

    274 - 0x112

=20

The page fault was a demand zero fault.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_page_fault_gua=
rd_page
```

=20

Success

=20

    275 - 0x113

=20

The page fault was a demand zero fault.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_page_fault_pag=
ing_file
```

=20

Success

=20

    276 - 0x114

=20

The page fault was satisfied by reading from a secondary stor= age
device.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cache_page_loc=
ked
```

=20

Success

=20

    277 - 0x115

=20

The cached page was locked during operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_crash_dump
```

=20

Success

=20

    278 - 0x116

=20

The crash dump exists in a paging file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_buffer_all_zer=
os
```

=20

Success

=20

    279 - 0x117

=20

The specified buffer contains all zeros.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reparse_object=
```

=20

Success

=20

    280 - 0x118

=20

A reparse should be performed by the Object Manager because t= he name
of the file resulted in a symbolic link.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_requi=
rements_changed
```

=20

Success

=20

    281 - 0x119

=20

The device has succeeded a query-stop and its resource requir= ements
have changed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_translation_co=
mplete
```

=20

Success

=20

    288 - 0x120

=20

The translator has translated these resources into the global= space and
no additional translations should be performed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_membership_=
evaluated_locally
```

=20

Success

=20

    289 - 0x121

=20

The directory service evaluated group memberships locally, be= cause it
was unable to contact a global catalog server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nothing_to_ter=
minate
```

=20

Success

=20

    290 - 0x122

=20

A process being terminated has no threads to terminate.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_process_not_in=
_job
```

=20

Success

=20

    291 - 0x123

=20

The specified process is not part of a job.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_process_in_job=
```

=20

Success

=20

    292 - 0x124

=20

The specified process is part of a job.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wait_for_oploc=
k
```

=20

Success

=20

    871 - 0x367

=20

An operation is blocked and waiting for an oplock.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_smb
```

=20

Error

=20

    65538 - 0x10002

=20

The debugger continued.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_bad_tid
```

=20

Error

=20

    327682 - 0x50002

=20

The TID is no longer valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_bad_fid
```

=20

Warning

=20

    393217 - 0x60001

=20

Invalid FID.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_invalid_a=
ccess
```

=20

Warning

=20

    786433 - 0xC0001

=20

Invalid open mode.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_bad_comma=
nd
```

=20

Error

=20

    1441794 - 0x160002

=20

An unknown SMB command code was received by the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_bad_uid
```

=20

Error

=20

    5963778 - 0x5B0002

=20

The UID specified is not known as a valid ID on this server s= ession.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_no_more_s=
ids
```

=20

Warning

=20

    7405569 - 0x710001

=20

Maximum number of searches has been exhausted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_invalid_l=
evel
```

=20

Warning

=20

    8126465 - 0x7C0001

=20

The InformationLevel supplied is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_negative_=
seek
```

=20

Warning

=20

    8585217 - 0x830001

=20

An attempt was made to seek to a negative absolute offset wit= hin a
file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_cancel_vi=
olation
```

=20

Warning

=20

    11337729 - 0xAD0001

=20

No lock request was outstanding for the supplied cancel regio= n.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_atomic_lo=
cks_not_supported
```

=20

Warning

=20

    11403265 - 0xAE0001

=20

The file system does not support atomic changes to the lock t= ype.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_use_mpx
```

=20

Error

=20

    16384002 - 0xFA0002

=20

Temporarily unable to support RAW mode transfers. Use MPX mod= e.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_use_stand=
ard
```

=20

Error

=20

    16449538 - 0xFB0002

=20

Temporarily unable to support RAW or MPX mode transfers. Use = standard
read/write.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_smb_continue_=
mpx
```

=20

Error

=20

    16515074 - 0xFC0002

=20

Continue in MPX mode. This error code is reserved for future = use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_cannot_co=
py
```

=20

Warning

=20

    17432577 - 0x10A0001

=20

The copy functions cannot be used.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_eas_didnt=
_fit
```

=20

Warning

=20

    18022401 - 0x1130001

=20

Either there are no extended attributes, or the available ext= ended
attributes did not fit into the response.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_os2_ea_access=
_denied
```

=20

Warning

=20

    65142785 - 0x3E20001

=20

Access to the extended attribute was denied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_object_name_ex=
ists
```

=20

Success

=20

    1073741824 - 0x40000000

=20

{Object Exists} An attempt was made to create an object but t= he object
name already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_thread_was_sus=
pended
```

=20

Success

=20

    1073741825 - 0x40000001

=20

{Thread Suspended} A thread termination occurred while the th= read was
suspended. The thread resumed, and termination proceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_working_set_li=
mit_range
```

=20

Success

=20

    1073741826 - 0x40000002

=20

{Working Set Range Error} An attempt was made to set the work= ing set
minimum or maximum to values that are outside the allowable range.\<=
/td\> =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_not_at_b=
ase
```

=20

Success

=20

    1073741827 - 0x40000003

=20

{Image Relocated} An image file could not be mapped at the ad= dress
that is specified in the image file. Local fixes must be performed on=
this image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_rxact_state_cr=
eated
```

=20

Success

=20

    1073741828 - 0x40000004

=20

This informational level status indicates that a specified re= gistry
subtree transaction state did not yet exist and had to be created. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_segment_notifi=
cation
```

=20

Success

=20

    1073741829 - 0x40000005

=20

{Segment Load} A virtual DOS machine (VDM) is loading, unload= ing, or
moving an MS-DOS or Win16 program segment image. An exception is ra=
ised so that a debugger can load, unload, or track symbols and
breakpoints = within these 16-bit segments.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_local_user_ses=
sion_key
```

=20

Success

=20

    1073741830 - 0x40000006

=20

{Local Session Key} A user session key was requested for a lo= cal
remote procedure call (RPC) connection. The session key that is returne=
d is a constant value and not unique to this connection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_current_di=
rectory
```

=20

Success

=20

    1073741831 - 0x40000007

=20

{Invalid Current Directory} The process cannot switch to the = startup
current directory. Select OK to set the current directory, or selec= t
CANCEL to exit.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_serial_more_wr=
ites
```

=20

Success

=20

    1073741832 - 0x40000008

=20

{Serial IOCTL Complete} A serial I/O operation was completed = by
another write to a serial port. (The IOCTL\_SERIAL\_XOFF\_COUNTER
reached z= ero.)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_registry_recov=
ered
```

=20

Success

=20

    1073741833 - 0x40000009

=20

{Registry Recovery} One of the files that contains the system= registry
data had to be recovered by using a log or alternate copy. The re=
covery was successful.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ft_read_recove=
ry_from_backup
```

=20

Success

=20

    1073741834 - 0x4000000A

=20

{Redundant Read} To satisfy a read request, the Windows&n= bsp;NT
fault-tolerant file system successfully read the requested data from= a
redundant copy. This was done because the file system encountered a
fail= ure on a member of the fault-tolerant volume but was unable to
reassign the= failing area of the device.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ft_write_recov=
ery
```

=20

Success

=20

    1073741835 - 0x4000000B

=20

{Redundant Write} To satisfy a write request, the Windows&= ;nbsp;NT
fault-tolerant file system successfully wrote a redundant copy of = the
information. This was done because the file system encountered a failur=
e on a member of the fault-tolerant volume but was unable to reassign
the f= ailing area of the device.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_serial_counter=
_timeout
```

=20

Success

=20

    1073741836 - 0x4000000C

=20

{Serial IOCTL Timeout} A serial I/O operation completed becau= se the
time-out period expired. (The IOCTL\_SERIAL\_XOFF\_COUNTER had not reac=
hed zero.)

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_null_lm_passwo=
rd
```

=20

Success

=20

    1073741837 - 0x4000000D

=20

{Password Too Complex} The Windows password is too complex to= be
converted to a LAN Manager password. The LAN Manager password that retu=
rned is a NULL string.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_machine_=
type_mismatch
```

=20

Success

=20

    1073741838 - 0x4000000E

=20

{Machine Type Mismatch} The image file is valid but is for a = machine
type other than the current machine. Select OK to continue, or CANC= EL
to fail the DLL load.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_receive_partia=
l
```

=20

Success

=20

    1073741839 - 0x4000000F

=20

{Partial Data Received} The network transport returned partia= l data to
its client. The remaining data will be sent later.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_receive_expedi=
ted
```

=20

Success

=20

    1073741840 - 0x40000010

=20

{Expedited Data Received} The network transport returned data= to its
client that was marked as expedited by the remote system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_receive_partia=
l_expedited
```

=20

Success

=20

    1073741841 - 0x40000011

=20

{Partial Expedited Data Received} The network transport retur= ned
partial data to its client and this data was marked as expedited by the=
remote system. The remaining data will be sent later.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_event_done
```

=20

Success

=20

    1073741842 - 0x40000012

=20

{TDI Event Done} The TDI indication has completed successfull= y.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_event_pending<=
/pre>
```

=20

Success

=20

    1073741843 - 0x40000013

=20

{TDI Event Pending} The TDI indication has entered the pendin= g state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_checking_file_=
system
```

=20

Success

=20

    1073741844 - 0x40000014

=20

Checking file system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_fatal_app_exit=
```

=20

Success

=20

    1073741845 - 0x40000015

=20

{Fatal Application Exit}

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_predefined_han=
dle
```

=20

Success

=20

    1073741846 - 0x40000016

=20

The specified registry key is referenced by a predefined hand= le.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_was_unlocked
```

=20

Success

=20

    1073741847 - 0x40000017

=20

{Page Unlocked} The page protection of a locked page was chan= ged to
\'No Access\' and the page was unlocked from memory and from the proce=
ss.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_service_notifi=
cation
```

=20

Success

=20

    1073741848 - 0x40000018

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_was_locked
```

=20

Success

=20

    1073741849 - 0x40000019

=20

{Page Locked} One of the pages to lock was already locked. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_log_hard_error=
```

=20

Success

=20

    1073741850 - 0x4000001A

=20

Application popup

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_already_win32<=
/pre>
```

=20

Success

=20

    1073741851 - 0x4000001B

=20

A Win32 process already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_unsimulat=
e
```

=20

Success

=20

    1073741852 - 0x4000001C

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_continue<=
/pre>
```

=20

Success

=20

    1073741853 - 0x4000001D

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_single_st=
ep
```

=20

Success

=20

    1073741854 - 0x4000001E

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_breakpoin=
t
```

=20

Success

=20

    1073741855 - 0x4000001F

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_exception=
_continue
```

=20

Success

=20

    1073741856 - 0x40000020

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_exception=
_lastchance
```

=20

Success

=20

    1073741857 - 0x40000021

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_exception=
_chain
```

=20

Success

=20

    1073741858 - 0x40000022

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_machine_=
type_mismatch_exe
```

=20

Success

=20

    1073741859 - 0x40000023

=20

{Machine Type Mismatch} The image file is valid but is for a = machine
type other than the current machine.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_yield_perfo=
rmed
```

=20

Success

=20

    1073741860 - 0x40000024

=20

A yield execution was performed and no thread was available t= o run.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_timer_resume_i=
gnored
```

=20

Success

=20

    1073741861 - 0x40000025

=20

The resume flag to a timer API was ignored.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_arbitration_un=
handled
```

=20

Success

=20

    1073741862 - 0x40000026

=20

The arbiter has deferred arbitration of these resources to it= s parent.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cardbus_not_su=
pported
```

=20

Success

=20

    1073741863 - 0x40000027

=20

The device has detected a CardBus card in its slot.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_createwx8=
6tib
```

=20

Success

=20

    1073741864 - 0x40000028

=20

An exception status code that is used by the Win32 x86 emulat= ion
subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mp_processor_m=
ismatch
```

=20

Success

=20

    1073741865 - 0x40000029

=20

The CPUs in this multiprocessor system are not all the same r= evision
level. To use all processors, the operating system restricts itself= to
the features of the least capable processor in the system. If problems =
occur with this system, contact the CPU manufacturer to see if this mix
of = processors is supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_hibernated
```

=20

Success

=20

    1073741866 - 0x4000002A

=20

The system was put into hibernation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resume_hiberna=
tion
```

=20

Success

=20

    1073741867 - 0x4000002B

=20

The system was resumed from hibernation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wake_system
```

=20

Success

=20

    1073742484 - 0x40000294

=20

The system has awoken.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_shutting_do=
wn
```

=20

Success

=20

    1073742704 - 0x40000370

=20

The directory service is shutting down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_uuid_local_only
```

=20

Success

=20

    1073872982 - 0x40020056

=20

A UUID that is valid only on this computer has been allocated= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_send_incomplete
```

=20

Success

=20

    1073873071 - 0x400200AF

=20

Some data remains to be sent in the request buffer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_guard_page_vio=
lation
```

=20

Warning

=20

    2147483649 - 0x80000001

=20

{EXCEPTION} Guard Page Exception A page of memory that marks = the end
of a data structure, such as a stack or an array, has been accessed= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_datatype_misal=
ignment
```

=20

Warning

=20

    2147483650 - 0x80000002

=20

{EXCEPTION} Alignment Fault A data type misalignment was dete= cted in a
load or store instruction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_breakpoint
```

=20

Warning

=20

    2147483651 - 0x80000003

=20

{EXCEPTION} Breakpoint A breakpoint has been reached.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_single_step
```

=20

Warning

=20

    2147483652 - 0x80000004

=20

{EXCEPTION} Single Step A single step or trace operation has = just been
completed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_buffer_overfl=
ow
```

=20

Warning

=20

    2147483653 - 0x80000005

=20

{Buffer Overflow} The data was too large to fit into the spec= ified
buffer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_no_more_files=
```

=20

Success

=20

    2147483654 - 0x80000006

=20

{No More Files} No more files were found which match the file=
specification. This is a warning status in specification but since it is
u= sed to end a query directory request, we consider it as an ok status.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wake_system_de=
bugger
```

=20

Warning

=20

    2147483655 - 0x80000007

=20

{Kernel Debugger Awakened} The system debugger was awakened b= y an
interrupt.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_handles_closed=
```

=20

Warning

=20

    2147483658 - 0x8000000A

=20

{Handles Closed} Handles to objects have been automatically c= losed
because of the requested operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_inheritance=
```

=20

Warning

=20

    2147483659 - 0x8000000B

=20

{Non-Inheritable ACL} An access control list (ACL) contains n= o
components that can be inherited.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_guid_substitut=
ion_made
```

=20

Warning

=20

    2147483660 - 0x8000000C

=20

{GUID Substitution} During the translation of a globally uniq= ue
identifier (GUID) to a Windows security ID (SID), no administratively
de= fined GUID prefix was found. A substitute prefix was used, which
will not c= ompromise system security. However, this may provide a more
restrictive acc= ess than intended.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_partial_copy
```

=20

Warning

=20

    2147483661 - 0x8000000D

=20

Because of protection conflicts, not all the requested bytes = could be
copied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_device_paper_=
empty
```

=20

Error

=20

    2147483662 - 0x8000000E

=20

{Out of Paper} The printer is out of paper.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_powered=
_off
```

=20

Warning

=20

    2147483663 - 0x8000000F

=20

{Device Power Is Off} The printer power has been turned off.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_off_lin=
e
```

=20

Warning

=20

    2147483664 - 0x80000010

=20

{Device Offline} The printer has been taken offline.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_busy
```

=20

Warning

=20

    2147483665 - 0x80000011

=20

{Device Busy} The device is currently busy.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_more_eas
```

=20

Warning

=20

    2147483666 - 0x80000012

=20

{No More EAs} No more extended attributes (EAs) were found fo= r the
file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_ea_nam=
e
```

=20

Warning

=20

    2147483667 - 0x80000013

=20

{Illegal EA} The specified extended attribute (EA) name conta= ins at
least one illegal character.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ea_list_incons=
istent
```

=20

Warning

=20

    2147483668 - 0x80000014

=20

{Inconsistent EA List} The extended attribute (EA) list is in=
consistent.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_ea_fla=
g
```

=20

Warning

=20

    2147483669 - 0x80000015

=20

{Invalid EA Flag} An invalid extended attribute (EA) flag was= set.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_verify_require=
d
```

=20

Warning

=20

    2147483670 - 0x80000016

=20

{Verifying Disk} The media has changed and a verify operation= is in
progress; therefore, no reads or writes may be performed to the devi=
ce, except those that are used in the verify operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_extraneous_inf=
ormation
```

=20

Warning

=20

    2147483671 - 0x80000017

=20

{Too Much Information} The specified access control list (ACL= )
contained more information than was expected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_rxact_commit_n=
ecessary
```

=20

Warning

=20

    2147483672 - 0x80000018

=20

This warning level status indicates that the transaction stat= e already
exists for the registry subtree, but that a transaction commit wa= s
previously aborted. The commit has NOT been completed but has not been
ro= lled back either; therefore, it may still be committed, if needed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_more_entrie=
s
```

=20

Warning

=20

    2147483674 - 0x8000001A

=20

{No More Entries} No more entries are available from an enume= ration
operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_filemark_detec=
ted
```

=20

Warning

=20

    2147483675 - 0x8000001B

=20

{Filemark Found} A filemark was detected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_media_changed<=
/pre>
```

=20

Warning

=20

    2147483676 - 0x8000001C

=20

{Media Changed} The media may have changed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bus_reset
```

=20

Warning

=20

    2147483677 - 0x8000001D

=20

{I/O Bus Reset} An I/O bus reset was detected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_end_of_media
```

=20

Warning

=20

    2147483678 - 0x8000001E

=20

{End of Media} The end of the media was encountered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_beginning_of_m=
edia
```

=20

Warning

=20

    2147483679 - 0x8000001F

=20

The beginning of a tape or partition has been detected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_media_check
```

=20

Warning

=20

    2147483680 - 0x80000020

=20

{Media Changed} The media may have changed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_setmark_detect=
ed
```

=20

Warning

=20

    2147483681 - 0x80000021

=20

A tape access reached a set mark.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_data_detect=
ed
```

=20

Warning

=20

    2147483682 - 0x80000022

=20

During a tape access, the end of the data written is reached.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_redirector_has=
_open_handles
```

=20

Warning

=20

    2147483683 - 0x80000023

=20

The redirector is in use and cannot be unloaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_server_has_ope=
n_handles
```

=20

Warning

=20

    2147483684 - 0x80000024

=20

The server is in use and cannot be unloaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_already_discon=
nected
```

=20

Warning

=20

    2147483685 - 0x80000025

=20

The specified connection has already been disconnected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_longjump
```

=

=20

Warning

=20

    2147483686 - 0x80000026

=20

A long jump has been executed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cleaner_cartri=
dge_installed
```

=20

Warning

=20

    2147483687 - 0x80000027

=20

A cleaner cartridge is present in the tape library.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_plugplay_query=
_vetoed
```

=20

Warning

=20

    2147483688 - 0x80000028

=20

The Plug and Play query operation was not successful.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unwind_consoli=
date
```

=20

Warning

=20

    2147483689 - 0x80000029

=20

A frame consolidation has been executed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_require=
s_cleaning
```

=20

Warning

=20

    2147484296 - 0x80000288

=20

The device has indicated that cleaning is necessary.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_door_op=
en
```

=20

Warning

=20

    2147484297 - 0x80000289

=20

The device has indicated that its door is open. Further opera= tions
require it closed and secured.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_unsuccessful<=
/pre>
```

=20

Warning

=20

    3221225473 - 0xC0000001

=20

{Operation Failed} The requested operation was unsuccessful.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_not_implement=
ed
```

=20

Error

=20

    3221225474 - 0xC0000002

=20

{Not Implemented} The requested operation is not implemented.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_info_=
class
```

=20

Warning

=20

    3221225475 - 0xC0000003

=20

{Invalid Parameter} The specified information class is not a = valid
information class for the specified object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_info_length_mi=
smatch
```

=20

Error

=20

    3221225476 - 0xC0000004

=20

The specified information record length does not match the le= ngth that
is required for the specified information class.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_access_violati=
on
```

=20

Error

=20

    3221225477 - 0xC0000005

=20

The instruction caused a memory access violation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_in_page_error<=
/pre>
```

=20

Error

=20

    3221225478 - 0xC0000006

=20

The required data was not placed into memory because of an I/= O error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pagefile_quota=
```

=20

Error

=20

    3221225479 - 0xC0000007

=20

The page file quota for the process has been exhausted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_handl=
e
```

=20

Warning

=20

    3221225480 - 0xC0000008

=20

An invalid HANDLE was specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_initial_st=
ack
```

=20

Error

=20

    3221225481 - 0xC0000009

=20

An invalid initial stack was specified in a call to NtCreateT= hread.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_initial_pc=
```

=20

Error

=20

    3221225482 - 0xC000000A

=20

An invalid initial start address was specified in a call to N=
tCreateThread.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_cid
```

=20

Error

=20

    3221225483 - 0xC000000B

=20

An invalid client ID was specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_timer_not_canc=
eled
```

=20

Error

=20

    3221225484 - 0xC000000C

=20

An attempt was made to cancel or set a timer that has an asso= ciated
APC and the specified thread is not the thread that originally set t= he
timer with an associated APC routine.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_param=
eter
```

=20

Warning

=20

    3221225485 - 0xC000000D

=20

An invalid parameter was passed to a service or function. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_no_such_devic=
e
```

=20

Warning

=20

    3221225486 - 0xC000000E

=20

A device that does not exist was specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_no_such_file<=
/pre>
```

=20

Warning

=20

    3221225487 - 0xC000000F

=20

{File Not Found} The file does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_devic=
e_request
```

=20

Warning

=20

    3221225488 - 0xC0000010

=20

The specified request is not a valid operation for the target= device.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_end_of_file
```

=20

Warning

=20

    3221225489 - 0xC0000011

=20

The end-of-file marker has been reached. There is no valid da= ta in the
file beyond this marker.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_wrong_volume<=
/pre>
```

=20

Error

=20

    3221225490 - 0xC0000012

=20

{Wrong Volume} The wrong volume is in the drive. Insert volum= e into
drive.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_no_media_in_d=
evice
```

=20

Error

=20

    3221225491 - 0xC0000013

=20

{No Disk} There is no disk in the drive. Insert a disk into d= rive.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unrecognized_m=
edia
```

=20

Error

=20

    3221225492 - 0xC0000014

=20

{Unknown Disk Format} The disk in drive is not formatted prop= erly.
Check the disk, and reformat it, if needed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_nonexistent_s=
ector
```

=20

Error

=20

    3221225493 - 0xC0000015

=20

{Sector Not Found} The specified sector does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_more_processi=
ng_required
```

=20

Warning

=20

    3221225494 - 0xC0000016

=20

{Still Busy} The specified I/O request packet (IRP) cannot be= disposed
of because the I/O operation is not complete.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_memory
```

=20

Error

=20

    3221225495 - 0xC0000017

=20

{Not Enough Quota} Not enough virtual memory or paging file q= uota is
available to complete the specified operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_conflicting_ad=
dresses
```

=20

Error

=20

    3221225496 - 0xC0000018

=20

{Conflicting Address Range} The specified address range confl= icts with
the address space.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_mapped_vie=
w
```

=20

Error

=20

    3221225497 - 0xC0000019

=20

The address range to unmap is not a mapped view.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unable_to_free=
_vm
```

=20

Error

=20

    3221225498 - 0xC000001A

=20

The virtual memory cannot be freed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unable_to_dele=
te_section
```

=20

Error

=20

    3221225499 - 0xC000001B

=20

The specified section cannot be deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_system=
_service
```

=20

Error

=20

    3221225500 - 0xC000001C

=20

An invalid system service was specified in a system service c= all.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_illegal_instru=
ction
```

=20

Error

=20

    3221225501 - 0xC000001D

=20

{EXCEPTION} Illegal Instruction An attempt was made to execut= e an
illegal instruction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_lock_=
sequence
```

=20

Warning

=20

    3221225502 - 0xC000001E

=20

{Invalid Lock Sequence} An attempt was made to execute an inv= alid lock
sequence.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_view_=
size
```

=20

Warning

=20

    3221225503 - 0xC000001F

=20

{Invalid Mapping} An attempt was made to create a view for a = section
that is bigger than the section.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_file_f=
or_section
```

=20

Error

=20

    3221225504 - 0xC0000020

=20

{Bad File} The attributes of the specified mapping file for a= section
of memory cannot be read.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_already_commi=
tted
```

=20

Warning

=20

    3221225505 - 0xC0000021

=20

{Already Committed} The specified address range is already co= mmitted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_access_denied=
```

=20

Warning

=20

    3221225506 - 0xC0000022

=20

{Access Denied} A process has requested access to an object b= ut has
not been granted those access rights.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_buffer_too_sma=
ll
```

=20

Error

=20

    3221225507 - 0xC0000023

=20

{Buffer Too Small} The buffer is too small to contain the ent= ry. No
information has been written to the buffer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_type_m=
ismatch
```

=20

Warning

=20

    3221225508 - 0xC0000024

=20

{Wrong Type} There is a mismatch between the type of object t= hat is
required by the requested operation and the type of object that is s=
pecified in the request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_noncontinuable=
_exception
```

=20

Error

=20

    3221225509 - 0xC0000025

=20

{EXCEPTION} Cannot Continue Windows cannot continue from this=
exception.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_dispos=
ition
```

=20

Error

=20

    3221225510 - 0xC0000026

=20

An invalid exception disposition was returned by an exception= handler.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unwind
```

=20

Error

=20

    3221225511 - 0xC0000027

=20

Unwind exception code.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_stack
```

=20

Error

=20

    3221225512 - 0xC0000028

=20

An invalid or unaligned stack was encountered during an unwin= d
operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_unwind=
_target
```

=20

Error

=20

    3221225513 - 0xC0000029

=20

An invalid unwind target was encountered during an unwind ope= ration.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_locked
```

=20

Error

=20

    3221225514 - 0xC000002A

=20

An attempt was made to unlock a page of memory that was not l= ocked.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_parity_error
```

=20

Error

=20

    3221225515 - 0xC000002B

=20

A device parity error on an I/O operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unable_to_deco=
mmit_vm
```

=20

Error

=20

    3221225516 - 0xC000002C

=20

An attempt was made to decommit uncommitted virtual memory. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_committed<=
/pre>
```

=20

Error

=20

    3221225517 - 0xC000002D

=20

An attempt was made to change the attributes on memory that h= as not
been committed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_port_a=
ttributes
```

=20

Error

=20

    3221225518 - 0xC000002E

=20

Invalid object attributes specified to NtCreatePort or invali= d port
attributes specified to NtConnectPort.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_port_message_t=
oo_long
```

=20

Error

=20

    3221225519 - 0xC000002F

=20

The length of the message that was passed to NtRequestPort or=
NtRequestWaitReplyPort is longer than the maximum message that is
allowed = by the port.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_mix
```

=20

Error

=20

    3221225520 - 0xC0000030

=20

An invalid combination of parameters was specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_quota_=
lower
```

=20

Error

=20

    3221225521 - 0xC0000031

=20

An attempt was made to lower a quota limit below the current = usage.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_disk_corrupt_=
error
```

=20

Error

=20

    3221225522 - 0xC0000032

=20

{Corrupt Disk} The file system structure on the disk is corru= pt and
unusable. Run the Chkdsk utility on the volume.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_object_name_in=
valid
```

=20

Error

=20

    3221225523 - 0xC0000033

=20

The object name is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_name_n=
ot_found
```

=20

Warning

=20

    3221225524 - 0xC0000034

=20

The object name is not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_name_c=
ollision
```

=20

Warning

=20

    3221225525 - 0xC0000035

=20

The object name already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_port_disconne=
cted
```

=20

Warning

=20

    3221225527 - 0xC0000037

=20

An attempt was made to send a message to a disconnected commu= nication
port.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_already=
_attached
```

=20

Error

=20

    3221225528 - 0xC0000038

=20

An attempt was made to attach to a device that was already at= tached to
another device.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_path_i=
nvalid
```

=20

Warning

=20

    3221225529 - 0xC0000039

=20

The object path component was not a directory object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_path_n=
ot_found
```

=20

Warning

=20

    3221225530 - 0xC000003A

=20

{Path Not Found} The path does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_object_path_s=
yntax_bad
```

=20

Warning

=20

    3221225531 - 0xC000003B

=20

The object path component was not a directory object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_data_overrun
```

=20

Error

=20

    3221225532 - 0xC000003C

=20

{Data Overrun} A data overrun error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_data_late_erro=
r
```

=20

Error

=20

    3221225533 - 0xC000003D

=20

{Data Late} A data late error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_data_error
```

=20

Error

=20

    3221225534 - 0xC000003E

=20

{Data Error} An error occurred in reading or writing data. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_crc_error
```

=20

Error

=20

    3221225535 - 0xC000003F

=20

{Bad CRC} A cyclic redundancy check (CRC) checksum error occu= rred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_section_too_b=
ig
```

=20

Warning

=20

    3221225536 - 0xC0000040

=20

{Section Too Large} The specified section is too big to map t= he file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_port_connecti=
on_refused
```

=20

Warning

=20

    3221225537 - 0xC0000041

=20

The NtConnectPort request is refused.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_port_=
handle
```

=20

Warning

=20

    3221225538 - 0xC0000042

=20

The type of port handle is invalid for the operation that is =
requested.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_sharing_viola=
tion
```

=20

Error

=20

    3221225539 - 0xC0000043

=20

A file cannot be opened because the share access flags are in=
compatible.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_quota_exceeded=
```

=20

Error

=20

    3221225540 - 0xC0000044

=20

Insufficient quota exists to complete the operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_page_p=
rotection
```

=20

Error

=20

    3221225541 - 0xC0000045

=20

The specified page protection was not valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mutant_not_own=
ed
```

=20

Error

=20

    3221225542 - 0xC0000046

=20

An attempt to release a mutant object was made by a thread th= at was
not the owner of the mutant object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_semaphore_limi=
t_exceeded
```

=20

Error

=20

    3221225543 - 0xC0000047

=20

An attempt was made to release a semaphore such that its maxi= mum count
would have been exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_port_already_s=
et
```

=20

Error

=20

    3221225544 - 0xC0000048

=20

An attempt was made to set the DebugPort or ExceptionPort of = a
process, but a port already exists in the process, or an attempt was
made= to set the CompletionPort of a file but a port was already set in
the file= , or an attempt was made to set the associated completion port
of an ALPC p= ort but it is already set.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_section_not_im=
age
```

=20

Error

=20

    3221225545 - 0xC0000049

=20

An attempt was made to query image information on a section t= hat does
not map an image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_suspend_count_=
exceeded
```

=20

Error

=20

    3221225546 - 0xC000004A

=20

An attempt was made to suspend a thread whose suspend count w= as at its
maximum.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_thread_is_ter=
minating
```

=20

Warning

=20

    3221225547 - 0xC000004B

=20

An attempt was made to suspend a thread that has begun termin= ation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_working_se=
t_limit
```

=20

Error

=20

    3221225548 - 0xC000004C

=20

An attempt was made to set the working set limit to an invali= d value
(for example, the minimum greater than maximum).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_incompatible_f=
ile_map
```

=20

Error

=20

    3221225549 - 0xC000004D

=20

A section was created to map a file that is not compatible wi= th an
already existing section that maps the same file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_section_protec=
tion
```

=20

Error

=20

    3221225550 - 0xC000004E

=20

A view to a section specifies a protection that is incompatib= le with
the protection of the initial view.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_eas_not_suppo=
rted
```

=20

Warning

=20

    3221225551 - 0xC000004F

=20

An operation involving EAs failed because the file system doe= s not
support EAs.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_ea_too_large<=
/pre>
```

=20

Warning

=20

    3221225552 - 0xC0000050

=20

An EA operation failed because the EA set is too large.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nonexistent_ea=
_entry
```

=20

Error

=20

    3221225553 - 0xC0000051

=20

An EA operation failed because the name or EA index is invali= d.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_eas_on_file=
```

=20

Error

=20

    3221225554 - 0xC0000052

=20

The file for which EAs were requested has no EAs.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ea_corrupt_err=
or
```

=20

Error

=20

    3221225555 - 0xC0000053

=20

The EA is corrupt and cannot be read.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_file_lock_con=
flict
```

=20

Error

=20

    3221225556 - 0xC0000054

=20

A requested read/write cannot be granted due to a conflicting= file
lock.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_lock_not_gran=
ted
```

=20

Warning

=20

    3221225557 - 0xC0000055

=20

A requested file lock cannot be granted due to other existing= locks.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_delete_pendin=
g
```

=20

Warning

=20

    3221225558 - 0xC0000056

=20

A non-close operation has been requested of a file object tha= t has a
delete pending.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ctl_file_not_s=
upported
```

=20

Error

=20

    3221225559 - 0xC0000057

=20

An attempt was made to set the control attribute on a file. T= his
attribute is not supported in the destination file system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unknown_revisi=
on
```

=20

Error

=20

    3221225560 - 0xC0000058

=20

Indicates a revision number that was encountered or specified= is not
one that is known by the service. It may be a more recent revision =
than the service is aware of.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_revision_misma=
tch
```

=20

Error

=20

    3221225561 - 0xC0000059

=20

Indicates that two revision levels are incompatible.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_owner<=
/pre>
```

=20

Error

=20

    3221225562 - 0xC000005A

=20

Indicates a particular security ID may not be assigned as the= owner of
an object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_primar=
y_group
```

=20

Error

=20

    3221225563 - 0xC000005B

=20

Indicates a particular security ID may not be assigned as the= primary
group of an object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_impersonati=
on_token
```

=20

Error

=20

    3221225564 - 0xC000005C

=20

An attempt has been made to operate on an impersonation token= by a
thread that is not currently impersonating a client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_disable_m=
andatory
```

=20

Error

=20

    3221225565 - 0xC000005D

=20

A mandatory group may not be disabled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_logon_serve=
rs
```

=20

Error

=20

    3221225566 - 0xC000005E

=20

No logon servers are currently available to service the logon= request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_logon_=
session
```

=20

Error

=20

    3221225567 - 0xC000005F

=20

A specified logon session does not exist. It may already have= been
terminated.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_privil=
ege
```

=20

Error

=20

    3221225568 - 0xC0000060

=20

A specified privilege does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_privilege_not=
_held
```

=20

Warning

=20

    3221225569 - 0xC0000061

=20

A required privilege is not held by the client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_accoun=
t_name
```

=20

Error

=20

    3221225570 - 0xC0000062

=20

The name provided is not a properly formed account name.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_user_exists
```

=20

Error

=20

    3221225571 - 0xC0000063

=20

The specified account already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_user
```

=20

Error

=20

    3221225572 - 0xC0000064

=20

The specified account does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_group_exists
```

=20

Error

=20

    3221225573 - 0xC0000065

=20

The specified group already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_group<=
/pre>
```

=20

Error

=20

    3221225574 - 0xC0000066

=20

The specified group does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_member_in_grou=
p
```

=20

Error

=20

    3221225575 - 0xC0000067

=20

The specified user account is already in the specified group = account.
Also used to indicate a group cannot be deleted because it contain= s a
member.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_member_not_in_=
group
```

=20

Error

=20

    3221225576 - 0xC0000068

=20

The specified user account is not a member of the specified g= roup
account.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_last_admin
```

=20

Error

=20

    3221225577 - 0xC0000069

=20

Indicates the requested operation would disable or delete the= last
remaining administration account. This is not allowed to prevent crea=
ting a situation in which the system cannot be administrated.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_wrong_passwor=
d
```

=20

Error

=20

    3221225578 - 0xC000006A

=20

When trying to update a password, this return status indicate= s that
the value provided as the current password is not correct.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ill_formed_pas=
sword
```

=20

Error

=20

    3221225579 - 0xC000006B

=20

When trying to update a password, this return status indicate= s that
the value provided for the new password contains values that are not=
allowed in passwords.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_password_restr=
iction
```

=20

Error

=20

    3221225580 - 0xC000006C

=20

When trying to update a password, this status indicates that = some
password update rule has been violated. For example, the password may =
not meet length criteria.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_logon_failure=
```

=20

Warning

=20

    3221225581 - 0xC000006D

=20

The attempted logon is invalid. This is either due to a bad u= sername
or authentication information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_account_restri=
ction
```

=20

Error

=20

    3221225582 - 0xC000006E

=20

Indicates a referenced user name and authentication informati= on are
valid, but some user account restriction has prevented successful au=
thentication (such as time-of-day restrictions).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_logon=
_hours
```

=20

Error

=20

    3221225583 - 0xC000006F

=20

The user account has time restrictions and may not be logged = onto at
this time.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_works=
tation
```

=20

Error

=20

    3221225584 - 0xC0000070

=20

The user account is restricted so that it may not be used to = log on
from the source workstation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_password_expi=
red
```

=20

Error

=20

    3221225585 - 0xC0000071

=20

The user account password has expired.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_account_disab=
led
```

=20

Error

=20

    3221225586 - 0xC0000072

=20

The referenced account is currently disabled and may not be l= ogged on
to.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_luids=
_requested
```

=20

Error

=20

    3221225588 - 0xC0000074

=20

The number of LUIDs requested may not be allocated with a sin= gle
allocation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_luids_exhauste=
d
```

=20

Error

=20

    3221225589 - 0xC0000075

=20

Indicates there are no more LUIDs to allocate.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_sub_au=
thority
```

=20

Error

=20

    3221225590 - 0xC0000076

=20

Indicates the sub-authority value is invalid for the particul= ar use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_acl
```

=20

Error

=20

    3221225591 - 0xC0000077

=20

Indicates the ACL structure is not valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_sid
```

=20

Error

=20

    3221225592 - 0xC0000078

=20

Indicates the SID structure is not valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_securi=
ty_descr
```

=20

Error

=20

    3221225593 - 0xC0000079

=20

Indicates the SECURITY\_DESCRIPTOR structure is not valid. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_procedure_not_=
found
```

=20

Error

=20

    3221225594 - 0xC000007A

=20

Indicates the specified procedure address cannot be found in = the DLL.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
format
```

=20

Error

=20

    3221225595 - 0xC000007B

=20

{Bad Image} The image is either not designed to run on Window= s or it
contains an error. Try installing the program again using the origi= nal
installation media or contact your system administrator or the software=
vendor for support.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_token
```

=

=20

Error

=20

    3221225596 - 0xC000007C

=20

An attempt was made to reference a token that does not exist.= This is
typically done by referencing the token that is associated with a =
thread when the thread is not impersonating a client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_inheritanc=
e_acl
```

=20

Error

=20

    3221225597 - 0xC000007D

=20

Indicates that an attempt to build either an inherited ACL or= ACE was
not successful. This can be caused by a number of things. One of t= he
more probable causes is the replacement of a CreatorId with a SID that
d= id not fit into the ACE or ACL.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_range_not_loc=
ked
```

=20

Warning

=20

    3221225598 - 0xC000007E

=20

The range specified in NtUnlockFile was not locked.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_disk_full
```

=20

Error

=20

    3221225599 - 0xC000007F

=20

An operation failed because the disk was full.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_server_disable=
d
```

=20

Error

=20

    3221225600 - 0xC0000080

=20

The GUID allocation server is disabled at the moment.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_server_not_dis=
abled
```

=20

Error

=20

    3221225601 - 0xC0000081

=20

The GUID allocation server is enabled at the moment.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_guids=
_requested
```

=20

Error

=20

    3221225602 - 0xC0000082

=20

Too many GUIDs were requested from the allocation server at o= nce.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_guids_exhauste=
d
```

=20

Error

=20

    3221225603 - 0xC0000083

=20

The GUIDs could not be allocated because the Authority Agent = was
exhausted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_id_aut=
hority
```

=20

Error

=20

    3221225604 - 0xC0000084

=20

The value provided was an invalid value for an identifier aut= hority.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_agents_exhaust=
ed
```

=20

Error

=20

    3221225605 - 0xC0000085

=20

No more authority agent values are available for the particul= ar
identifier authority value.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_volume=
_label
```

=20

Error

=20

    3221225606 - 0xC0000086

=20

An invalid volume label has been specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_section_not_ex=
tended
```

=20

Error

=20

    3221225607 - 0xC0000087

=20

A mapped section could not be extended.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_mapped_dat=
a
```

=20

Error

=20

    3221225608 - 0xC0000088

=20

Specified section to flush does not map a data file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_data_=
not_found
```

=20

Error

=20

    3221225609 - 0xC0000089

=20

Indicates the specified image file did not contain a resource= section.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_type_=
not_found
```

=20

Error

=20

    3221225610 - 0xC000008A

=20

Indicates the specified resource type cannot be found in the = image
file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_name_=
not_found
```

=20

Error

=20

    3221225611 - 0xC000008B

=20

Indicates the specified resource name cannot be found in the = image
file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_array_bounds_e=
xceeded
```

=20

Error

=20

    3221225612 - 0xC000008C

=20

{EXCEPTION} Array bounds exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_denormal=
_operand
```

=20

Error

=20

    3221225613 - 0xC000008D

=20

{EXCEPTION} Floating-point denormal operand.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_divide_b=
y_zero
```

=20

Error

=20

    3221225614 - 0xC000008E

=20

{EXCEPTION} Floating-point division by zero.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_inexact_=
result
```

=20

Error

=20

    3221225615 - 0xC000008F

=20

{EXCEPTION} Floating-point inexact result.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_invalid_=
operation
```

=20

Error

=20

    3221225616 - 0xC0000090

=20

{EXCEPTION} Floating-point invalid operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_overflow=
```

=20

Error

=20

    3221225617 - 0xC0000091

=20

{EXCEPTION} Floating-point overflow.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_stack_ch=
eck
```

=20

Error

=20

    3221225618 - 0xC0000092

=20

{EXCEPTION} Floating-point stack check.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_underflo=
w
```

=20

Error

=20

    3221225619 - 0xC0000093

=20

{EXCEPTION} Floating-point underflow.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_integer_divide=
_by_zero
```

=20

Error

=20

    3221225620 - 0xC0000094

=20

{EXCEPTION} Integer division by zero.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_integer_overfl=
ow
```

=20

Error

=20

    3221225621 - 0xC0000095

=20

{EXCEPTION} Integer overflow.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_privileged_ins=
truction
```

=20

Error

=20

    3221225622 - 0xC0000096

=20

{EXCEPTION} Privileged instruction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_too_many_pagi=
ng_files
```

=20

Warning

=20

    3221225623 - 0xC0000097

=20

An attempt was made to install more paging files than the sys= tem
supports.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_invalid
```

=20

Error

=20

    3221225624 - 0xC0000098

=20

The volume for a file has been externally altered such that t= he opened
file is no longer valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_allotted_space=
_exceeded
```

=20

Error

=20

    3221225625 - 0xC0000099

=20

When a block of memory is allotted for future updates, such a= s the
memory allocated to hold discretionary access control and primary gro=
up information, successive updates may exceed the amount of memory
original= ly allotted. Because a quota may already have been charged to
several proce= sses that have handles to the object, it is not
reasonable to alter the siz= e of the allocated memory. Instead, a
request that requires more memory tha= n has been allotted must fail and
the STATUS\_ALLOTTED\_SPACE\_EXCEEDED error = returned.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_insufficient_r=
esources
```

=20

Error

=20

    3221225626 - 0xC000009A

=20

Insufficient system resources exist to complete the API.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_dfs_exit_path=
_found
```

=20

Warning

=20

    3221225627 - 0xC000009B

=20

An attempt has been made to open a DFS exit path control file= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_data_error_un=
used
```

=20

Warning

=20

    3221225628 - 0xC000009C

=20

There are bad blocks (sectors) on the hard disk.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_not_con=
nected
```

=20

Error

=20

    3221225629 - 0xC000009D

=20

There is bad cabling, non-termination, or the controller is n= ot able
to obtain access to the hard disk.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_power_f=
ailure
```

=20

Error

=20

    3221225630 - 0xC000009E

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_free_vm_not_at=
_base
```

=20

Error

=20

    3221225631 - 0xC000009F

=20

Virtual memory cannot be freed because the base address is no= t the
base of the region and a region size of zero was specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_memory_not_all=
ocated
```

=20

Error

=20

    3221225632 - 0xC00000A0

=20

An attempt was made to free virtual memory that is not alloca= ted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_working_set_qu=
ota
```

=20

Error

=20

    3221225633 - 0xC00000A1

=20

The working set is not big enough to allow the requested page= s to be
locked.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_media_write_p=
rotected
```

=20

Error

=20

    3221225634 - 0xC00000A2

=20

{Write Protect Error} The disk cannot be written to because i= t is
write-protected. Remove the write protection from the volume in drive.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_not_rea=
dy
```

=20

Error

=20

    3221225635 - 0xC00000A3

=20

{Drive Not Ready} The drive is not ready for use; its door ma= y be
open. Check drive and make sure that a disk is inserted and that the d=
rive door is closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_group_=
attributes
```

=20

Error

=20

    3221225636 - 0xC00000A4

=20

The specified attributes are invalid or are incompatible with= the
attributes for the group as a whole.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_impersonat=
ion_level
```

=20

Error

=20

    3221225637 - 0xC00000A5

=20

A specified impersonation level is invalid. Also used to indi= cate that
a required impersonation level was not provided.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_open_anon=
ymous
```

=20

Error

=20

    3221225638 - 0xC00000A6

=20

An attempt was made to open an anonymous-level token. Anonymo= us tokens
may not be opened.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_validation=
_class
```

=20

Error

=20

    3221225639 - 0xC00000A7

=20

The validation information class requested was invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_token_type=
```

=20

Error

=20

    3221225640 - 0xC00000A8

=20

The type of a token object is inappropriate for its attempted= use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_master_boo=
t_record
```

=20

Error

=20

    3221225641 - 0xC00000A9

=20

The type of a token object is inappropriate for its attempted= use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_instruction_mi=
salignment
```

=20

Error

=20

    3221225642 - 0xC00000AA

=20

An attempt was made to execute an instruction at an unaligned= address
and the host system does not support unaligned instruction referen= ces.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_instance_not_=
available
```

=20

Warning

=20

    3221225643 - 0xC00000AB

=20

The maximum named pipe instance count has been reached.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_pipe_not_avai=
lable
```

=20

Warning

=20

    3221225644 - 0xC00000AC

=20

An instance of a named pipe cannot be found in the listening = state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_pipe_=
state
```

=20

Warning

=20

    3221225645 - 0xC00000AD

=20

The named pipe is not in the connected or closing state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_pipe_busy
```

=20

Warning

=20

    3221225646 - 0xC00000AE

=20

The specified pipe is set to complete operations and there ar= e current
I/O operations queued so that it cannot be changed to queue opera=
tions.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_illegal_funct=
ion
```

=20

Warning

=20

    3221225647 - 0xC00000AF

=20

The specified handle is not open to the server end of the nam= ed pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_pipe_disconne=
cted
```

=20

Error

=20

    3221225648 - 0xC00000B0

=20

The specified named pipe is in the disconnected state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_pipe_closing<=
/pre>
```

=20

Warning

=20

    3221225649 - 0xC00000B1

=20

The specified named pipe is in the closing state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pipe_connected=
```

=20

Error

=20

    3221225650 - 0xC00000B2

=20

The specified named pipe is in the connected state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pipe_listening=
```

=20

Error

=20

    3221225651 - 0xC00000B3

=20

The specified named pipe is in the listening state.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_read_=
mode
```

=20

Warning

=20

    3221225652 - 0xC00000B4

=20

The specified named pipe is not in message mode.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_io_timeout
```

=20

Error

=20

    3221225653 - 0xC00000B5

=20

{Device Timeout} The specified I/O operation was not complete= d before
the time-out period expired.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_forced_cl=
osed
```

=20

Error

=20

    3221225654 - 0xC00000B6

=20

The specified file has been closed by another process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_profiling_not_=
started
```

=20

Error

=20

    3221225655 - 0xC00000B7

=20

Profiling is not started.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_profiling_not_=
stopped
```

=20

Error

=20

    3221225656 - 0xC00000B8

=20

Profiling is not stopped.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_could_not_inte=
rpret
```

=20

Error

=20

    3221225657 - 0xC00000B9

=20

The passed ACL did not contain the minimum required informati= on.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_file_is_a_dir=
ectory
```

=20

Warning

=20

    3221225658 - 0xC00000BA

=20

The file that was specified as a target is a directory, and t= he caller
specified that it could be anything but a directory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_not_lis=
tening
```

=20

Error

=20

    3221225660 - 0xC00000BC

=20

This remote computer is not listening.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_duplicate_name=
```

=20

Error

=20

    3221225661 - 0xC00000BD

=20

A duplicate name exists on the network.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_network_pa=
th
```

=20

Error

=20

    3221225662 - 0xC00000BE

=20

The network path cannot be located.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_network_busy
```

=20

Error

=20

    3221225663 - 0xC00000BF

=20

The network is busy.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_does_no=
t_exist
```

=20

Error

=20

    3221225664 - 0xC00000C0

=20

This device does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_comma=
nds
```

=20

Error

=20

    3221225665 - 0xC00000C1

=20

The network BIOS command limit has been reached.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_adapter_hardwa=
re_error
```

=20

Error

=20

    3221225666 - 0xC00000C2

=20

An I/O adapter hardware error has occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_networ=
k_response
```

=20

Error

=20

    3221225667 - 0xC00000C3

=20

The network responded incorrectly.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_unexpected_ne=
twork_error
```

=20

Error

=20

    3221225668 - 0xC00000C4

=20

An unexpected network error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_remote_ada=
pter
```

=20

Error

=20

    3221225669 - 0xC00000C5

=20

The remote adapter is not compatible.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_print_queue_f=
ull
```

=20

Error

=20

    3221225670 - 0xC00000C6

=20

The print queue is full.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_no_spool_spac=
e
```

=20

Error

=20

    3221225671 - 0xC00000C7

=20

Space to store the file that is waiting to be printed is not = available
on the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_print_cancell=
ed
```

=20

Error

=20

    3221225672 - 0xC00000C8

=20

The requested print file has been canceled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_network_name_=
deleted
```

=20

Error

=20

    3221225673 - 0xC00000C9

=20

The network name was deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_network_acces=
s_denied
```

=20

Error

=20

    3221225674 - 0xC00000CA

=20

Network access is denied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_bad_device_ty=
pe
```

=20

Error

=20

    3221225675 - 0xC00000CB

=20

{Incorrect Network Resource Type} The specified device type (= LPT, for
example) conflicts with the actual device type on the remote resou= rce.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_bad_network_n=
ame
```

=20

Error

=20

    3221225676 - 0xC00000CC

=20

{Network Name Not Found} The specified share name cannot be f= ound on
the remote server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_names=
```

=20

Error

=20

    3221225677 - 0xC00000CD

=20

The name limit for the network adapter card of the local comp= uter was
exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_too_many_sess=
ions
```

=20

Error

=20

    3221225678 - 0xC00000CE

=20

The network BIOS session limit was exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_sharing_paused=
```

=20

Error

=20

    3221225679 - 0xC00000CF

=20

File sharing has been temporarily paused.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_request_not_a=
ccepted
```

=20

Error

=20

    3221225680 - 0xC00000D0

=20

No more connections can be made to this remote computer at th= is time
because the computer has already accepted the maximum number of con=
nections.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_redirector_pau=
sed
```

=20

Error

=20

    3221225681 - 0xC00000D1

=20

Print or disk redirection is temporarily paused.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_net_write_faul=
t
```

=20

Error

=20

    3221225682 - 0xC00000D2

=20

A network data fault occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_profiling_at_l=
imit
```

=20

Error

=20

    3221225683 - 0xC00000D3

=20

The number of active profiling objects is at the maximum and = no more
may be started.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_not_same_devi=
ce
```

=20

Warning

=20

    3221225684 - 0xC00000D4

=20

{Incorrect Volume} The destination file of a rename request i= s located
on a different device than the source of the rename request.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_file_renamed<=
/pre>
```

=20

Warning

=20

    3221225685 - 0xC00000D5

=20

The specified file has been renamed and thus cannot be modifi= ed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_virtual_circui=
t_closed
```

=20

Error

=20

    3221225686 - 0xC00000D6

=20

{Network Request Timeout} The session with a remote server ha= s been
disconnected because the time-out interval for a request has expired= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_security_on=
_object
```

=20

Error

=20

    3221225687 - 0xC00000D7

=20

Indicates an attempt was made to operate on the security of a= n object
that does not have security associated with it.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_wait
```

=20

Error

=20

    3221225688 - 0xC00000D8

=20

Used to indicate that an operation cannot continue without bl= ocking
for I/O.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_pipe_empty
```

=20

Warning

=20

    3221225689 - 0xC00000D9

=20

Used to indicate that a read operation was done on an empty p= ipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_access_do=
main_info
```

=20

Error

=20

    3221225690 - 0xC00000DA

=20

Configuration information could not be read from the domain c=
ontroller, either because the machine is unavailable or access has been
den= ied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_terminate=
_self
```

=20

Error

=20

    3221225691 - 0xC00000DB

=20

Indicates that a thread attempted to terminate itself by defa= ult
(called NtTerminateThread with NULL) and it was the last thread in the =
current process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_server=
_state
```

=20

Error

=20

    3221225692 - 0xC00000DC

=20

Indicates the Sam Server was in the wrong state to perform th= e desired
operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_domain=
_state
```

=20

Error

=20

    3221225693 - 0xC00000DD

=20

Indicates the domain was in the wrong state to perform the de= sired
operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_domain=
_role
```

=20

Error

=20

    3221225694 - 0xC00000DE

=20

This operation is only allowed for the primary domain control= ler of
the domain.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_domain=
```

=20

Error

=20

    3221225695 - 0xC00000DF

=20

The specified domain did not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_domain_exists<=
/pre>
```

=20

Error

=20

    3221225696 - 0xC00000E0

=20

The specified domain already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_domain_limit_e=
xceeded
```

=20

Error

=20

    3221225697 - 0xC00000E1

=20

An attempt was made to exceed the limit on the number of doma= ins per
server for this release.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_oplock_not_gra=
nted
```

=20

Error

=20

    3221225698 - 0xC00000E2

=20

An error status returned when the opportunistic lock (oplock)= request
is denied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_oplock=
_protocol
```

=20

Error

=20

    3221225699 - 0xC00000E3

=20

An error status returned when an invalid opportunistic lock (= oplock)
acknowledgment is received by a file system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_internal_db_co=
rruption
```

=20

Error

=20

    3221225700 - 0xC00000E4

=20

This error indicates that the requested operation cannot be c= ompleted
due to a catastrophic media failure or an on-disk data structure c=
orruption.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_internal_error=
```

=20

Error

=20

    3221225701 - 0xC00000E5

=20

An internal error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_generic_not_ma=
pped
```

=20

Error

=20

    3221225702 - 0xC00000E6

=20

Indicates generic access types were contained in an access ma= sk which
should already be mapped to non-generic access types.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_descriptor=
_format
```

=20

Error

=20

    3221225703 - 0xC00000E7

=20

Indicates a security descriptor is not in the necessary forma= t
(absolute or self-relative).

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_user_b=
uffer
```

=20

Error

=20

    3221225704 - 0xC00000E8

=20

An access to a user buffer failed at an expected point in tim= e. This
code is defined because the caller does not want to accept STATUS\_A=
CCESS\_VIOLATION in its filter.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unexpected_io_=
error
```

=20

Error

=20

    3221225705 - 0xC00000E9

=20

If an I/O error that is not defined in the standard FsRtl fil= ter is
returned, it is converted to the following error, which is guarantee= d
to be in the filter. In this case, information is lost; however, the
filt= er correctly handles the exception.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unexpected_mm_=
create_err
```

=20

Error

=20

    3221225706 - 0xC00000EA

=20

If an MM error that is not defined in the standard FsRtl filt= er is
returned, it is converted to one of the following errors, which are g=
uaranteed to be in the filter. In this case, information is lost;
however, = the filter correctly handles the exception.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unexpected_mm_=
map_error
```

=20

Error

=20

    3221225707 - 0xC00000EB

=20

If an MM error that is not defined in the standard FsRtl filt= er is
returned, it is converted to one of the following errors, which are g=
uaranteed to be in the filter. In this case, information is lost;
however, = the filter correctly handles the exception.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unexpected_mm_=
extend_err
```

=20

Error

=20

    3221225708 - 0xC00000EC

=20

If an MM error that is not defined in the standard FsRtl filt= er is
returned, it is converted to one of the following errors, which are g=
uaranteed to be in the filter. In this case, information is lost;
however, = the filter correctly handles the exception.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_logon_proc=
ess
```

=20

Error

=20

    3221225709 - 0xC00000ED

=20

The requested action is restricted for use by logon processes= only. The
calling process has not registered as a logon process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_logon_session_=
exists
```

=20

Error

=20

    3221225710 - 0xC00000EE

=20

An attempt has been made to start a new session manager or LS= A logon
session by using an ID that is already in use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_1
```

=20

Error

=20

    3221225711 - 0xC00000EF

=20

An invalid parameter was passed to a service or function as t= he first
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_2
```

=20

Error

=20

    3221225712 - 0xC00000F0

=20

An invalid parameter was passed to a service or function as t= he second
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_3
```

=20

Error

=20

    3221225713 - 0xC00000F1

=20

An invalid parameter was passed to a service or function as t= he third
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_4
```

=20

Error

=20

    3221225714 - 0xC00000F2

=20

An invalid parameter was passed to a service or function as t= he fourth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_5
```

=20

Error

=20

    3221225715 - 0xC00000F3

=20

An invalid parameter was passed to a service or function as t= he fifth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_6
```

=20

Error

=20

    3221225716 - 0xC00000F4

=20

An invalid parameter was passed to a service or function as t= he sixth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_7
```

=20

Error

=20

    3221225717 - 0xC00000F5

=20

An invalid parameter was passed to a service or function as t= he
seventh argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_8
```

=20

Error

=20

    3221225718 - 0xC00000F6

=20

An invalid parameter was passed to a service or function as t= he eighth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_9
```

=20

Error

=20

    3221225719 - 0xC00000F7

=20

An invalid parameter was passed to a service or function as t= he ninth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_10
```

=20

Error

=20

    3221225720 - 0xC00000F8

=20

An invalid parameter was passed to a service or function as t= he tenth
argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_11
```

=20

Error

=20

    3221225721 - 0xC00000F9

=20

An invalid parameter was passed to a service or function as t= he
eleventh argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_parame=
ter_12
```

=20

Error

=20

    3221225722 - 0xC00000FA

=20

An invalid parameter was passed to a service or function as t= he
twelfth argument.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_redirector_no=
t_started
```

=20

Warning

=20

    3221225723 - 0xC00000FB

=20

An attempt was made to access a network file, but the network= software
was not yet started.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_redirector_sta=
rted
```

=20

Error

=20

    3221225724 - 0xC00000FC

=20

An attempt was made to start the redirector, but the redirect= or has
already been started.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_stack_overflow=
```

=20

Error

=20

    3221225725 - 0xC00000FD

=20

A new guard page for the stack cannot be created.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_packag=
e
```

=20

Error

=20

    3221225726 - 0xC00000FE

=20

A specified authentication package is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_function_t=
able
```

=20

Error

=20

    3221225727 - 0xC00000FF

=20

A malformed function table was encountered during an unwind o= peration.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_variable_not_f=
ound
```

=20

Error

=20

    3221225728 - 0xC0000100

=20

Indicates the specified environment variable name was not fou= nd in the
specified environment block.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_directory_not=
_empty
```

=20

Warning

=20

    3221225729 - 0xC0000101

=20

Indicates that the directory trying to be deleted is not empt= y.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_corrupt_e=
rror
```

=20

Error

=20

    3221225730 - 0xC0000102

=20

{Corrupt File} The file or directory is corrupt and unreadabl= e. Run
the Chkdsk utility.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_a_director=
y
```

=20

Error

=20

    3221225731 - 0xC0000103

=20

A requested opened file is not a directory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_logon_sess=
ion_state
```

=20

Error

=20

    3221225732 - 0xC0000104

=20

The logon session is not in a state that is consistent with t= he
requested operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_logon_session_=
collision
```

=20

Error

=20

    3221225733 - 0xC0000105

=20

An internal LSA error has occurred. An authentication package= has
requested the creation of a logon session but the ID of an already exi=
sting logon session has been specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_name_too_long<=
/pre>
```

=20

Error

=20

    3221225734 - 0xC0000106

=20

A specified name string is too long for its intended use. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_files_open
```

=20

Error

=20

    3221225735 - 0xC0000107

=20

The user attempted to force close the files on a redirected d= rive, but
there were opened files on the drive, and the user did not specif= y a
sufficient level of force.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_in_=
use
```

=20

Error

=20

    3221225736 - 0xC0000108

=20

The user attempted to force close the files on a redirected d= rive, but
there were opened directories on the drive, and the user did not =
specify a sufficient level of force.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_message_not_fo=
und
```

=20

Error

=20

    3221225737 - 0xC0000109

=20

RtlFindMessage could not locate the requested message ID in t= he
message table resource.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_process_is_te=
rminating
```

=20

Warning

=20

    3221225738 - 0xC000010A

=20

An attempt was made to duplicate an object handle into or out= of an
exiting process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_logon_=
type
```

=20

Error

=20

    3221225739 - 0xC000010B

=20

Indicates an invalid value has been provided for the LogonTyp= e
requested.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_guid_transl=
ation
```

=20

Error

=20

    3221225740 - 0xC000010C

=20

Indicates that an attempt was made to assign protection to a = file
system file or directory and one of the SIDs in the security descripto=
r could not be translated into a GUID that could be stored by the file
syst= em. This causes the protection attempt to fail, which may cause a
file crea= tion attempt to fail.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cannot_imperso=
nate
```

=20

Error

=20

    3221225741 - 0xC000010D

=20

Indicates that an attempt has been made to impersonate via a = named
pipe that has not yet been read from.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_already_=
loaded
```

=20

Error

=20

    3221225742 - 0xC000010E

=20

Indicates that the specified image is already loaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_not_pres=
ent
```

=20

Error

=20

    3221225743 - 0xC000010F

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_lid_not_=
exist
```

=20

Error

=20

    3221225744 - 0xC0000110

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_lid_alre=
ady_owned
```

=20

Error

=20

    3221225745 - 0xC0000111

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_not_lid_=
owner
```

=20

Error

=20

    3221225746 - 0xC0000112

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_invalid_=
command
```

=20

Error

=20

    3221225747 - 0xC0000113

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_invalid_=
lid
```

=20

Error

=20

    3221225748 - 0xC0000114

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_selector=
_not_available
```

=20

Error

=20

    3221225749 - 0xC0000115

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_abios_invalid_=
selector
```

=20

Error

=20

    3221225750 - 0xC0000116

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_ldt
```

=20

Error

=20

    3221225751 - 0xC0000117

=20

Indicates that an attempt was made to change the size of the = LDT for a
process that has no LDT.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_ldt_si=
ze
```

=20

Error

=20

    3221225752 - 0xC0000118

=20

Indicates that an attempt was made to grow an LDT by setting = its size,
or that the size was not an even number of selectors.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_ldt_of=
fset
```

=20

Error

=20

    3221225753 - 0xC0000119

=20

Indicates that the starting value for the LDT information was= not an
integral multiple of the selector size.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_ldt_de=
scriptor
```

=20

Error

=20

    3221225754 - 0xC000011A

=20

Indicates that the user supplied an invalid descriptor when t= rying to
set up LDT descriptors.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
ne_format
```

=20

Error

=20

    3221225755 - 0xC000011B

=20

The specified image file did not have the correct format. It = appears
to be NE format.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_rxact_invalid_=
state
```

=20

Error

=20

    3221225756 - 0xC000011C

=20

Indicates that the transaction state of a registry subtree is=
incompatible with the requested operation. For example, a request has
been= made to start a new transaction with one already in progress, or a
request= has been made to apply a transaction when one is not currently
in progress= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_rxact_commit_f=
ailure
```

=20

Error

=20

    3221225757 - 0xC000011D

=20

Indicates an error has occurred during a registry transaction= commit.
The database has been left in an unknown, but probably inconsisten= t,
state. The state of the registry transaction is left as COMMITTING.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mapped_file_si=
ze_zero
```

=20

Error

=20

    3221225758 - 0xC000011E

=20

An attempt was made to map a file of size zero with the maxim= um size
specified as zero.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_too_many_open=
ed_files
```

=20

Warning

=20

    3221225759 - 0xC000011F

=20

Too many files are opened on a remote server. This error shou= ld only
be returned by the Windows redirector on a remote drive.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cancelled
```

=20

Error

=20

    3221225760 - 0xC0000120

=20

The I/O request was canceled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_cannot_delete=
```

=20

Warning

=20

    3221225761 - 0xC0000121

=20

An attempt has been made to remove a file or directory that c= annot be
deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_comput=
er_name
```

=20

Error

=20

    3221225762 - 0xC0000122

=20

Indicates a name that was specified as a remote computer name= is
syntactically invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_file_deleted<=
/pre>
```

=20

Warning

=20

    3221225763 - 0xC0000123

=20

An I/O request other than close was performed on a file after= it was
deleted, which can only happen to a request that did not complete b=
efore the last handle was closed via NtClose.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_special_accoun=
t
```

=20

Error

=20

    3221225764 - 0xC0000124

=20

Indicates an operation that is incompatible with built-in acc= ounts has
been attempted on a built-in (special) SAM account. For example, =
built-in accounts cannot be deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_special_group<=
/pre>
```

=20

Error

=20

    3221225765 - 0xC0000125

=20

The operation requested may not be performed on the specified= group
because it is a built-in special group.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_special_user
```

=20

Error

=20

    3221225766 - 0xC0000126

=20

The operation requested may not be performed on the specified= user
because it is a built-in special user.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_members_primar=
y_group
```

=20

Error

=20

    3221225767 - 0xC0000127

=20

Indicates a member cannot be removed from a group because the= group is
currently the member\'s primary group.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_file_closed
```

=20

Warning

=20

    3221225768 - 0xC0000128

=20

An I/O request other than close and several other special cas= e
operations was attempted using a file object that had already been
closed= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_threa=
ds
```

=20

Error

=20

    3221225769 - 0xC0000129

=20

Indicates a process has too many threads to perform the reque= sted
action. For example, assignment of a primary token may only be perform=
ed when a process has zero or one threads.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_thread_not_in_=
process
```

=20

Error

=20

    3221225770 - 0xC000012A

=20

An attempt was made to operate on a thread within a specific = process,
but the specified thread is not in the specified process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_token_already_=
in_use
```

=20

Error

=20

    3221225771 - 0xC000012B

=20

An attempt was made to establish a token for use as a primary= token but
the token is already in use. A token can only be the primary tok= en of
one process at a time.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pagefile_quota=
_exceeded
```

=20

Error

=20

    3221225772 - 0xC000012C

=20

The page file quota was exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_commitment_lim=
it
```

=20

Error

=20

    3221225773 - 0xC000012D

=20

{Out of Virtual Memory} Your system is low on virtual memory.= To ensure
that Windows runs correctly, increase the size of your virtual m= emory
paging file. For more information, see Help.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
le_format
```

=20

Error

=20

    3221225774 - 0xC000012E

=20

The specified image file did not have the correct format: it = appears
to be LE format.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
not_mz
```

=20

Error

=20

    3221225775 - 0xC000012F

=20

The specified image file did not have the correct format: it = did not
have an initial MZ.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
protect
```

=20

Error

=20

    3221225776 - 0xC0000130

=20

The specified image file did not have the correct format: it = did not
have a proper e\_lfarlc in the MZ header.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
win_16
```

=20

Error

=20

    3221225777 - 0xC0000131

=20

The specified image file did not have the correct format: it = appears
to be a 16-bit Windows image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_logon_server_c=
onflict
```

=20

Error

=20

    3221225778 - 0xC0000132

=20

The Netlogon service cannot start because another Netlogon se= rvice
running in the domain conflicts with the specified role.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_time_differenc=
e_at_dc
```

=20

Error

=20

    3221225779 - 0xC0000133

=20

The time at the primary domain controller is different from t= he time
at the backup domain controller or member server by too large an am=
ount.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_synchronizatio=
n_required
```

=20

Error

=20

    3221225780 - 0xC0000134

=20

The SAM database on a Windows&nbsp;Server is significantl= y out of
synchronization with the copy on the domain controller. A complete=
synchronization is required.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_dll_not_found<=
/pre>
```

=20

Error

=20

    3221225781 - 0xC0000135

=20

{Unable To Locate Component} This application has failed to s= tart
because the component was not found. Reinstalling the application may =
fix this problem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_open_failed
```

=20

Error

=20

    3221225782 - 0xC0000136

=20

The NtCreateFile API failed. This error should never be retur= ned to an
application; it is a place holder for the Windows LAN Manager Red=
irector to use in its internal error-mapping routines.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_privilege_f=
ailed
```

=20

Error

=20

    3221225783 - 0xC0000137

=20

{Privilege Failed} The I/O permissions for the process could = not be
changed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ordinal_not_fo=
und
```

=20

Error

=20

    3221225784 - 0xC0000138

=20

{Ordinal Not Found} The ordinal could not be located in the d= ynamic
link library.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_entrypoint_not=
_found
```

=20

Error

=20

    3221225785 - 0xC0000139

=20

{Entry Point Not Found} The procedure entry point could not b= e located
in the dynamic link library.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_control_c_exit=
```

=20

Error

=20

    3221225786 - 0xC000013A

=20

{Application Exit by CTRL+C} The application terminated as a = result of
a CTRL+C.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_local_disconne=
ct
```

=20

Error

=20

    3221225787 - 0xC000013B

=20

{Virtual Circuit Closed} The network transport on your comput= er has
closed a network connection. There may or may not be I/O requests ou=
tstanding.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_disconn=
ect
```

=20

Error

=20

    3221225788 - 0xC000013C

=20

{Virtual Circuit Closed} The network transport on a remote co= mputer
has closed a network connection. There may or may not be I/O request= s
outstanding.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_resourc=
es
```

=20

Error

=20

    3221225789 - 0xC000013D

=20

{Insufficient Resources on Remote Computer} The remote comput= er has
insufficient resources to complete the network request. For example,=
the remote computer may not have enough available memory to carry out
the = request at this time.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_link_failed
```

=20

Error

=20

    3221225790 - 0xC000013E

=20

{Virtual Circuit Closed} An existing connection (virtual circ= uit) has
been broken at the remote computer. There is probably something wr= ong
with the network software protocol or the network hardware on the remot=
e computer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_link_timeout
```

=20

Error

=20

    3221225791 - 0xC000013F

=20

{Virtual Circuit Closed} The network transport on your comput= er has
closed a network connection because it had to wait too long for a re=
sponse from the remote computer.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_connec=
tion
```

=20

Error

=20

    3221225792 - 0xC0000140

=20

The connection handle that was given to the transport was inv= alid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_addres=
s
```

=20

Error

=20

    3221225793 - 0xC0000141

=20

The address handle that was given to the transport was invali= d.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_dll_init_faile=
d
```

=20

Error

=20

    3221225794 - 0xC0000142

=20

{DLL Initialization Failed} Initialization of the dynamic lin= k library
failed. The process is terminating abnormally.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_missing_system=
file
```

=20

Error

=20

    3221225795 - 0xC0000143

=20

{Missing System File} The required system file is bad or miss= ing.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unhandled_exce=
ption
```

=20

Error

=20

    3221225796 - 0xC0000144

=20

{Application Error} An exception occurred in the application.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_app_init_failu=
re
```

=20

Error

=20

    3221225797 - 0xC0000145

=20

{Application Error} The application failed to initialize prop= erly.
Click OK to terminate the application.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pagefile_creat=
e_failed
```

=20

Error

=20

    3221225798 - 0xC0000146

=20

{Unable to Create Paging File} The creation of the paging fil= e failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_pagefile
```

=20

Error

=20

    3221225799 - 0xC0000147

=20

{No Paging File Specified} No paging file was specified in th= e system
configuration.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_level<=
/pre>
```

=20

Error

=20

    3221225800 - 0xC0000148

=20

{Incorrect System Call Level} An invalid level was passed int= o the
specified system call.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wrong_password=
_core
```

=20

Error

=20

    3221225801 - 0xC0000149

=20

{Incorrect Password to LAN Manager Server} You specified an i= ncorrect
password to a LAN Manager 2.x or MS-NET server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_illegal_float_=
context
```

=20

Error

=20

    3221225802 - 0xC000014A

=20

{EXCEPTION} A real-mode application issued a floating-point i=
nstruction and floating-point hardware is not present.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pipe_broken
```

=20

Error

=20

    3221225803 - 0xC000014B

=20

The pipe operation has failed because the other end of the pi= pe has
been closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_registry_corru=
pt
```

=20

Error

=20

    3221225804 - 0xC000014C

=20

{The Registry Is Corrupt} The structure of one of the files t= hat
contains registry data is corrupt; the image of the file in memory is c=
orrupt; or the file could not be recovered because the alternate copy or
lo= g was absent or corrupt.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_registry_io_fa=
iled
```

=20

Error

=20

    3221225805 - 0xC000014D

=20

An I/O operation initiated by the Registry failed and cannot = be
recovered. The registry could not read in, write out, or flush one of
th= e files that contain the system\'s image of the registry.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_event_pair<=
/pre>
```

=20

Error

=20

    3221225806 - 0xC000014E

=20

An event pair synchronization operation was performed using t= he
thread-specific client/server event pair object, but no event pair
objec= t was associated with the thread.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unrecognized_v=
olume
```

=20

Error

=20

    3221225807 - 0xC000014F

=20

The volume does not contain a recognized file system. Be sure= that all
required file system drivers are loaded and that the volume is no= t
corrupt.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_serial_no_devi=
ce_inited
```

=20

Error

=20

    3221225808 - 0xC0000150

=20

No serial device was successfully initialized. The serial dri= ver will
unload.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_alias<=
/pre>
```

=20

Error

=20

    3221225809 - 0xC0000151

=20

The specified local group does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_member_not_in_=
alias
```

=20

Error

=20

    3221225810 - 0xC0000152

=20

The specified account name is not a member of the group.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_member_in_alia=
s
```

=20

Error

=20

    3221225811 - 0xC0000153

=20

The specified account name is already a member of the group.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_alias_exists
```

=20

Error

=20

    3221225812 - 0xC0000154

=20

The specified local group already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_logon_not_gran=
ted
```

=20

Error

=20

    3221225813 - 0xC0000155

=20

A requested type of logon (for example, interactive, network,= and
service) is not granted by the local security policy of the target sys=
tem. Ask the system administrator to grant the necessary form of logon.
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_secre=
ts
```

=20

Error

=20

    3221225814 - 0xC0000156

=20

The maximum number of secrets that may be stored in a single = system
was exceeded. The length and number of secrets is limited to satisfy=
U.S. State Department export restrictions.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_secret_too_lon=
g
```

=20

Error

=20

    3221225815 - 0xC0000157

=20

The length of a secret exceeds the maximum allowable length. = The
length and number of secrets is limited to satisfy U.S. State Departmen=
t export restrictions.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_internal_db_er=
ror
```

=20

Error

=20

    3221225816 - 0xC0000158

=20

The local security authority (LSA) database contains an inter= nal
inconsistency.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_fullscreen_mod=
e
```

=20

Error

=20

    3221225817 - 0xC0000159

=20

The requested operation cannot be performed in full-screen mo= de.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_conte=
xt_ids
```

=20

Error

=20

    3221225818 - 0xC000015A

=20

During a logon attempt, the user\'s security context accumulat= ed too
many security IDs. This is a very unusual situation. Remove the user=
from some global or local groups to reduce the number of security IDs to
i= ncorporate into the security context.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_logon_type_not=
_granted
```

=20

Error

=20

    3221225819 - 0xC000015B

=20

A user has requested a type of logon (for example, interactiv= e or
network) that has not been granted. An administrator has control over =
who may logon interactively and through the network.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_registry_f=
ile
```

=20

Error

=20

    3221225820 - 0xC000015C

=20

The system has attempted to load or restore a file into the r= egistry,
and the specified file is not in the format of a registry file. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nt_cross_encry=
ption_required
```

=20

Error

=20

    3221225821 - 0xC000015D

=20

An attempt was made to change a user password in the security= account
manager without providing the necessary Windows cross-encrypted pa=
ssword.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_domain_ctrlr_c=
onfig_error
```

=20

Error

=20

    3221225822 - 0xC000015E

=20

A Windows&nbsp;Server has an incorrect configuration. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ft_missing_mem=
ber
```

=20

Error

=20

    3221225823 - 0xC000015F

=20

An attempt was made to explicitly access the secondary copy o= f
information via a device control to the fault tolerance driver and the
se= condary copy is not present in the system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ill_formed_ser=
vice_entry
```

=20

Error

=20

    3221225824 - 0xC0000160

=20

A configuration registry node that represents a driver servic= e entry
was ill-formed and did not contain the required value entries.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_illegal_charac=
ter
```

=20

Error

=20

    3221225825 - 0xC0000161

=20

An illegal character was encountered. For a multibyte charact= er set,
this includes a lead byte without a succeeding trail byte. For the =
Unicode character set this includes the characters 0xFFFF and 0xFFFE.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unmappable_cha=
racter
```

=20

Error

=20

    3221225826 - 0xC0000162

=20

No mapping for the Unicode character exists in the target mul= tibyte
code page.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_undefined_char=
acter
```

=20

Error

=20

    3221225827 - 0xC0000163

=20

The Unicode character is not defined in the Unicode character= set that
is installed on the system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_floppy_volume<=
/pre>
```

=20

Error

=20

    3221225828 - 0xC0000164

=20

The paging file cannot be created on a floppy disk.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_floppy_id_mark=
_not_found
```

=20

Error

=20

    3221225829 - 0xC0000165

=20

{Floppy Disk Error} While accessing a floppy disk, an ID addr= ess mark
was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_floppy_wrong_c=
ylinder
```

=20

Error

=20

    3221225830 - 0xC0000166

=20

{Floppy Disk Error} While accessing a floppy disk, the track = address
from the sector ID field was found to be different from the track a=
ddress that is maintained by the controller.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_floppy_unknown=
_error
```

=20

Error

=20

    3221225831 - 0xC0000167

=20

{Floppy Disk Error} The floppy disk controller reported an er= ror that
is not recognized by the floppy disk driver.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_floppy_bad_reg=
isters
```

=20

Error

=20

    3221225832 - 0xC0000168

=20

{Floppy Disk Error} While accessing a floppy-disk, the contro= ller
returned inconsistent results via its registers.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_disk_recalibra=
te_failed
```

=20

Error

=20

    3221225833 - 0xC0000169

=20

{Hard Disk Error} While accessing the hard disk, a recalibrat= e
operation failed, even after retries.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_disk_operation=
_failed
```

=20

Error

=20

    3221225834 - 0xC000016A

=20

{Hard Disk Error} While accessing the hard disk, a disk opera= tion
failed even after retries.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_disk_reset_fai=
led
```

=20

Error

=20

    3221225835 - 0xC000016B

=20

{Hard Disk Error} While accessing the hard disk, a disk contr= oller
reset was needed, but even that failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_shared_irq_bus=
y
```

=20

Error

=20

    3221225836 - 0xC000016C

=20

An attempt was made to open a device that was sharing an inte= rrupt
request (IRQ) with other devices. At least one other device that uses=
that IRQ was already opened. Two concurrent opens of devices that share
an= IRQ and only work via interrupts is not supported for the particular
bus t= ype that the devices use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ft_orphaning
```

=20

Error

=20

    3221225837 - 0xC000016D

=20

{FT Orphaning} A disk that is part of a fault-tolerant volume= can no
longer be accessed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bios_failed_to=
_connect_interrupt
```

=20

Error

=20

    3221225838 - 0xC000016E

=20

The basic input/output system (BIOS) failed to connect a syst= em
interrupt to the device or bus for which the device is connected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_partition_fail=
ure
```

=20

Error

=20

    3221225842 - 0xC0000172

=20

The tape could not be partitioned.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_block_=
length
```

=20

Error

=20

    3221225843 - 0xC0000173

=20

When accessing a new tape of a multi-volume partition, the cu= rrent
blocksize is incorrect.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_not_par=
titioned
```

=20

Error

=20

    3221225844 - 0xC0000174

=20

The tape partition information could not be found when loadin= g a tape.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unable_to_lock=
_media
```

=20

Error

=20

    3221225845 - 0xC0000175

=20

An attempt to lock the eject media mechanism failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unable_to_unlo=
ad_media
```

=20

Error

=20

    3221225846 - 0xC0000176

=20

An attempt to unload media failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_eom_overflow
```

=20

Error

=20

    3221225847 - 0xC0000177

=20

The physical end of tape was detected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_media
```

=

=20

Error

=20

    3221225848 - 0xC0000178

=20

{No Media} There is no media in the drive.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_such_member=
```

=20

Error

=20

    3221225850 - 0xC000017A

=20

A member could not be added to or removed from the local grou= p because
the member does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_member=
```

=20

Error

=20

    3221225851 - 0xC000017B

=20

A new member could not be added to a local group because the = member
has the wrong account type.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_key_deleted
```

=20

Error

=20

    3221225852 - 0xC000017C

=20

An illegal operation was attempted on a registry key that has= been
marked for deletion.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_log_space
```

=20

Error

=20

    3221225853 - 0xC000017D

=20

The system could not allocate the required space in a registr= y log.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_sids<=
/pre>
```

=20

Error

=20

    3221225854 - 0xC000017E

=20

Too many SIDs have been specified.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_lm_cross_encry=
ption_required
```

=20

Error

=20

    3221225855 - 0xC000017F

=20

An attempt was made to change a user password in the security= account
manager without providing the necessary LM cross-encrypted passwor= d.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_key_has_childr=
en
```

=20

Error

=20

    3221225856 - 0xC0000180

=20

An attempt was made to create a symbolic link in a registry k= ey that
already has subkeys or values.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_child_must_be_=
volatile
```

=20

Error

=20

    3221225857 - 0xC0000181

=20

An attempt was made to create a stable subkey under a volatil= e parent
key.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_configu=
ration_error
```

=20

Error

=20

    3221225858 - 0xC0000182

=20

The I/O device is configured incorrectly or the configuration=
parameters to the driver are incorrect.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_interna=
l_error
```

=20

Error

=20

    3221225859 - 0xC0000183

=20

An error was detected between two drivers or within an I/O dr= iver.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_invalid_devic=
e_state
```

=20

Error

=20

    3221225860 - 0xC0000184

=20

The device is not in a valid state to perform this request. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_device_erro=
r
```

=20

Error

=20

    3221225861 - 0xC0000185

=20

The I/O device reported an I/O error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_protoco=
l_error
```

=20

Error

=20

    3221225862 - 0xC0000186

=20

A protocol error was detected between the driver and the devi= ce.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_backup_control=
ler
```

=20

Error

=20

    3221225863 - 0xC0000187

=20

This operation is only allowed for the primary domain control= ler of
the domain.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_log_file_full<=
/pre>
```

=20

Error

=20

    3221225864 - 0xC0000188

=20

The log file space is insufficient to support this operation.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_late
```

=

=20

Error

=20

    3221225865 - 0xC0000189

=20

A write operation was attempted to a volume after it was dism= ounted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_trust_lsa_s=
ecret
```

=20

Error

=20

    3221225866 - 0xC000018A

=20

The workstation does not have a trust secret for the primary = domain in
the local LSA database.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_trust_sam_a=
ccount
```

=20

Error

=20

    3221225867 - 0xC000018B

=20

The SAM database on the Windows&nbsp;Server does not have= a computer
account for this workstation trust relationship.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_trusted_domain=
_failure
```

=20

Error

=20

    3221225868 - 0xC000018C

=20

The logon request failed because the trust relationship betwe= en the
primary domain and the trusted domain failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_trusted_relati=
onship_failure
```

=20

Error

=20

    3221225869 - 0xC000018D

=20

The logon request failed because the trust relationship betwe= en this
workstation and the primary domain failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_eventlog_file_=
corrupt
```

=20

Error

=20

    3221225870 - 0xC000018E

=20

The Eventlog log file is corrupt.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_eventlog_cant_=
start
```

=20

Error

=20

    3221225871 - 0xC000018F

=20

No Eventlog log file could be opened. The Eventlog service di= d not
start.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_trust_failure<=
/pre>
```

=20

Error

=20

    3221225872 - 0xC0000190

=20

The network logon failed. This may be because the validation = authority
cannot be reached.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mutant_limit_e=
xceeded
```

=20

Error

=20

    3221225873 - 0xC0000191

=20

An attempt was made to acquire a mutant such that its maximum= count
would have been exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_netlogon_not_s=
tarted
```

=20

Error

=20

    3221225874 - 0xC0000192

=20

An attempt was made to logon, but the NetLogon service was no= t
started.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_account_expir=
ed
```

=20

Error

=20

    3221225875 - 0xC0000193

=20

The user account has expired.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_possible_deadl=
ock
```

=20

Error

=20

    3221225876 - 0xC0000194

=20

{EXCEPTION} Possible deadlock condition.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_network_creden=
tial_conflict
```

=20

Error

=20

    3221225877 - 0xC0000195

=20

Multiple connections to a server or shared resource by the sa= me user,
using more than one user name, are not allowed. Disconnect all pre=
vious connections to the server or shared resource and try again.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_session=
_limit
```

=20

Error

=20

    3221225878 - 0xC0000196

=20

An attempt was made to establish a session to a network serve= r, but
there are already too many sessions established to that server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_eventlog_file_=
changed
```

=20

Error

=20

    3221225879 - 0xC0000197

=20

The log file has changed between reads.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nologon_interd=
omain_trust_account
```

=20

Error

=20

    3221225880 - 0xC0000198

=20

The account used is an interdomain trust account. Use your gl= obal user
account or local user account to access this server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nologon_workst=
ation_trust_account
```

=20

Error

=20

    3221225881 - 0xC0000199

=20

The account used is a computer account. Use your global user = account
or local user account to access this server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nologon_server=
_trust_account
```

=20

Error

=20

    3221225882 - 0xC000019A

=20

The account used is a server trust account. Use your global u= ser
account or local user account to access this server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_domain_trust_i=
nconsistent
```

=20

Error

=20

    3221225883 - 0xC000019B

=20

The name or SID of the specified domain is inconsistent with = the trust
information for that domain.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_fs_driver_requ=
ired
```

=20

Error

=20

    3221225884 - 0xC000019C

=20

A volume has been accessed for which a file system driver is = required
that has not yet been loaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_user_sessio=
n_key
```

=20

Error

=20

    3221225986 - 0xC0000202

=20

There is no user session key for the specified logon session.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_user_session_d=
eleted
```

=20

Error

=20

    3221225987 - 0xC0000203

=20

The remote user session has been deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_lang_=
not_found
```

=20

Error

=20

    3221225988 - 0xC0000204

=20

Indicates the specified resource language ID cannot be found = in the
image file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_insuff_server=
_resources
```

=20

Warning

=20

    3221225989 - 0xC0000205

=20

Insufficient server resources exist to complete the request.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_buffer=
_size
```

=20

Error

=20

    3221225990 - 0xC0000206

=20

The size of the buffer is invalid for the specified operation= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_addres=
s_component
```

=20

Error

=20

    3221225991 - 0xC0000207

=20

The transport rejected the specified network address as inval= id.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_addres=
s_wildcard
```

=20

Error

=20

    3221225992 - 0xC0000208

=20

The transport rejected the specified network address due to i= nvalid
use of a wildcard.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_addre=
sses
```

=20

Error

=20

    3221225993 - 0xC0000209

=20

The transport address could not be opened because all the ava= ilable
addresses are in use.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_address_alread=
y_exists
```

=20

Error

=20

    3221225994 - 0xC000020A

=20

The transport address could not be opened because it already = exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_address_closed=
```

=20

Error

=20

    3221225995 - 0xC000020B

=20

The transport address is now closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_dis=
connected
```

=20

Error

=20

    3221225996 - 0xC000020C

=20

The transport connection is now disconnected.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_res=
et
```

=20

Error

=20

    3221225997 - 0xC000020D

=20

The transport connection has been reset.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_nodes=
```

=20

Error

=20

    3221225998 - 0xC000020E

=20

The transport cannot dynamically acquire any more nodes.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_ab=
orted
```

=20

Error

=20

    3221225999 - 0xC000020F

=20

The transport aborted a pending transaction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_ti=
med_out
```

=20

Error

=20

    3221226000 - 0xC0000210

=20

The transport timed out a request that is waiting for a respo= nse.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_no=
_release
```

=20

Error

=20

    3221226001 - 0xC0000211

=20

The transport did not receive a release for a pending respons= e.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_no=
_match
```

=20

Error

=20

    3221226002 - 0xC0000212

=20

The transport did not find a transaction that matches the spe= cific
token.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_re=
sponded
```

=20

Error

=20

    3221226003 - 0xC0000213

=20

The transport had previously responded to a transaction reque= st.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_in=
valid_id
```

=20

Error

=20

    3221226004 - 0xC0000214

=20

The transport does not recognize the specified transaction re= quest ID.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transaction_in=
valid_type
```

=20

Error

=20

    3221226005 - 0xC0000215

=20

The transport does not recognize the specified transaction re= quest
type.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_server_ses=
sion
```

=20

Error

=20

    3221226006 - 0xC0000216

=20

The transport can only process the specified request on the s= erver
side of a session.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_client_ses=
sion
```

=20

Error

=20

    3221226007 - 0xC0000217

=20

The transport can only process the specified request on the c= lient
side of a session.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cannot_load_re=
gistry_file
```

=20

Error

=20

    3221226008 - 0xC0000218

=20

{Registry File Failure} The registry cannot load the hive (fi= le). It
is corrupt, absent, or not writable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_debug_attach_f=
ailed
```

=20

Error

=20

    3221226009 - 0xC0000219

=20

{Unexpected Failure in DebugActiveProcess} An unexpected fail= ure
occurred while processing a DebugActiveProcess API request. You may cho=
ose OK to terminate the process, or Cancel to ignore the error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_system_process=
_terminated
```

=20

Error

=20

    3221226010 - 0xC000021A

=20

{Fatal System Error} The system process terminated unexpected= ly. The
system has been shut down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_data_not_accep=
ted
```

=20

Error

=20

    3221226011 - 0xC000021B

=20

{Data Not Accepted} The TDI client could not handle the data = received
during an indication.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_browser_ser=
vers_found
```

=20

Error

=20

    3221226012 - 0xC000021C

=20

{Unable to Retrieve Browser Server List} The list of servers = for this
workgroup is not currently available.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_vdm_hard_error=
```

=20

Error

=20

    3221226013 - 0xC000021D

=20

NTVDM encountered a hard error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_cancel_=
timeout
```

=20

Error

=20

    3221226014 - 0xC000021E

=20

{Cancel Timeout} The driver failed to complete a canceled I/O= request
in the allotted time.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reply_message_=
mismatch
```

=20

Error

=20

    3221226015 - 0xC000021F

=20

{Reply Message Mismatch} An attempt was made to reply to an L= PC
message, but the thread specified by the client ID in the message was
no= t waiting on that message.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mapped_alignme=
nt
```

=20

Error

=20

    3221226016 - 0xC0000220

=20

{Mapped View Alignment Incorrect} An attempt was made to map = a view of
a file, but either the specified base address or the offset into = the
file were not aligned on the proper allocation granularity.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_checksum=
_mismatch
```

=20

Error

=20

    3221226017 - 0xC0000221

=20

{Bad Image Checksum} The image is possibly corrupt. The heade= r
checksum does not match the computed checksum.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_lost_writebehi=
nd_data
```

=20

Error

=20

    3221226018 - 0xC0000222

=20

{Delayed Write Failed} Windows was unable to save all the dat= a for the
file. The data has been lost. This error may be caused by a failu= re of
your computer hardware or network connection. Try to save this file e=
lsewhere.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_client_server_=
parameters_invalid
```

=20

Error

=20

    3221226019 - 0xC0000223

=20

The parameters passed to the server in the client/server shar= ed memory
window were invalid. Too much data may have been put in the share= d
memory window.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_password_must=
_change
```

=20

Error

=20

    3221226020 - 0xC0000224

=20

The user password must be changed before logging on the first= time.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_found
```

=20

Error

=20

    3221226021 - 0xC0000225

=20

The object was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_tiny_strea=
m
```

=20

Error

=20

    3221226022 - 0xC0000226

=20

The stream is not a tiny stream.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_recovery_failu=
re
```

=20

Error

=20

    3221226023 - 0xC0000227

=20

A transaction recovery failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_stack_overflow=
_read
```

=20

Error

=20

    3221226024 - 0xC0000228

=20

The request must be handled by the stack overflow code.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_fail_check
```

=20

Error

=20

    3221226025 - 0xC0000229

=20

A consistency check failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_duplicate_obje=
ctid
```

=20

Error

=20

    3221226026 - 0xC000022A

=20

The attempt to insert the ID in the index failed because the = ID is
already in the index.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_objectid_exist=
s
```

=20

Error

=20

    3221226027 - 0xC000022B

=20

The attempt to set the object ID failed because the object al= ready has
an ID.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_convert_to_lar=
ge
```

=20

Error

=20

    3221226028 - 0xC000022C

=20

Internal OFS status codes indicating how an allocation operat= ion is
handled. Either it is retried after the containing oNode is moved or=
the extent stream is converted to a large stream.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_retry
```

=20

Error

=20

    3221226029 - 0xC000022D

=20

The request needs to be retried.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_found_out_of_s=
cope
```

=20

Error

=20

    3221226030 - 0xC000022E

=20

The attempt to find the object found an object on the volume = that
matches by ID; however, it is out of the scope of the handle that is u=
sed for the operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_allocate_bucke=
t
```

=20

Error

=20

    3221226031 - 0xC000022F

=20

The bucket array must be grown. Retry the transaction after d= oing so.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_propset_not_fo=
und
```

=20

Error

=20

    3221226032 - 0xC0000230

=20

The specified property set does not exist on the object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_marshall_overf=
low
```

=20

Error

=20

    3221226033 - 0xC0000231

=20

The user/kernel marshaling buffer has overflowed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_varian=
t
```

=20

Error

=20

    3221226034 - 0xC0000232

=20

The supplied variant structure contains invalid data.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_domain_control=
ler_not_found
```

=20

Error

=20

    3221226035 - 0xC0000233

=20

A domain controller for this domain was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_account_locked=
_out
```

=20

Error

=20

    3221226036 - 0xC0000234

=20

The user account has been automatically locked because too ma= ny
invalid logon attempts or password change attempts have been
requested.\<= /td\> =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_handle_not_cl=
osable
```

=20

Warning

=20

    3221226037 - 0xC0000235

=20

NtClose was called on a handle that was protected from close = via
NtSetInformationObject.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_ref=
used
```

=20

Error

=20

    3221226038 - 0xC0000236

=20

The transport-connection attempt was refused by the remote sy= stem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_graceful_disco=
nnect
```

=20

Error

=20

    3221226039 - 0xC0000237

=20

The transport connection was gracefully closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_address_alread=
y_associated
```

=20

Error

=20

    3221226040 - 0xC0000238

=20

The transport endpoint already has an address associated with= it.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_address_not_as=
sociated
```

=20

Error

=20

    3221226041 - 0xC0000239

=20

An address has not yet been associated with the transport end= point.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_inv=
alid
```

=20

Error

=20

    3221226042 - 0xC000023A

=20

An operation was attempted on a nonexistent transport connect= ion.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_act=
ive
```

=20

Error

=20

    3221226043 - 0xC000023B

=20

An invalid operation was attempted on an active transport con= nection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_network_unreac=
hable
```

=20

Error

=20

    3221226044 - 0xC000023C

=20

The remote network is not reachable by the transport.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_host_unreachab=
le
```

=20

Error

=20

    3221226045 - 0xC000023D

=20

The remote system is not reachable by the transport.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_protocol_unrea=
chable
```

=20

Error

=20

    3221226046 - 0xC000023E

=20

The remote system does not support the transport protocol. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_port_unreachab=
le
```

=20

Error

=20

    3221226047 - 0xC000023F

=20

No service is operating at the destination port of the transp= ort on
the remote system.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_request_aborte=
d
```

=20

Error

=20

    3221226048 - 0xC0000240

=20

The request was aborted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_abo=
rted
```

=20

Error

=20

    3221226049 - 0xC0000241

=20

The transport connection was aborted by the local system. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_compressio=
n_buffer
```

=20

Error

=20

    3221226050 - 0xC0000242

=20

The specified buffer contains ill-formed data.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_user_mapped_fi=
le
```

=20

Error

=20

    3221226051 - 0xC0000243

=20

The requested operation cannot be performed on a file with a = user
mapped section open.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_audit_failed
```

=20

Error

=20

    3221226052 - 0xC0000244

=20

{Audit Failed} An attempt to generate a security audit failed= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_timer_resoluti=
on_not_set
```

=20

Error

=20

    3221226053 - 0xC0000245

=20

The timer resolution was not previously set by the current pr= ocess.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_connection_cou=
nt_limit
```

=20

Error

=20

    3221226054 - 0xC0000246

=20

A connection to the server could not be made because the limi= t on the
number of concurrent connections for this account has been reached= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_login_time_res=
triction
```

=20

Error

=20

    3221226055 - 0xC0000247

=20

Attempting to log on during an unauthorized time of day for t= his
account.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_login_wksta_re=
striction
```

=20

Error

=20

    3221226056 - 0xC0000248

=20

The account is not authorized to log on from this station. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_image_mp_up_mi=
smatch
```

=20

Error

=20

    3221226057 - 0xC0000249

=20

{UP/MP Image Mismatch} The image has been modified for use on= a
uniprocessor system, but you are running it on a multiprocessor
machine.= Reinstall the image file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_insufficient_l=
ogon_info
```

=20

Error

=20

    3221226064 - 0xC0000250

=20

There is insufficient account information to log you on.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_dll_entryp=
oint
```

=20

Error

=20

    3221226065 - 0xC0000251

=20

{Invalid DLL Entrypoint} The dynamic link library is not writ= ten
correctly. The stack pointer has been left in an inconsistent state. Th=
e entry point should be declared as WINAPI or STDCALL. Select YES to
fail t= he DLL load. Select NO to continue execution. Selecting NO may
cause the ap= plication to operate incorrectly.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_service_en=
trypoint
```

=20

Error

=20

    3221226066 - 0xC0000252

=20

{Invalid Service Callback Entrypoint} The service is not writ= ten
correctly. The stack pointer has been left in an inconsistent state. Th=
e callback entry point should be declared as WINAPI or STDCALL.
Selecting O= K will cause the service to continue operation. However,
the service proces= s may operate incorrectly.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_lpc_reply_lost=
```

=20

Error

=20

    3221226067 - 0xC0000253

=20

The server received the messages but did not send a reply. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ip_address_con=
flict1
```

=20

Error

=20

    3221226068 - 0xC0000254

=20

There is an IP address conflict with another system on the ne= twork.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ip_address_con=
flict2
```

=20

Error

=20

    3221226069 - 0xC0000255

=20

There is an IP address conflict with another system on the ne= twork.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_registry_quota=
_limit
```

=20

Error

=20

    3221226070 - 0xC0000256

=20

{Low On Registry Space} The system has reached the maximum si= ze that
is allowed for the system part of the registry. Additional storage =
requests will be ignored.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_status_path_not_cove=
red
```

=20

Error

=20

    3221226071 - 0xC0000257

=20

The contacted server does not support the indicated part of t= he DFS
namespace.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_callback_ac=
tive
```

=20

Error

=20

    3221226072 - 0xC0000258

=20

A callback return system service cannot be executed when no c= allback
is active.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_license_quota_=
exceeded
```

=20

Error

=20

    3221226073 - 0xC0000259

=20

The service being accessed is licensed for a particular numbe= r of
connections. No more connections can be made to the service at this ti=
me because the service has already accepted the maximum number of
connectio= ns.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pwd_too_short<=
/pre>
```

=20

Error

=20

    3221226074 - 0xC000025A

=20

The password provided is too short to meet the policy of your= user
account. Choose a longer password.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pwd_too_recent=
```

=20

Error

=20

    3221226075 - 0xC000025B

=20

The policy of your user account does not allow you to change = passwords
too frequently. This is done to prevent users from changing back = to a
familiar, but potentially discovered, password. If you feel your passw=
ord has been compromised, contact your administrator immediately to have
a = new one assigned.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pwd_history_co=
nflict
```

=20

Error

=20

    3221226076 - 0xC000025C

=20

You have attempted to change your password to one that you ha= ve used
in the past. The policy of your user account does not allow this. S=
elect a password that you have not previously used.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_plugplay_no_de=
vice
```

=20

Error

=20

    3221226078 - 0xC000025E

=20

You have attempted to load a legacy device driver while its d= evice
instance had been disabled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unsupported_co=
mpression
```

=20

Error

=20

    3221226079 - 0xC000025F

=20

The specified compression format is unsupported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_hw_pro=
file
```

=20

Error

=20

    3221226080 - 0xC0000260

=20

The specified hardware profile configuration is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_plugpl=
ay_device_path
```

=20

Error

=20

    3221226081 - 0xC0000261

=20

The specified Plug and Play registry device path is invalid.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_ordinal=
_not_found
```

=20

Error

=20

    3221226082 - 0xC0000262

=20

{Driver Entry Point Not Found} The device driver could not lo= cate the
ordinal in driver.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_entrypo=
int_not_found
```

=20

Error

=20

    3221226083 - 0xC0000263

=20

{Driver Entry Point Not Found} The device driver could not lo= cate the
entry point in driver.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_resource_not_o=
wned
```

=20

Error

=20

    3221226084 - 0xC0000264

=20

{Application Error} The application attempted to release a re= source it
did not own. Click OK to terminate the application.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_links=
```

=20

Error

=20

    3221226085 - 0xC0000265

=20

An attempt was made to create more links on a file than the f= ile
system supports.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_quota_list_inc=
onsistent
```

=20

Error

=20

    3221226086 - 0xC0000266

=20

The specified quota list is internally inconsistent with its =
descriptor.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_is_offlin=
e
```

=20

Error

=20

    3221226087 - 0xC0000267

=20

The specified file has been relocated to offline storage. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_evaluation_exp=
iration
```

=20

Error

=20

    3221226088 - 0xC0000268

=20

{Windows Evaluation Notification} The evaluation period for t= his
installation of Windows has expired. This system will shutdown in 1 hou=
r. To restore access to this installation of Windows, upgrade this
installa= tion by using a licensed distribution of this product.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_illegal_dll_re=
location
```

=20

Error

=20

    3221226089 - 0xC0000269

=20

{Illegal System DLL Relocation} The system DLL was relocated = in
memory. The application will not run properly. The relocation occurred
b= ecause the DLL occupied an address range that is reserved for Windows
syste= m DLLs. The vendor supplying the DLL should be contacted for a
new DLL. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_license_violat=
ion
```

=20

Error

=20

    3221226090 - 0xC000026A

=20

{License Violation} The system has detected tampering with yo= ur
registered product type. This is a violation of your software license.
T= ampering with the product type is not permitted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_dll_init_faile=
d_logoff
```

=20

Error

=20

    3221226091 - 0xC000026B

=20

{DLL Initialization Failed} The application failed to initial= ize
because the window station is shutting down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_unable_=
to_load
```

=20

Error

=20

    3221226092 - 0xC000026C

=20

{Unable to Load Device Driver} The device driver could not be= loaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_dfs_unavailabl=
e
```

=20

Error

=20

    3221226093 - 0xC000026D

=20

DFS is unavailable on the contacted server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_volume_dismoun=
ted
```

=20

Error

=20

    3221226094 - 0xC000026E

=20

An operation was attempted to a volume after it was dismounte= d.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_internal_=
error
```

=20

Error

=20

    3221226095 - 0xC000026F

=20

An internal error occurred in the Win32 x86 emulation subsyst= em.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wx86_float_sta=
ck_check
```

=20

Error

=20

    3221226096 - 0xC0000270

=20

Win32 x86 emulation subsystem floating-point stack check. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_validate_conti=
nue
```

=20

Error

=20

    3221226097 - 0xC0000271

=20

The validation process needs to continue on to the next step.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_match
```

=

=20

Error

=20

    3221226098 - 0xC0000272

=20

There was no match for the specified key in the index.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_more_matche=
s
```

=20

Error

=20

    3221226099 - 0xC0000273

=20

There are no more matches for the current index enumeration.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_a_reparse_=
point
```

=20

Error

=20

    3221226101 - 0xC0000275

=20

The NTFS file or directory is not a reparse point.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_reparse_tag=
_invalid
```

=20

Error

=20

    3221226102 - 0xC0000276

=20

The Windows I/O reparse tag passed for the NTFS reparse point= is
invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_reparse_tag=
_mismatch
```

=20

Error

=20

    3221226103 - 0xC0000277

=20

The Windows I/O reparse tag does not match the one that is in= the NTFS
reparse point.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_reparse_dat=
a_invalid
```

=20

Error

=20

    3221226104 - 0xC0000278

=20

The user data passed for the NTFS reparse point is invalid. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_io_reparse_tag=
_not_handled
```

=20

Error

=20

    3221226105 - 0xC0000279

=20

The layered file system driver for this I/O tag did not handl= e it when
needed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reparse_point_=
not_resolved
```

=20

Error

=20

    3221226112 - 0xC0000280

=20

The NTFS symbolic link could not be resolved even though the = initial
file name is valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_directory_is_a=
_reparse_point
```

=20

Error

=20

    3221226113 - 0xC0000281

=20

The NTFS directory is a reparse point.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_range_list_con=
flict
```

=20

Error

=20

    3221226114 - 0xC0000282

=20

The range could not be added to the range list because of a c= onflict.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_source_element=
_empty
```

=20

Error

=20

    3221226115 - 0xC0000283

=20

The specified medium changer source element contains no media= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_destination_el=
ement_full
```

=20

Error

=20

    3221226116 - 0xC0000284

=20

The specified medium changer destination element already cont= ains
media.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_illegal_elemen=
t_address
```

=20

Error

=20

    3221226117 - 0xC0000285

=20

The specified medium changer element does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_magazine_not_p=
resent
```

=20

Error

=20

    3221226118 - 0xC0000286

=20

The specified element is contained in a magazine that is no l= onger
present.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reinitializati=
on_needed
```

=20

Error

=20

    3221226119 - 0xC0000287

=20

The device requires re-initialization due to hardware errors.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_encryption_fai=
led
```

=20

Error

=20

    3221226122 - 0xC000028A

=20

The file encryption attempt failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_decryption_fai=
led
```

=20

Error

=20

    3221226123 - 0xC000028B

=20

The file decryption attempt failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_range_not_foun=
d
```

=20

Error

=20

    3221226124 - 0xC000028C

=20

The specified range could not be found in the range list. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_recovery_po=
licy
```

=20

Error

=20

    3221226125 - 0xC000028D

=20

There is no encryption recovery policy configured for this sy= stem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_efs
```

=20

Error

=20

    3221226126 - 0xC000028E

=20

The required encryption driver is not loaded for this system.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wrong_efs
```

=20

Error

=20

    3221226127 - 0xC000028F

=20

The file was encrypted with a different encryption driver tha= n is
currently loaded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_user_keys
```

=20

Error

=20

    3221226128 - 0xC0000290

=20

There are no EFS keys defined for the user.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_not_encry=
pted
```

=20

Error

=20

    3221226129 - 0xC0000291

=20

The specified file is not encrypted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_export_for=
mat
```

=20

Error

=20

    3221226130 - 0xC0000292

=20

The specified file is not in the defined EFS export format. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_file_encrypted=
```

=20

Error

=20

    3221226131 - 0xC0000293

=20

The specified file is encrypted and the user does not have th= e ability
to decrypt it.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_guid_not_f=
ound
```

=20

Error

=20

    3221226133 - 0xC0000295

=20

The GUID passed was not recognized as valid by a WMI data pro= vider.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_instance_n=
ot_found
```

=20

Error

=20

    3221226134 - 0xC0000296

=20

The instance name passed was not recognized as valid by a WMI= data
provider.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_itemid_not=
_found
```

=20

Error

=20

    3221226135 - 0xC0000297

=20

The data item ID passed was not recognized as valid by a WMI = data
provider.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_try_again<=
/pre>
```

=20

Error

=20

    3221226136 - 0xC0000298

=20

The WMI request could not be completed and should be retried.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_shared_policy<=
/pre>
```

=20

Error

=20

    3221226137 - 0xC0000299

=20

The policy object is shared and can only be modified at the r= oot.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_policy_object_=
not_found
```

=20

Error

=20

    3221226138 - 0xC000029A

=20

The policy object does not exist when it should.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_policy_only_in=
_ds
```

=20

Error

=20

    3221226139 - 0xC000029B

=20

The requested policy information only lives in the Ds.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_volume_not_upg=
raded
```

=20

Error

=20

    3221226140 - 0xC000029C

=20

The volume must be upgraded to enable this feature.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_storage=
_not_active
```

=20

Error

=20

    3221226141 - 0xC000029D

=20

The remote storage service is not operational at this time. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_remote_storage=
_media_error
```

=20

Error

=20

    3221226142 - 0xC000029E

=20

The remote storage service encountered a media error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_tracking_se=
rvice
```

=20

Error

=20

    3221226143 - 0xC000029F

=20

The tracking (workstation) service is not running.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_server_sid_mis=
match
```

=20

Error

=20

    3221226144 - 0xC00002A0

=20

The server process is running under a SID that is different f= rom the
SID that is required by client.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_attribut=
e_or_value
```

=20

Error

=20

    3221226145 - 0xC00002A1

=20

The specified directory service attribute or value does not e= xist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_invalid_att=
ribute_syntax
```

=20

Error

=20

    3221226146 - 0xC00002A2

=20

The attribute syntax specified to the directory service is in= valid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_attribute_t=
ype_undefined
```

=20

Error

=20

    3221226147 - 0xC00002A3

=20

The attribute type specified to the directory service is not = defined.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_attribute_o=
r_value_exists
```

=20

Error

=20

    3221226148 - 0xC00002A4

=20

The specified directory service attribute or value already ex= ists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_busy
```

\<= /td\> =20

Error

=20

    3221226149 - 0xC00002A5

=20

The directory service is busy.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_unavailable=
```

=20

Error

=20

    3221226150 - 0xC00002A6

=20

The directory service is unavailable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_rids_all=
ocated
```

=20

Error

=20

    3221226151 - 0xC00002A7

=20

The directory service was unable to allocate a relative ident= ifier.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_more_rid=
s
```

=20

Error

=20

    3221226152 - 0xC00002A8

=20

The directory service has exhausted the pool of relative iden= tifiers.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_incorrect_r=
ole_owner
```

=20

Error

=20

    3221226153 - 0xC00002A9

=20

The requested operation could not be performed because the di= rectory
service is not the master for that type of operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_ridmgr_init=
_error
```

=20

Error

=20

    3221226154 - 0xC00002AA

=20

The directory service was unable to initialize the subsystem = that
allocates relative identifiers.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_obj_class_v=
iolation
```

=20

Error

=20

    3221226155 - 0xC00002AB

=20

The requested operation did not satisfy one or more constrain= ts that
are associated with the class of the object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cant_on_non=
_leaf
```

=20

Error

=20

    3221226156 - 0xC00002AC

=20

The directory service can perform the requested operation onl= y on a
leaf object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cant_on_rdn=
```

=20

Error

=20

    3221226157 - 0xC00002AD

=20

The directory service cannot perform the requested operation = on the
Relatively Defined Name (RDN) attribute of an object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cant_mod_ob=
j_class
```

=20

Error

=20

    3221226158 - 0xC00002AE

=20

The directory service detected an attempt to modify the objec= t class
of an object.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cross_dom_m=
ove_failed
```

=20

Error

=20

    3221226159 - 0xC00002AF

=20

An error occurred while performing a cross domain move operat= ion.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_gc_not_avai=
lable
```

=20

Error

=20

    3221226160 - 0xC00002B0

=20

Unable to contact the global catalog server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_directory_serv=
ice_required
```

=20

Error

=20

    3221226161 - 0xC00002B1

=20

The requested operation requires a directory service, and non= e was
available.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reparse_attrib=
ute_conflict
```

=20

Error

=20

    3221226162 - 0xC00002B2

=20

The reparse attribute cannot be set because it is incompatibl= e with an
existing attribute.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cant_enable_de=
ny_only
```

=20

Error

=20

    3221226163 - 0xC00002B3

=20

A group marked \'use for deny only\' cannot be enabled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_multiple=
_faults
```

=20

Error

=20

    3221226164 - 0xC00002B4

=20

{EXCEPTION} Multiple floating-point faults.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_float_multiple=
_traps
```

=20

Error

=20

    3221226165 - 0xC00002B5

=20

{EXCEPTION} Multiple floating-point traps.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_removed=
```

=20

Error

=20

    3221226166 - 0xC00002B6

=20

The device has been removed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_journal_delete=
_in_progress
```

=20

Error

=20

    3221226167 - 0xC00002B7

=20

The volume change journal is being deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_journal_not_ac=
tive
```

=20

Error

=20

    3221226168 - 0xC00002B8

=20

The volume change journal is not active.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_nointerface
```

=20

Error

=20

    3221226169 - 0xC00002B9

=20

The requested interface is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_admin_limit=
_exceeded
```

=20

Error

=20

    3221226177 - 0xC00002C1

=20

A directory service resource limit has been exceeded.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_failed_=
sleep
```

=20

Error

=20

    3221226178 - 0xC00002C2

=20

{System Standby Failed} The driver does not support standby m= ode.
Updating this driver may allow the system to go to standby mode.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mutual_authent=
ication_failed
```

=20

Error

=20

    3221226179 - 0xC00002C3

=20

Mutual Authentication failed. The server password is out of d= ate at
the domain controller.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_corrupt_system=
_file
```

=20

Error

=20

    3221226180 - 0xC00002C4

=20

The system file has become corrupt and has been replaced. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_datatype_misal=
ignment_error
```

=20

Error

=20

    3221226181 - 0xC00002C5

=20

{EXCEPTION} Alignment Error A data type misalignment error wa= s
detected in a load or store instruction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_read_only<=
/pre>
```

=20

Error

=20

    3221226182 - 0xC00002C6

=20

The WMI data item or data block is read-only.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_set_failur=
e
```

=20

Error

=20

    3221226183 - 0xC00002C7

=20

The WMI data item or data block could not be changed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_commitment_min=
imum
```

=20

Error

=20

    3221226184 - 0xC00002C8

=20

{Virtual Memory Minimum Too Low} Your system is low on virtua= l memory.
Windows is increasing the size of your virtual memory paging file= .
During this process, memory requests for some applications may be
denied.= For more information, see Help.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_reg_nat_consum=
ption
```

=20

Error

=20

    3221226185 - 0xC00002C9

=20

{EXCEPTION} Register NaT consumption faults. A NaT value is c= onsumed
on a non-speculative instruction.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_transport_full=
```

=20

Error

=20

    3221226186 - 0xC00002CA

=20

The transport element of the medium changer contains media, w= hich is
causing the operation to fail.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_sam_init_fa=
ilure
```

=20

Error

=20

    3221226187 - 0xC00002CB

=20

Security Accounts Manager initialization failed. Click OK to = shut down
this system and restart in Directory Services Restore Mode. Check= the
event log for more detailed information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_only_if_connec=
ted
```

=20

Error

=20

    3221226188 - 0xC00002CC

=20

This operation is supported only when you are connected to th= e server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_sensitive_g=
roup_violation
```

=20

Error

=20

    3221226189 - 0xC00002CD

=20

Only an administrator can modify the membership list of an ad=
ministrative group.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pnp_restart_en=
umeration
```

=20

Error

=20

    3221226190 - 0xC00002CE

=20

A device was removed so enumeration must be restarted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_journal_entry_=
deleted
```

=20

Error

=20

    3221226191 - 0xC00002CF

=20

The journal entry has been deleted from the journal.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cant_mod_pr=
imarygroupid
```

=20

Error

=20

    3221226192 - 0xC00002D0

=20

Cannot change the primary group ID of a domain controller acc= ount.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_system_image_b=
ad_signature
```

=20

Error

=20

    3221226193 - 0xC00002D1

=20

{Fatal System Error} The system image is not properly signed.= The file
has been replaced with the signed file. The system has been shut = down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pnp_reboot_req=
uired
```

=20

Error

=20

    3221226194 - 0xC00002D2

=20

The device will not start without a reboot.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_power_state_in=
valid
```

=20

Error

=20

    3221226195 - 0xC00002D3

=20

The power state of the current device cannot support this req= uest.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_invalid_gro=
up_type
```

=20

Error

=20

    3221226196 - 0xC00002D4

=20

The specified group type is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_nest_glo=
balgroup_in_mixeddomain
```

=20

Error

=20

    3221226197 - 0xC00002D5

=20

In a mixed domain, no nesting of a global group if the group = is
security enabled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_nest_loc=
algroup_in_mixeddomain
```

=20

Error

=20

    3221226198 - 0xC00002D6

=20

In a mixed domain, cannot nest local groups with other local = groups,
if the group is security enabled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_global_cant=
_have_local_member
```

=20

Error

=20

    3221226199 - 0xC00002D7

=20

A global group cannot have a local group as a member.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_global_cant=
_have_universal_member
```

=20

Error

=20

    3221226200 - 0xC00002D8

=20

A global group cannot have a universal group as a member. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_universal_c=
ant_have_local_member
```

=20

Error

=20

    3221226201 - 0xC00002D9

=20

A universal group cannot have a local group as a member.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_global_cant=
_have_crossdomain_member
```

=20

Error

=20

    3221226202 - 0xC00002DA

=20

A global group cannot have a cross-domain member.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_local_cant_=
have_crossdomain_local_member
```

=20

Error

=20

    3221226203 - 0xC00002DB

=20

A local group cannot have another cross-domain local group as= a member.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_have_primar=
y_members
```

=20

Error

=20

    3221226204 - 0xC00002DC

=20

Cannot change to a security-disabled group because primary me= mbers are
in this group.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_not_suppor=
ted
```

=20

Error

=20

    3221226205 - 0xC00002DD

=20

The WMI operation is not supported by the data block or metho= d.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_insufficient_p=
ower
```

=20

Error

=20

    3221226206 - 0xC00002DE

=20

There is not enough power to complete the requested operation= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_sam_need_bootk=
ey_password
```

=20

Error

=20

    3221226207 - 0xC00002DF

=20

The Security Accounts Manager needs to get the boot password.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_sam_need_bootk=
ey_floppy
```

=20

Error

=20

    3221226208 - 0xC00002E0

=20

The Security Accounts Manager needs to get the boot key from = the
floppy disk.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_cant_start<=
/pre>
```

=20

Error

=20

    3221226209 - 0xC00002E1

=20

The directory service cannot start.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_init_failur=
e
```

=20

Error

=20

    3221226210 - 0xC00002E2

=20

The directory service could not start. Click OK to shut down = this
system and restart in Directory Services Restore Mode. Check the event=
log for more detailed information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_sam_init_failu=
re
```

=20

Error

=20

    3221226211 - 0xC00002E3

=20

The Security Accounts Manager initialization failed. Click OK= to shut
down this system and restart in Safe Mode. Check the event log for= more
detailed information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_gc_required=
```

=20

Error

=20

    3221226212 - 0xC00002E4

=20

The requested operation can be performed only on a global cat= alog
server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_local_membe=
r_of_local_only
```

=20

Error

=20

    3221226213 - 0xC00002E5

=20

A local group can only be a member of other local groups in t= he same
domain.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_no_fpo_in_u=
niversal_groups
```

=20

Error

=20

    3221226214 - 0xC00002E6

=20

Foreign security principals cannot be members of universal gr= oups.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_machine_acc=
ount_quota_exceeded
```

=20

Error

=20

    3221226215 - 0xC00002E7

=20

Your computer could not be joined to the domain. You have exc= eeded the
maximum number of computer accounts you are allowed to create in = this
domain. Contact your system administrator to have this limit reset or =
increased.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_multiple_fault=
_violation
```

=20

Error

=20

    3221226216 - 0xC00002E8

=20

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_current_domain=
_not_allowed
```

=20

Error

=20

    3221226217 - 0xC00002E9

=20

This operation cannot be performed on the current domain. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_cannot_make
```

=20

Error

=20

    3221226218 - 0xC00002EA

=20

The directory or file cannot be created.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_system_shutdow=
n
```

=20

Error

=20

    3221226219 - 0xC00002EB

=20

The system is in the process of shutting down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_init_failur=
e_console
```

=20

Error

=20

    3221226220 - 0xC00002EC

=20

Directory Services could not start. Click OK to shut down the= system.
You can use the recovery console to diagnose the system further. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_sam_init_fa=
ilure_console
```

=20

Error

=20

    3221226221 - 0xC00002ED

=20

Security Accounts Manager initialization failed. Click OK to = shut down
the system. You can use the recovery console to diagnose the syst= em
further.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unfinished_con=
text_deleted
```

=20

Error

=20

    3221226222 - 0xC00002EE

=20

A security context was deleted before the context was complet= ed. This
is considered a logon failure.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_tgt_reply
```

=20

Error

=20

    3221226223 - 0xC00002EF

=20

The client is trying to negotiate a context and the server re= quires
user-to-user but did not send a TGT reply.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_objectid_not_f=
ound
```

=20

Error

=20

    3221226224 - 0xC00002F0

=20

An object ID was not found in the file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_ip_addresse=
s
```

=20

Error

=20

    3221226225 - 0xC00002F1

=20

Unable to accomplish the requested task because the local mac= hine does
not have any IP addresses.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wrong_credenti=
al_handle
```

=20

Error

=20

    3221226226 - 0xC00002F2

=20

The supplied credential handle does not match the credential = that is
associated with the security context.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_crypto_system_=
invalid
```

=20

Error

=20

    3221226227 - 0xC00002F3

=20

The crypto system or checksum function is invalid because a r= equired
function is unavailable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_max_referrals_=
exceeded
```

=20

Error

=20

    3221226228 - 0xC00002F4

=20

The number of maximum ticket referrals has been exceeded. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_must_be_kdc
```

=20

Error

=20

    3221226229 - 0xC00002F5

=20

The local machine must be a Kerberos KDC (domain controller) = and it is
not.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_strong_crypto_=
not_supported
```

=20

Error

=20

    3221226230 - 0xC00002F6

=20

The other end of the security negotiation requires strong cry= pto but
it is not supported on the local machine.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_too_many_princ=
ipals
```

=20

Error

=20

    3221226231 - 0xC00002F7

=20

The KDC reply contained more than one principal name.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_pa_data
```

=20

Error

=20

    3221226232 - 0xC00002F8

=20

Expected to find PA data for a hint of what etype to use, but= it was
not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pkinit_name_mi=
smatch
```

=20

Error

=20

    3221226233 - 0xC00002F9

=20

The client certificate does not contain a valid UPN, or does = not match
the client name in the logon request. Contact your administrator.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_logo=
n_required
```

=20

Error

=20

    3221226234 - 0xC00002FA

=20

Smart card logon is required and was not used.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_kdc_invalid_re=
quest
```

=20

Error

=20

    3221226235 - 0xC00002FB

=20

An invalid request was sent to the KDC.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_kdc_unable_to_=
refer
```

=20

Error

=20

    3221226236 - 0xC00002FC

=20

The KDC was unable to generate a referral for the service req= uested.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_kdc_unknown_et=
ype
```

=20

Error

=20

    3221226237 - 0xC00002FD

=20

The encryption type requested is not supported by the KDC. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_shutdown_in_pr=
ogress
```

=20

Error

=20

    3221226238 - 0xC00002FE

=20

A system shutdown is in progress.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_server_shutdow=
n_in_progress
```

=20

Error

=20

    3221226239 - 0xC00002FF

=20

The server machine is shutting down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_supported_=
on_sbs
```

=20

Error

=20

    3221226240 - 0xC0000300

=20

This operation is not supported on a computer running Windows=
Server&nbsp;2003 for Small Business Server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_guid_disco=
nnected
```

=20

Error

=20

    3221226241 - 0xC0000301

=20

The WMI GUID is no longer available.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_already_di=
sabled
```

=20

Error

=20

    3221226242 - 0xC0000302

=20

Collection or events for the WMI GUID is already disabled. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wmi_already_en=
abled
```

=20

Error

=20

    3221226243 - 0xC0000303

=20

Collection or events for the WMI GUID is already enabled. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mft_too_fragme=
nted
```

=20

Error

=20

    3221226244 - 0xC0000304

=20

The master file table on the volume is too fragmented to comp= lete this
operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_copy_protectio=
n_failure
```

=20

Error

=20

    3221226245 - 0xC0000305

=20

Copy protection failure.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_authentica=
tion_failure
```

=20

Error

=20

    3221226246 - 0xC0000306

=20

Copy protection error=E2=80=94DVD CSS Authentication failed.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_key_not_pr=
esent
```

=20

Error

=20

    3221226247 - 0xC0000307

=20

Copy protection error=E2=80=94The specified sector does not c= ontain a
valid key.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_key_not_es=
tablished
```

=20

Error

=20

    3221226248 - 0xC0000308

=20

Copy protection error=E2=80=94DVD session key not established= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_scrambled_=
sector
```

=20

Error

=20

    3221226249 - 0xC0000309

=20

Copy protection error=E2=80=94The read failed because the sec= tor is
encrypted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_region_mis=
match
```

=20

Error

=20

    3221226250 - 0xC000030A

=20

Copy protection error=E2=80=94The region of the specified DVD= does not
correspond to the region setting of the drive.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_css_resets_exh=
austed
```

=20

Error

=20

    3221226251 - 0xC000030B

=20

Copy protection error=E2=80=94The region setting of the drive= may be
permanent.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pkinit_failure=
```

=20

Error

=20

    3221226272 - 0xC0000320

=20

The Kerberos protocol encountered an error while validating t= he KDC
certificate during smart card logon. There is more information in th= e
system event log.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_subs=
ystem_failure
```

=20

Error

=20

    3221226273 - 0xC0000321

=20

The Kerberos protocol encountered an error while attempting t= o use the
smart card subsystem.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_no_kerb_key
```

=20

Error

=20

    3221226274 - 0xC0000322

=20

The target server does not have acceptable Kerberos credentia= ls.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_host_down
```

=20

Error

=20

    3221226320 - 0xC0000350

=20

The transport determined that the remote system is down.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_unsupported_pr=
eauth
```

=20

Error

=20

    3221226321 - 0xC0000351

=20

An unsupported pre-authentication mechanism was presented to = the
Kerberos package.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_efs_alg_blob_t=
oo_big
```

=20

Error

=20

    3221226322 - 0xC0000352

=20

The encryption algorithm that is used on the source file need= s a
bigger key buffer than the one that is used on the destination file. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_port_not_set
```

=20

Error

=20

    3221226323 - 0xC0000353

=20

An attempt to remove a processes DebugPort was made, but a po= rt was
not already associated with the process.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_debugger_inact=
ive
```

=20

Error

=20

    3221226324 - 0xC0000354

=20

An attempt to do an operation on a debug port failed because = the port
is in the process of being deleted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_version_che=
ck_failure
```

=20

Error

=20

    3221226325 - 0xC0000355

=20

This version of Windows is not compatible with the behavior v= ersion of
the directory forest, domain, or domain controller.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_auditing_disab=
led
```

=20

Error

=20

    3221226326 - 0xC0000356

=20

The specified event is currently not being audited.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_prent4_machine=
_account
```

=20

Error

=20

    3221226327 - 0xC0000357

=20

The machine account was created prior to Windows&nbsp;NT = 4.0. The
account needs to be recreated.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_ds_ag_cant_hav=
e_universal_member
```

=20

Error

=20

    3221226328 - 0xC0000358

=20

An account group cannot have a universal group as a member. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
win_32
```

=20

Error

=20

    3221226329 - 0xC0000359

=20

The specified image file did not have the correct format; it = appears
to be a 32-bit Windows image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_image_=
win_64
```

=20

Error

=20

    3221226330 - 0xC000035A

=20

The specified image file did not have the correct format; it = appears
to be a 64-bit Windows image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_bad_bindings
```

=20

Error

=20

    3221226331 - 0xC000035B

=20

The client\'s supplied SSPI channel bindings were incorrect. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_network_sessio=
n_expired
```

=20

Error

=20

    3221226332 - 0xC000035C

=20

The client session has expired; so the client must re-authent= icate to
continue accessing the remote resources.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_apphelp_block<=
/pre>
```

=20

Error

=20

    3221226333 - 0xC000035D

=20

The AppHelp dialog box canceled; thus preventing the applicat= ion from
starting.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_all_sids_filte=
red
```

=20

Error

=20

    3221226334 - 0xC000035E

=20

The SID filtering operation removed all SIDs.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_not_safe_mode_=
driver
```

=20

Error

=20

    3221226335 - 0xC000035F

=20

The driver was not loaded because the system is starting in s= afe mode.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_access_disable=
d_by_policy_default
```

=20

Error

=20

    3221226337 - 0xC0000361

=20

Access has been restricted by your Administrator by the defau= lt
software restriction policy level.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_access_disable=
d_by_policy_path
```

=20

Error

=20

    3221226338 - 0xC0000362

=20

Access has been restricted by your Administrator by location = with
policy rule.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_access_disable=
d_by_policy_publisher
```

=20

Error

=20

    3221226339 - 0xC0000363

=20

Access has been restricted by your Administrator by software = publisher
policy.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_access_disable=
d_by_policy_other
```

=20

Error

=20

    3221226340 - 0xC0000364

=20

Access to has been restricted by your Administrator by policy= rule.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_failed_driver_=
entry
```

=20

Error

=20

    3221226341 - 0xC0000365

=20

The driver was not loaded because it failed its initializatio= n call.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_device_enumera=
tion_error
```

=20

Error

=20

    3221226342 - 0xC0000366

=20

The device encountered an error while applying power or readi= ng the
device configuration. This may be caused by a failure of your hardwa= re
or by a poor connection.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mount_point_no=
t_resolved
```

=20

Error

=20

    3221226344 - 0xC0000368

=20

The create operation failed because the name contained at lea= st one
mount point that resolves to a volume to which the specified device =
object is not attached.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_device=
_object_parameter
```

=20

Error

=20

    3221226345 - 0xC0000369

=20

The device object parameter is either not a valid device obje= ct or is
not attached to the volume that is specified by the file name. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_mca_occured
```

=20

Error

=20

    3221226346 - 0xC000036A

=20

A machine check error has occurred. Check the system event lo= g for
additional information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_blocked=
_critical
```

=20

Error

=20

    3221226347 - 0xC000036B

=20

Driver has been blocked from loading.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_blocked=
```

=20

Error

=20

    3221226348 - 0xC000036C

=20

Driver has been blocked from loading.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_databas=
e_error
```

=20

Error

=20

    3221226349 - 0xC000036D

=20

There was error processing the driver database.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_system_hive_to=
o_large
```

=20

Error

=20

    3221226350 - 0xC000036E

=20

System hive size has exceeded its limit.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_invalid_import=
_of_non_dll
```

=20

Error

=20

    3221226351 - 0xC000036F

=20

A dynamic link library (DLL) referenced a module that was nei= ther a
DLL nor the process\'s executable image.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_wron=
g_pin
```

=20

Error

=20

    3221226368 - 0xC0000380

=20

An incorrect PIN was presented to the smart card.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_card=
_blocked
```

=20

Error

=20

    3221226369 - 0xC0000381

=20

The smart card is blocked.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_card=
_not_authenticated
```

=20

Error

=20

    3221226370 - 0xC0000382

=20

No PIN was presented to the smart card.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_no_c=
ard
```

=20

Error

=20

    3221226371 - 0xC0000383

=20

No smart card is available.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_no_k=
ey_container
```

=20

Error

=20

    3221226372 - 0xC0000384

=20

The requested key container does not exist on the smart card.=

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_no_c=
ertificate
```

=20

Error

=20

    3221226373 - 0xC0000385

=20

The requested certificate does not exist on the smart card. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_no_k=
eyset
```

=20

Error

=20

    3221226374 - 0xC0000386

=20

The requested keyset does not exist.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_io_e=
rror
```

=20

Error

=20

    3221226375 - 0xC0000387

=20

A communication error with the smart card has been detected.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_downgrade_dete=
cted
```

=20

Error

=20

    3221226376 - 0xC0000388

=20

The system detected a possible attempt to compromise security= . Ensure
that you can contact the server that authenticated you.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_cert=
_revoked
```

=20

Error

=20

    3221226377 - 0xC0000389

=20

The smart card certificate used for authentication has been r= evoked.
Contact your system administrator. There may be additional informat= ion
in the event log.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_issuing_ca_unt=
rusted
```

=20

Error

=20

    3221226378 - 0xC000038A

=20

An untrusted certificate authority was detected while process= ing the
smart card certificate that is used for authentication. Contact you= r
system administrator.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_revocation_off=
line_c
```

=20

Error

=20

    3221226379 - 0xC000038B

=20

The revocation status of the smart card certificate that is u= sed for
authentication could not be determined. Contact your system adminis=
trator.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_pkinit_client_=
failure
```

=20

Error

=20

    3221226380 - 0xC000038C

=20

The smart card certificate used for authentication was not tr= usted.
Contact your system administrator.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_smartcard_cert=
_expired
```

=20

Error

=20

    3221226381 - 0xC000038D

=20

The smart card certificate used for authentication has expire= d.
Contact your system administrator.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_driver_failed_=
prior_unload
```

=20

Error

=20

    3221226382 - 0xC000038E

=20

The driver could not be loaded because a previous version of = the
driver is still in memory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
NT_status_wow_assertion<=
/pre>
```

=20

Error

=20

    3221264536 - 0xC0009898

=20

WOW Assertion Error.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_string_bi=
nding
```

=20

Error

=20

    3221356545 - 0xC0020001

=20

The string binding is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_wrong_kind_of_bin=
ding
```

=20

Error

=20

    3221356546 - 0xC0020002

=20

The binding handle is not the correct type.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_binding
```

=20

Error

=20

    3221356547 - 0xC0020003

=20

The binding handle is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_protseq_not_suppo=
rted
```

=20

Error

=20

    3221356548 - 0xC0020004

=20

The RPC protocol sequence is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_rpc_prots=
eq
```

=20

Error

=20

    3221356549 - 0xC0020005

=20

The RPC protocol sequence is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_string_uu=
id
```

=20

Error

=20

    3221356550 - 0xC0020006

=20

The string UUID is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_endpoint_=
format
```

=20

Error

=20

    3221356551 - 0xC0020007

=20

The endpoint format is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_net_addr<=
/pre>
```

=20

Error

=20

    3221356552 - 0xC0020008

=20

The network address is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_endpoint_found=
```

=20

Error

=20

    3221356553 - 0xC0020009

=20

No endpoint was found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_timeout
```

=20

Error

=20

    3221356554 - 0xC002000A

=20

The time-out value is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_object_not_found<=
/pre>
```

=20

Error

=20

    3221356555 - 0xC002000B

=20

The object UUID was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_already_registere=
d
```

=20

Error

=20

    3221356556 - 0xC002000C

=20

The object UUID has already been registered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_type_already_regi=
stered
```

=20

Error

=20

    3221356557 - 0xC002000D

=20

The type UUID has already been registered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_already_listening=
```

=20

Error

=20

    3221356558 - 0xC002000E

=20

The RPC server is already listening.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_protseqs_regis=
tered
```

=20

Error

=20

    3221356559 - 0xC002000F

=20

No protocol sequences have been registered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_not_listening
```

=20

Error

=20

    3221356560 - 0xC0020010

=20

The RPC server is not listening.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_mgr_type<=
/pre>
```

=20

Error

=20

    3221356561 - 0xC0020011

=20

The manager type is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_if
```

\<= /td\> =20

Error

=20

    3221356562 - 0xC0020012

=20

The interface is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_bindings
```

=

=20

Error

=20

    3221356563 - 0xC0020013

=20

There are no bindings.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_protseqs
```

=

=20

Error

=20

    3221356564 - 0xC0020014

=20

There are no protocol sequences.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_cant_create_endpo=
int
```

=20

Error

=20

    3221356565 - 0xC0020015

=20

The endpoint cannot be created.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_out_of_resources<=
/pre>
```

=20

Error

=20

    3221356566 - 0xC0020016

=20

Insufficient resources are available to complete this operati= on.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_server_unavailabl=
e
```

=20

Error

=20

    3221356567 - 0xC0020017

=20

The RPC server is unavailable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_server_too_busy
```

=20

Error

=20

    3221356568 - 0xC0020018

=20

The RPC server is too busy to complete this operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_network_o=
ptions
```

=20

Error

=20

    3221356569 - 0xC0020019

=20

The network options are invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_call_active
```

=20

Error

=20

    3221356570 - 0xC002001A

=20

No RPCs are active on this thread.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_call_failed
```

=

=20

Error

=20

    3221356571 - 0xC002001B

=20

The RPC failed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_call_failed_dne
```

=20

Error

=20

    3221356572 - 0xC002001C

=20

The RPC failed and did not execute.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_protocol_error
```

=20

Error

=20

    3221356573 - 0xC002001D

=20

An RPC protocol error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unsupported_trans=
_syn
```

=20

Error

=20

    3221356575 - 0xC002001F

=20

The RPC server does not support the transfer syntax.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unsupported_type<=
/pre>
```

=20

Error

=20

    3221356577 - 0xC0020021

=20

The type UUID is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_tag
```

=

=20

Error

=20

    3221356578 - 0xC0020022

=20

The tag is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_bound
```

=20

Error

=20

    3221356579 - 0xC0020023

=20

The array bounds are invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_entry_name
```

=20

Error

=20

    3221356580 - 0xC0020024

=20

The binding does not contain an entry name.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_name_synt=
ax
```

=20

Error

=20

    3221356581 - 0xC0020025

=20

The name syntax is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unsupported_name_=
syntax
```

=20

Error

=20

    3221356582 - 0xC0020026

=20

The name syntax is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_uuid_no_address
```

=20

Error

=20

    3221356584 - 0xC0020028

=20

No network address is available to construct a UUID.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_duplicate_endpoin=
t
```

=20

Error

=20

    3221356585 - 0xC0020029

=20

The endpoint is a duplicate.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_authn_typ=
e
```

=20

Error

=20

    3221356586 - 0xC002002A

=20

The authentication type is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_max_calls_too_sma=
ll
```

=20

Error

=20

    3221356587 - 0xC002002B

=20

The maximum number of calls is too small.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_string_too_long
```

=20

Error

=20

    3221356588 - 0xC002002C

=20

The string is too long.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_protseq_not_found=
```

=20

Error

=20

    3221356589 - 0xC002002D

=20

The RPC protocol sequence was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_procnum_out_of_ra=
nge
```

=20

Error

=20

    3221356590 - 0xC002002E

=20

The procedure number is out of range.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_binding_has_no_au=
th
```

=20

Error

=20

    3221356591 - 0xC002002F

=20

The binding does not contain any authentication information.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_authn_ser=
vice
```

=20

Error

=20

    3221356592 - 0xC0020030

=20

The authentication service is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_authn_lev=
el
```

=20

Error

=20

    3221356593 - 0xC0020031

=20

The authentication level is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_auth_iden=
tity
```

=20

Error

=20

    3221356594 - 0xC0020032

=20

The security context is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unknown_authz_ser=
vice
```

=20

Error

=20

    3221356595 - 0xC0020033

=20

The authorization service is unknown.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EPT_NT_invalid_entry
```

=20

Error

=20

    3221356596 - 0xC0020034

=20

The entry is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EPT_NT_cant_perform_op
```

=20

Error

=20

    3221356597 - 0xC0020035

=20

The operation cannot be performed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EPT_NT_not_registered
```

=20

Error

=20

    3221356598 - 0xC0020036

=20

No more endpoints are available from the endpoint mapper. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_nothing_to_export=
```

=20

Error

=20

    3221356599 - 0xC0020037

=20

No interfaces have been exported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_incomplete_name
```

=20

Error

=20

    3221356600 - 0xC0020038

=20

The entry name is incomplete.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_vers_opti=
on
```

=20

Error

=20

    3221356601 - 0xC0020039

=20

The version option is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_more_members
```

=20

Error

=20

    3221356602 - 0xC002003A

=20

There are no more members.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_not_all_objs_unex=
ported
```

=20

Error

=20

    3221356603 - 0xC002003B

=20

There is nothing to unexport.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_interface_not_fou=
nd
```

=20

Error

=20

    3221356604 - 0xC002003C

=20

The interface was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_entry_already_exi=
sts
```

=20

Error

=20

    3221356605 - 0xC002003D

=20

The entry already exists.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_entry_not_found
```

=20

Error

=20

    3221356606 - 0xC002003E

=20

The entry was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_name_service_unav=
ailable
```

=20

Error

=20

    3221356607 - 0xC002003F

=20

The name service is unavailable.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_naf_id
```

=20

Error

=20

    3221356608 - 0xC0020040

=20

The network address family is invalid.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_cannot_support
```

=20

Error

=20

    3221356609 - 0xC0020041

=20

The requested operation is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_context_availa=
ble
```

=20

Error

=20

    3221356610 - 0xC0020042

=20

No security context is available to allow impersonation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_internal_error
```

=20

Error

=20

    3221356611 - 0xC0020043

=20

An internal error occurred in the RPC.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_zero_divide
```

=

=20

Error

=20

    3221356612 - 0xC0020044

=20

The RPC server attempted to divide an integer by zero.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_address_error
```

=20

Error

=20

    3221356613 - 0xC0020045

=20

An addressing error occurred in the RPC server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_fp_div_zero
```

=

=20

Error

=20

    3221356614 - 0xC0020046

=20

A floating point operation at the RPC server caused a divide = by zero.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_fp_underflow
```

=20

Error

=20

    3221356615 - 0xC0020047

=20

A floating point underflow occurred at the RPC server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_fp_overflow
```

=

=20

Error

=20

    3221356616 - 0xC0020048

=20

A floating point overflow occurred at the RPC server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_call_in_progress<=
/pre>
```

=20

Error

=20

    3221356617 - 0xC0020049

=20

An RPC is already in progress for this thread.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_more_bindings<=
/pre>
```

=20

Error

=20

    3221356618 - 0xC002004A

=20

There are no more bindings.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_group_member_not_=
found
```

=20

Error

=20

    3221356619 - 0xC002004B

=20

The group member was not found.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
EPT_NT_cant_create
```

=

=20

Error

=20

    3221356620 - 0xC002004C

=20

The endpoint mapper database entry could not be created.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_object
```

=20

Error

=20

    3221356621 - 0xC002004D

=20

The object UUID is the nil UUID.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_interfaces
```

=20

Error

=20

    3221356623 - 0xC002004F

=20

No interfaces have been registered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_call_cancelled
```

=20

Error

=20

    3221356624 - 0xC0020050

=20

The RPC was canceled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_binding_incomplet=
e
```

=20

Error

=20

    3221356625 - 0xC0020051

=20

The binding handle does not contain all the required informat= ion.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_comm_failure
```

=20

Error

=20

    3221356626 - 0xC0020052

=20

A communications failure occurred during an RPC.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_unsupported_authn=
_level
```

=20

Error

=20

    3221356627 - 0xC0020053

=20

The requested authentication level is not supported.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_princ_name
```

=20

Error

=20

    3221356628 - 0xC0020054

=20

No principal name was registered.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_not_rpc_error
```

=20

Error

=20

    3221356629 - 0xC0020055

=20

The error specified is not a valid Windows RPC error code. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_sec_pkg_error
```

=20

Error

=20

    3221356631 - 0xC0020057

=20

A security package-specific error occurred.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_not_cancelled
```

=20

Error

=20

    3221356632 - 0xC0020058

=20

The thread was not canceled.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_async_han=
dle
```

=20

Error

=20

    3221356642 - 0xC0020062

=20

Invalid asynchronous RPC handle.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_async_cal=
l
```

=20

Error

=20

    3221356643 - 0xC0020063

=20

Invalid asynchronous RPC call handle for this operation.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_proxy_access_deni=
ed
```

=20

Error

=20

    3221356644 - 0xC0020064

=20

Access to the HTTP proxy is denied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_no_more_entries
```

=20

Error

=20

    3221422081 - 0xC0030001

=20

The list of RPC servers available for auto-handle binding has= been
exhausted.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_char_trans_ope=
n_fail
```

=20

Error

=20

    3221422082 - 0xC0030002

=20

The file designated by DCERPCCHARTRANS cannot be opened.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_char_trans_sho=
rt_file
```

=20

Error

=20

    3221422083 - 0xC0030003

=20

The file containing the character translation table has fewer= than 512
bytes.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_in_null_contex=
t
```

=20

Error

=20

    3221422084 - 0xC0030004

=20

A null context handle is passed as an \[in\] parameter.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_context_mismat=
ch
```

=20

Error

=20

    3221422085 - 0xC0030005

=20

The context handle does not match any known context handles.\<= /td\>
=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_context_damage=
d
```

=20

Error

=20

    3221422086 - 0xC0030006

=20

The context handle changed during a call.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_handles_mismat=
ch
```

=20

Error

=20

    3221422087 - 0xC0030007

=20

The binding handles passed to an RPC do not match.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_ss_cannot_get_cal=
l_handle
```

=20

Error

=20

    3221422088 - 0xC0030008

=20

The stub is unable to get the call handle.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_null_ref_pointer<=
/pre>
```

=20

Error

=20

    3221422089 - 0xC0030009

=20

A null reference pointer was passed to the stub.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_enum_value_out_of=
_range
```

=20

Error

=20

    3221422090 - 0xC003000A

=20

The enumeration value is out of range.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_byte_count_too_sm=
all
```

=20

Error

=20

    3221422091 - 0xC003000B

=20

The byte count is too small.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_bad_stub_data
```

=20

Error

=20

    3221422092 - 0xC003000C

=20

The stub received bad data.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_es_action=
```

=20

Error

=20

    3221422169 - 0xC0030059

=20

Invalid operation on the encoding/decoding handle.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_wrong_es_version<=
/pre>
```

=20

Error

=20

    3221422170 - 0xC003005A

=20

Incompatible version of the serializing package.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_wrong_stub_versio=
n
```

=20

Error

=20

    3221422171 - 0xC003005B

=20

Incompatible version of the RPC stub.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_pipe_obje=
ct
```

=20

Error

=20

    3221422172 - 0xC003005C

=20

The RPC pipe object is invalid or corrupt.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_invalid_pipe_oper=
ation
```

=20

Error

=20

    3221422173 - 0xC003005D

=20

An invalid operation was attempted on an RPC pipe object. =20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_wrong_pipe_versio=
n
```

=20

Error

=20

    3221422174 - 0xC003005E

=20

Unsupported RPC pipe version.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_pipe_closed
```

=

=20

Error

=20

    3221422175 - 0xC003005F

=20

The RPC pipe object has already been closed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_pipe_discipline_e=
rror
```

=20

Error

=20

    3221422176 - 0xC0030060

=20

The RPC call completed before all pipes were processed.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
RPC_NT_pipe_empty
```

\<= /td\> =20

Error

=20

    3221422177 - 0xC0030061

=20

No more data is available from the RPC pipe.

=20

=20

=20 =20 =20 =20 =20 =20 =20

### Type [smbsubcommand](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"smbsubcommand-items\"}

=20

This field does not allow any custom items.

=20

Name

=20

Value

=20

Description

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_set_nmpipe_sta=
te
```

=20

    1:37:1

=20

The TRANS\_SET\_NMPIPE\_STATE subcommand allows a client to set = the
read mode and the non-blocking mode of a specified named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_raw_read_nmpip=
e
```

=20

    1:37:17

=20

The TRANS\_RAW\_READ\_NMPIPE subcommand allows for a raw read of= data
from a name pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_query_nmpipe_s=
tate
```

=20

    1:37:33

=20

The TRANS\_QUERY\_NMPIPE\_STATE subcommand allows a client to re= trieve
information about a specified named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_query_nmpipe_i=
nfo
```

=20

    1:37:34

=20

The TRANS\_QUERY\_NMPIPE\_INFO subcommand allows for a client to=
retrieve information about a specified named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_peek_nmpipe
```

=20

    1:37:35

=20

The TRANS\_PEEK\_NMPIPE subcommand is used to copy data out of = a named
pipe without removing it and to retrieve information about data in = a
named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_transact_nmpip=
e
```

=20

    1:37:38

=20

The TRANS\_TRANSACT\_NMPIPE subcommand is used to execute a tra= nsacted
exchange against a named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_raw_write_nmpi=
pe
```

=20

    1:37:49

=20

The TRANS\_RAW\_WRITE\_NMPIPE subcommand allows for a raw write = of
data to a named pipe. Raw writes to named pipes put bytes directly into
= a pipe in byte mode, regardless of whether it is a message mode pipe
or byt= e mode pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_read_nmpipe
```

=20

    1:37:54

=20

The TRANS\_READ\_NMPIPE subcommand allows a client to read data= from a
named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_write_nmpipe
```

=20

    1:37:55

=20

The TRANS\_WRITE\_NMPIPE subcommand allows a client to write da= ta to a
named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_wait_nmpipe
```

=20

    1:37:83

=20

The TRANS\_WAIT\_NMPIPE subcommand allows a client to be notifi= ed when
the specified named pipe is available to be connected to.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS_call_nmpipe
```

=20

    1:37:84

=20

The TRANS\_CALL\_NMPIPE subcommand allows a client to open a na= med
pipe, issue a write to the named pipe, issue a read from the named pipe=
, and close the named pipe.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_open2
```

=20

    1:50:0

=20

Open or create a file and set extended attributes on the file= .

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_find_first2
```

=20

    1:50:1

=20

Begin a search for file(s) within a directory or for a direc= tory.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_find_next2
```

=20

    1:50:2

=20

Continue a search for file(s) within a directory or for a dir= ectory.
The search MUST have been initiated using TRANS2\_FIND\_FIRST2.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_query_fs_info=
```

=20

    1:50:3

=20

Request information about the object store underlying a share= on the
server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_set_fs_inform=
ation
```

=20

    1:50:4

=20

This subcommand is reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_query_path_in=
formation
```

=20

    1:50:5

=20

Get information about a specific file or directory. There are= several
information levels that can be queried.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_set_path_info=
rmation
```

=20

    1:50:6

=20

Set the standard and extended attribute information of a spec= ific file
or directory on the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_query_file_in=
formation
```

=20

    1:50:7

=20

This transaction is an alternative to TRANS2\_QUERY\_PATH\_INFOR=
MATION.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_set_file_info=
rmation
```

=20

    1:50:8

=20

This transaction is an alternative to TRANS2\_SET\_PATH\_INFORMA= TION.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_fsctl
```

=20

    1:50:9

=20

This subcommand is reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_ioctl2
```

\<= /td\> =20

    1:50:10

=20

This subcommand is reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_find_notify_f=
irst
```

=20

    1:50:11

=20

This command was rendered obsolete.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_find_notify_n=
ext
```

=20

    1:50:12

=20

This command was rendered obsolete.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_create_direct=
ory
```

=20

    1:50:13

=20

This transaction is used to create a new directory and can be= used to
set extended attribute information.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_session_setup=
```

=20

    1:50:14

=20

This subcommand is reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_get_dfs_refer=
ral
```

=20

    1:50:16

=20

Request a referral for a disk object in DFS.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_TRANS2_report_dfs_in=
consistency
```

=20

    1:50:17

=20

This subcommand is reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_create
```

=20

    1:160:1

=20

This transaction subcommand is used to create or open a file = or
directory when extended attributes (EAs) or a security descriptor (SD)
n= eed to be applied.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_ioctl
```

=20

    1:160:2

=20

This transaction subcommand allows IOCTL and FSCTL functions = to be
transferred transparently from client to server. This command is usef=
ul for sending platform-specific or implementation-specific information
to = the server.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_set_secu=
rity_desc
```

=20

    1:160:3

=20

This transaction subcommand allows a client to set the securi= ty
descriptors for a file.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_notify_c=
hange
```

=20

    1:160:4

=20

This command notifies the client when the directory, specifie= d by FID,
is modified. It also returns the names of all file system objects= that
changed, and the ways in which they were modified. The command is a \"=
single shot\" and therefore needs to be reissued to watch for more
directory= changes.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_rename
```

=20

    1:160:5

=20

This subcommand was reserved but not implemented.

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SMB_NT_TRANSACT_query_se=
curity_desc
```

=20

    1:160:6

=20

This transaction subcommand allows a client to retrieve the s= ecurity
descriptor for a file.

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20

### Type [tls\_version](3D%22https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/0.4=) {#3D\"tls_version-items\"}

=20

Name

=20

Value

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
SSL 3.0
```

=20

    48 - 0x30

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TLS 1.0
```

=20

    49 - 0x31

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TLS 1.1
```

=20

    50 - 0x32

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TLS 1.2
```

=20

    51 - 0x33

=20

=20

``` {style="3D\"white-space:" pre-wrap\"=""}
TLS 1.3
```

=20

    52 - 0x34

=20

=20

=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20 =20
=20

\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: text/css Content-Transfer-Encoding: quoted-printable
Content-Location:
https://pvdev2.pvdev2.npav.accedian.net/pvbackd/api/static/pvx.css
\@charset \"utf-8\"; \@import
url(\"https://fonts.googleapis.com/css?family=3DRoboto:400,700\|Sourc=
e+Code+Pro\|Droid+Sans+Mono\"); html { color: rgb(0, 0, 0); background:
rgb(255, 255, 255); } body, div, dl, dt, dd, ul, ol, li, h1, h2, h3, h4,
h5, h6, pre, code, form,= fieldset, legend, input, textarea, p,
blockquote, th, td { margin: 0px; pa= dding: 0px; } table {
border-collapse: collapse; border-spacing: 0px; } fieldset, img {
border: 0px; } address, caption, cite, code, dfn, em, strong, th, var {
font-style: normal= ; font-weight: normal; } ol, ul { list-style: none;
} caption, th { text-align: left; } h1, h2, h3, h4, h5, h6 { font-size:
100%; font-weight: normal; } q::before, q::after { content: \"\"; }
abbr, acronym { border: 0px; font-variant: normal; } sup {
vertical-align: text-top; } sub { vertical-align: text-bottom; } input,
textarea, select { font-family: inherit; font-size: inherit; font-we=
ight: inherit; } legend { color: rgb(0, 0, 0); }
\#yui3-css-stamp.cssreset { display: none; } a { text-decoration: none;
color: inherit; border-bottom: 1px solid var(\--p= rimary-color); }
a:hover { background: var(\--primary-color-light); } em { font-style:
italic; } strong { font-weight: bold; } ol { list-style-type: decimal;
padding: 5px; } ol \> li { margin: 5px 5px 5px 1.5em; padding-left: 5px;
} html { font-family: Roboto, sans-serif; font-size: 18px; color:
rgb(34, 34,= 34); background: rgb(248, 248, 248); \--primary-color:
\#f59d15; \--primary-c= olor-light: \#f59d1518; } body { max-width:
66em; margin: 0px auto; color: rgb(51, 51, 51); } body \> header \> h1 {
margin: 0.5em 0px; font-size: 210%; color: black; } body \> main \>
section \> h3:target { background: rgb(255, 255, 170); } body \> header,
body \> nav, body \> main { background: white; padding: 1em 3e= m; }
body \> header, body \> nav { margin-bottom: 2px; } body \> nav \> ul {
display: flex; } body \> nav \> ul \> li { flex: 0 1 0%; margin-right:
12px; background: var(\--= primary-color-light); border-radius: 3px; }
body \> nav \> ul \> li \> a { display: inline-block; padding: 6px 20px;
} body \> nav li.current { background: var(\--primary-color); color:
white; } body \> nav li.current a { color: inherit; } body \> main \> h2
{ margin: 1.25em 0px; font-size: 180%; font-weight: bold; = color:
black; } body \> main \> h2 \> .header-annotation { font-size: 55%;
font-weight: normal= ; margin-left: 1em; } body \> main \> h3, body \>
main \> section \> h3 { font-size: 100%; font-style:= italic; } body \>
main \> section \> h3 { margin-top: 20px; } .VersionNumber { font-size:
125%; color: rgb(102, 102, 102); margin-bottom:= 1em; } code {
font-family: \"Droid Sans Mono\", monospace; font-size: 15px; } .Logo {
margin: 1.5em 0px; } .Nav { margin-bottom: 2em; } .CallIndex {
margin-bottom: 4em; } .CallIndex \> \* \> tr \> th, .CallIndex \> \* \>
tr \> td { padding: 5px 1em 5px 0= px; vertical-align: top; } .CallIndex
\> thead \> tr \> th { font-weight: bold; font-size: 125%; padding:= 1em
0px 0.5em; color: var(\--primary-color); } .CallIndex \> tbody \> tr \>
th { font-family: \"Droid Sans Mono\", monospace; w= hite-space: pre;
padding-top: 7px; } .Markdown { margin: 2em 0px; } .Markdown:target \>
header::before { content: \"=E2=87=92\"; display: inline-b= lock;
position: absolute; margin-left: -38px; margin-top: -2px; font-size: =
30px; color: var(\--primary-color); } .Markdown \> header \> span.name
\> a.anchor { margin-left: 16px; visibility: = hidden; font-weight:
normal; } .Markdown \> header:hover \> span.name \> a.anchor {
visibility: visible; } .Markdown .callType { font-weight: bold; }
.Markdown .documentation p, .Markdown .documentation pre {
margin-bottom: 0= .5em; } .Markdown .documentation ul, .Markdown
.documentation ol { margin-left: 2em= ; margin-bottom: 0.5em; }
.Markdown .documentation ul \> li, .Markdown .documentation ol \> li {
list-s= tyle: disc; } .Markdown .documentation code { display:
inline-block; padding: 0.1em 0.3em= ; margin: 0.1em; border-radius:
0.2em; background: rgb(238, 238, 238); min-= width: 15px; text-align:
center; font-weight: bold; } .Markdown .documentation pre \> code {
display: block; max-width: 100%; padd= ing: 10px; overflow: auto;
border: 1px solid rgb(242, 242, 242); background= : rgb(248, 248, 248);
font-weight: inherit; border-radius: 0px; text-align:= left;
line-height: 20px; } .Markdown \> header { display: flex; margin-bottom:
1em; height: 2.5em; bord= er-bottom: 1px solid rgb(221, 221, 221);
align-items: center; } .Markdown \> header \> span { display: flex;
align-items: center; } .Markdown \> header \> span.name { font-family:
\"Droid Sans Mono\"; font-size:= 140%; font-weight: bold; color: black;
flex: 1 1 0%; } .CallIndex span.kind, .Markdown span.kind {
border-radius: 3px; padding: 0p= x 0.5em; height: 24px; margin: 0px 8px;
color: white; } span.kind.stream { background: rgb(85, 187, 85); }
.Markdown span.kind.stream::after { content: \"Stream\"; } .CallIndex
span.kind.stream::after { content: \"S\"; } span.kind.hidden {
background: rgb(187, 85, 85); } .Markdown span.kind.hidden::after {
content: \"Hidden\"; } .CallIndex span.kind.hidden::after { content:
\"H\"; } .Markdown .documentation h1 { margin: 1em 0px; font-size: 125%;
color: blac= k; } .Markdown .documentation h2, .Markdown .documentation
h3 { margin: 0.8em 0p= x; padding: 0.3em 0px; } .Markdown .documentation
h2 { text-decoration: underline; font-size: 120%; = } .Markdown
.documentation h3 { font-style: italic; font-size: 115%; } .Markdown
table { margin: 20px 0px; } .Markdown table \> \* \> tr \> th, .Markdown
table \> \* \> tr \> td { padding: 6px= 12px; } .Markdown table \> thead
\> tr \> th { border-bottom: 2px solid black; font-we= ight: bold; }
.Markdown table \> tbody \> tr \> td { border-bottom: 1px solid rgb(204,
204, = 204); } .Markdown table \> tbody \> tr:last-child \> td {
border-bottom: none; } .List { margin-top: 20px; font-size: 14px; }
.List thead \> tr \> th { font-weight: bold; } .List \> \* \> tr \>
th:target { background: rgb(255, 255, 170); } .List tr:hover \> th,
.List tr:hover \> td { background: rgb(242, 242, 242); = } .List td,
.List th { padding: 5px; border: 1px solid rgb(221, 221, 221); ve=
rtical-align: top; } .List pre { line-height: 18px; } .Subtitle {
margin: 6px 0px; color: rgb(85, 85, 85); } \#filter-by-layer { display:
flex; } .MultiChoices { margin: 0px auto; display: inline-block;
font-size: 90%; } .MultiChoices \> li { display: inline-block;
border-width: 1px 0px 1px 1px; = border-style: solid; border-color:
rgb(170, 170, 170); border-image: initia= l; color:
var(\--primary-color); padding: 2px 8px; cursor: pointer; margin-b=
ottom: 2px; } .MultiChoices \> li.isSelected { background:
var(\--primary-color); color: wh= ite; } .MultiChoices \> li.isSelected
+ li.isSelected { border-left-color: white; } .MultiChoices \>
li:first-child { border-top-left-radius: 5px; border-bottom=
-left-radius: 5px; } .MultiChoices \> li:last-child {
border-top-right-radius: 5px; border-bottom= -right-radius: 5px;
border-right-width: 1px; } \#fields-list-table tr.isHidden { display:
none; } \@media print { html { font-size: 8pt; } body { max-width: none;
} section { break-inside: avoid; } }
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: text/css Content-Transfer-Encoding: quoted-printable
Content-Location:
https://fonts.googleapis.com/css?family=Roboto:400,700\|Source+Code+Pro\|Droid+Sans+Mono
\@charset \"utf-8\"; \@font-face { font-family: \"Droid Sans Mono\";
font-style: normal; font-weigh= t: 400; src: local(\"Droid Sans Mono
Regular\"), local(\"DroidSansMono-Regular= \"),
url(\"https://fonts.gstatic.com/s/droidsansmono/v13/6NUO8FuJNQ2MbkrZ5-J8=
lKFrp7pRef2rUGIW9g.woff2\") format(\"woff2\"); unicode-range: U+0-FF,
U+131, U= +152-153, U+2BB-2BC, U+2C6, U+2DA, U+2DC, U+2000-206F, U+2074,
U+20AC, U+21= 22, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD; }
\@font-face { font-family: Roboto; font-style: normal; font-weight: 400;
src= : local(\"Roboto\"), local(\"Roboto-Regular\"),
url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu72xKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+460-52F, U+1C80-1C88, U+20B4, U+2DE0-2DFF,
U+A640-A69F, U+FE2E-FE2= F; } \@font-face { font-family: Roboto;
font-style: normal; font-weight: 400; src= : local(\"Roboto\"),
local(\"Roboto-Regular\"), url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu5mxKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+400-45F, U+490-491, U+4B0-4B1, U+2116; } \@font-face
{ font-family: Roboto; font-style: normal; font-weight: 400; src= :
local(\"Roboto\"), local(\"Roboto-Regular\"),
url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu7mxKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+1F00-1FFF; } \@font-face { font-family: Roboto;
font-style: normal; font-weight: 400; src= : local(\"Roboto\"),
local(\"Roboto-Regular\"), url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu4WxKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+370-3FF; } \@font-face { font-family: Roboto;
font-style: normal; font-weight: 400; src= : local(\"Roboto\"),
local(\"Roboto-Regular\"), url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu7WxKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+102-103, U+110-111, U+128-129, U+168-169, U+1A0-1A1,
U+1AF-1B0, U+= 1EA0-1EF9, U+20AB; } \@font-face { font-family: Roboto;
font-style: normal; font-weight: 400; src= : local(\"Roboto\"),
local(\"Roboto-Regular\"), url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu7GxKKTU1Kvnz.woff2\") format(\"woff2\");
unicode-= range: U+100-24F, U+259, U+1E00-1EFF, U+2020, U+20A0-20AB,
U+20AD-20CF, U+2= 113, U+2C60-2C7F, U+A720-A7FF; } \@font-face {
font-family: Roboto; font-style: normal; font-weight: 400; src= :
local(\"Roboto\"), local(\"Roboto-Regular\"),
url(\"https://fonts.gstatic.com/=
s/roboto/v20/KFOmCnqEu92Fr1Mu4mxKKTU1Kg.woff2\") format(\"woff2\");
unicode-ra= nge: U+0-FF, U+131, U+152-153, U+2BB-2BC, U+2C6, U+2DA,
U+2DC, U+2000-206F,= U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212,
U+2215, U+FEFF, U+FFFD; } \@font-face { font-family: Roboto; font-style:
normal; font-weight: 700; src= : local(\"Roboto Bold\"),
local(\"Roboto-Bold\"), url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfCRc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+460-52F, U+1C80-1C88, U+20B4,
U+2DE0-2DFF, U+A640-A69F, U+FE= 2E-FE2F; } \@font-face { font-family:
Roboto; font-style: normal; font-weight: 700; src= : local(\"Roboto
Bold\"), local(\"Roboto-Bold\"), url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfABc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+400-45F, U+490-491, U+4B0-4B1,
U+2116; } \@font-face { font-family: Roboto; font-style: normal;
font-weight: 700; src= : local(\"Roboto Bold\"), local(\"Roboto-Bold\"),
url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfCBc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+1F00-1FFF; } \@font-face {
font-family: Roboto; font-style: normal; font-weight: 700; src= :
local(\"Roboto Bold\"), local(\"Roboto-Bold\"),
url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfBxc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+370-3FF; } \@font-face {
font-family: Roboto; font-style: normal; font-weight: 700; src= :
local(\"Roboto Bold\"), local(\"Roboto-Bold\"),
url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfCxc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+102-103, U+110-111, U+128-129,
U+168-169, U+1A0-1A1, U+1AF-1= B0, U+1EA0-1EF9, U+20AB; } \@font-face {
font-family: Roboto; font-style: normal; font-weight: 700; src= :
local(\"Roboto Bold\"), local(\"Roboto-Bold\"),
url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfChc4AMP6lbBP.woff2\")
format(\"woff2\"); un= icode-range: U+100-24F, U+259, U+1E00-1EFF,
U+2020, U+20A0-20AB, U+20AD-20C= F, U+2113, U+2C60-2C7F, U+A720-A7FF; }
\@font-face { font-family: Roboto; font-style: normal; font-weight: 700;
src= : local(\"Roboto Bold\"), local(\"Roboto-Bold\"),
url(\"https://fonts.gstatic.co=
m/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfBBc4AMP6lQ.woff2\")
format(\"woff2\"); unic= ode-range: U+0-FF, U+131, U+152-153, U+2BB-2BC,
U+2C6, U+2DA, U+2DC, U+2000= -206F, U+2074, U+20AC, U+2122, U+2191,
U+2193, U+2212, U+2215, U+FEFF, U+FF= FD; } \@font-face { font-family:
\"Source Code Pro\"; font-style: normal; font-weigh= t: 400; src:
local(\"Source Code Pro Regular\"), local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlMOvWnsUnxlC9.woff2\") format(\"woff2\"); unicode-range:
U+460-52F, U+1= C80-1C88, U+20B4, U+2DE0-2DFF, U+A640-A69F, U+FE2E-FE2F;
} \@font-face { font-family: \"Source Code Pro\"; font-style: normal;
font-weigh= t: 400; src: local(\"Source Code Pro Regular\"),
local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlOevWnsUnxlC9.woff2\") format(\"woff2\"); unicode-range:
U+400-45F, U+4= 90-491, U+4B0-4B1, U+2116; } \@font-face { font-family:
\"Source Code Pro\"; font-style: normal; font-weigh= t: 400; src:
local(\"Source Code Pro Regular\"), local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlPuvWnsUnxlC9.woff2\") format(\"woff2\"); unicode-range:
U+370-3FF; } \@font-face { font-family: \"Source Code Pro\"; font-style:
normal; font-weigh= t: 400; src: local(\"Source Code Pro Regular\"),
local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlMuvWnsUnxlC9.woff2\") format(\"woff2\"); unicode-range:
U+102-103, U+1= 10-111, U+128-129, U+168-169, U+1A0-1A1, U+1AF-1B0,
U+1EA0-1EF9, U+20AB; } \@font-face { font-family: \"Source Code Pro\";
font-style: normal; font-weigh= t: 400; src: local(\"Source Code Pro
Regular\"), local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlM-vWnsUnxlC9.woff2\") format(\"woff2\"); unicode-range:
U+100-24F, U+2= 59, U+1E00-1EFF, U+2020, U+20A0-20AB, U+20AD-20CF,
U+2113, U+2C60-2C7F, U+A= 720-A7FF; } \@font-face { font-family:
\"Source Code Pro\"; font-style: normal; font-weigh= t: 400; src:
local(\"Source Code Pro Regular\"), local(\"SourceCodePro-Regular= \"),
url(\"https://fonts.gstatic.com/s/sourcecodepro/v11/HI\_SiYsKILxRpg3hIP6s=
J7fM7PqlPevWnsUnxg.woff2\") format(\"woff2\"); unicode-range: U+0-FF,
U+131, U= +152-153, U+2BB-2BC, U+2C6, U+2DA, U+2DC, U+2000-206F, U+2074,
U+20AC, U+21= 22, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD; }
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: font/woff2 Content-Transfer-Encoding: base64
Content-Location:
https://fonts.gstatic.com/s/droidsansmono/v13/6NUO8FuJNQ2MbkrZ5-J8lKFrp7pRef2rUGIW9g.woff2
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
b6zQ40gvb7atlaWVFb6YBWGla2YOAA==
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: font/woff2 Content-Transfer-Encoding: base64
Content-Location:
https://fonts.gstatic.com/s/roboto/v20/KFOmCnqEu92Fr1Mu4mxKKTU1Kg.woff2
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
BpRdsaJNILE4vXDjqAIA
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: font/woff2 Content-Transfer-Encoding: base64
Content-Location:
https://fonts.gstatic.com/s/roboto/v20/KFOlCnqEu92Fr1MmWUlfBBc4AMP6lQ.woff2
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
ZBasOKAMe8TBDPVDxvI70yPbAA==
\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\--
Content-Type: image/svg+xml Content-Transfer-Encoding: quoted-printable
Content-Location:
https://accedian.com/wp-content/themes/accedian/images/accedian-logo-gold.svg

Accedian\_logo\_Artworked\_RGB\_Accedian\_Gold

\-\-\-\-\--MultipartBoundary\--jfhRo4H3ke25yqtVuJfESsiHnGTjLXu3rL6cuQu2jV\-\-\-\-\--
