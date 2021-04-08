# PVX API

Version 0.7.0

## Table of contents

1.  [Fields](#fields-list)
2.  [Types](#types-list)
3.  [Values](#items-list)

## Fields

List of fields (both *values* and *keys*) used in [PVQL](#query) to
query data.

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th>Field Name</th>
<th>Type</th>
<th>Layers</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><span id="field-aborts"></span>
<pre><code>aborts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of aborted Citrix sessions</td>
</tr>
<tr class="even">
<td><span id="field-aborts.ratio"></span>
<pre><code>aborts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The ratio of aborts to the total number of launch attempts</td>
</tr>
<tr class="odd">
<td><span id="field-ajax.requests"></span>
<pre><code>ajax.requests</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of javascript requests</td>
</tr>
<tr class="even">
<td><span id="field-alert.access_denied"></span>
<pre><code>alert.access_denied</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A valid certificate was received, but when access control was applied, the sender decided not to proceed with negotiation. Code 49.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.bad_certificate"></span>
<pre><code>alert.bad_certificate</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A certificate was corrupt, contained signatures that did not verify correctly, etc. Code 42.</td>
</tr>
<tr class="even">
<td><span id="field-alert.bad_record_mac"></span>
<pre><code>alert.bad_record_mac</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This alert is returned if a record is received with an incorrect MAC. Code 20.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.certificate_expired"></span>
<pre><code>alert.certificate_expired</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A certificate has expired or is not currently valid. Code 45.</td>
</tr>
<tr class="even">
<td><span id="field-alert.certificate_revoked"></span>
<pre><code>alert.certificate_revoked</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A certificate was revoked by its signer. Code 44.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.certificate_unknown"></span>
<pre><code>alert.certificate_unknown</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable. Code 46.</td>
</tr>
<tr class="even">
<td><span id="field-alert.close_notify"></span>
<pre><code>alert.close_notify</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This message notifies the recipient that the sender will not send any more messages on this connection. Code 0.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.decode_error"></span>
<pre><code>alert.decode_error</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A message could not be decoded because some field was out of the specified range or the length of the message was incorrect. Code 50.</td>
</tr>
<tr class="even">
<td><span id="field-alert.decompression_failure"></span>
<pre><code>alert.decompression_failure</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The decompression function received improper input (e.g., data that would expand to excessive length). Code 30.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.decrypt_error"></span>
<pre><code>alert.decrypt_error</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A handshake cryptographic operation failed, including being unable to correctly verify a signature or validate a Finished message. Code 51.</td>
</tr>
<tr class="even">
<td><span id="field-alert.decryption_failed"></span>
<pre><code>alert.decryption_failed</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This alert was used in some earlier versions of TLS, and may have permitted certain attacks against the CBC mode. Code 21.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.export_restriction"></span>
<pre><code>alert.export_restriction</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This alert was used in some earlier versions of TLS. Code 60.</td>
</tr>
<tr class="even">
<td><span id="field-alert.handshake_failure"></span>
<pre><code>alert.handshake_failure</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Reception of a handshake failure alert message indicates that the sender was unable to negotiate an acceptable set of security parameters given the options available. Code 40.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.illegal_parameter"></span>
<pre><code>alert.illegal_parameter</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A field in the handshake was out of range or inconsistent with other fields. Code 47.</td>
</tr>
<tr class="even">
<td><span id="field-alert.insufficient_security"></span>
<pre><code>alert.insufficient_security</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Returned instead of a handshake failure when a negotiation has failed specifically because the server requires ciphers more secure than those supported by the client. Code 71.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.internal_error"></span>
<pre><code>alert.internal_error</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>An internal error unrelated to the peer or the correctness of the protocol (such as a memory allocation failure) makes it impossible to continue. Code 80.</td>
</tr>
<tr class="even">
<td><span id="field-alert.no_certificate"></span>
<pre><code>alert.no_certificate</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This alert was used in SSLv3 but not any version of TLS. Code 41.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.no_renegotiation"></span>
<pre><code>alert.no_renegotiation</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Sent by the client in response to a hello request or by the server in response to a client hello after initial handshaking. Code 100.</td>
</tr>
<tr class="even">
<td><span id="field-alert.protocol_version"></span>
<pre><code>alert.protocol_version</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The protocol version the client has attempted to negotiate is recognized but not supported. Code 70.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.record_overflow"></span>
<pre><code>alert.record_overflow</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A TLSCiphertext record was received that had a length more than 2^14+2048 bytes, or a record decrypted to a TLSCompressed record with more than 2^14+1024 bytes. Code 22.</td>
</tr>
<tr class="even">
<td><span id="field-alert.unexpected_message"></span>
<pre><code>alert.unexpected_message</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>An inappropriate message was received. Code 10.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.unknown_ca"></span>
<pre><code>alert.unknown_ca</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A valid certificate chain or partial chain was received, but the certificate was not accepted because the CA certificate could not be located or couldn't be matched with a known, trusted CA. Code 48.</td>
</tr>
<tr class="even">
<td><span id="field-alert.unsupported_certificate"></span>
<pre><code>alert.unsupported_certificate</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>A certificate was of an unsupported type. Code 43.</td>
</tr>
<tr class="odd">
<td><span id="field-alert.unsupported_extension"></span>
<pre><code>alert.unsupported_extension</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Sent by clients that receive an extended server hello containing an extension that they did not put in the corresponding client hello. Code 110.</td>
</tr>
<tr class="even">
<td><span id="field-alert.user_canceled"></span>
<pre><code>alert.user_canceled</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>This handshake is being canceled for some reason unrelated to a protocol failure. Code 90.</td>
</tr>
<tr class="odd">
<td><span id="field-alert_types"></span>
<pre><code>alert_types</code></pre></td>
<td><a href="#type-alerttypes"></a>
<pre><code>alerttypes</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Flags of alerts present in the TLS conversation</td>
</tr>
<tr class="even">
<td><span id="field-application.id"></span>
<pre><code>application.id</code></pre></td>
<td><a href="#type-application_id"></a>
<pre><code>application_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The application ID</td>
</tr>
<tr class="odd">
<td><span id="field-application.name"></span>
<pre><code>application.name</code></pre></td>
<td><a href="#type-application"></a>
<pre><code>application</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The application</td>
</tr>
<tr class="even">
<td><span id="field-attempts"></span>
<pre><code>attempts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of launch attempts</td>
</tr>
<tr class="odd">
<td><span id="field-begin"></span>
<pre><code>begin</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The timestamp of the first captured packet</td>
</tr>
<tr class="even">
<td><span id="field-begins"></span>
<pre><code>begins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of VoIP flows that started</td>
</tr>
<tr class="odd">
<td><span id="field-call"></span>
<pre><code>call</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The VoIP call id</td>
</tr>
<tr class="even">
<td><span id="field-call.direction"></span>
<pre><code>call.direction</code></pre></td>
<td><a href="#type-calldirection"></a>
<pre><code>calldirection</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The direction (inbound, outbound, unknown) of the VoIP calls</td>
</tr>
<tr class="odd">
<td><span id="field-call.duration"></span>
<pre><code>call.duration</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total duration of the VoIP calls</td>
</tr>
<tr class="even">
<td><span id="field-call.global.jitter"></span>
<pre><code>call.global.jitter</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average measured jitter for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-call.global.rtt"></span>
<pre><code>call.global.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-call.jitter.count"></span>
<pre><code>call.jitter.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of measured jitters for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-call.jitter.deviation"></span>
<pre><code>call.jitter.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the measured jitter for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-call.jitter.total"></span>
<pre><code>call.jitter.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The sum of both caller and callee average round-trip times</td>
</tr>
<tr class="odd">
<td><span id="field-call.rtt.count"></span>
<pre><code>call.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of round-trip times for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-call.rtt.deviation"></span>
<pre><code>call.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for call PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-call.rtt.total"></span>
<pre><code>call.rtt.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The sum of both caller and callee average round-trip times</td>
</tr>
<tr class="even">
<td><span id="field-call.state"></span>
<pre><code>call.state</code></pre></td>
<td><a href="#type-callstate"></a>
<pre><code>callstate</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The latest call state in this conversation</td>
</tr>
<tr class="odd">
<td><span id="field-callee"></span>
<pre><code>callee</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The VoIP callee id</td>
</tr>
<tr class="even">
<td><span id="field-callee.codec"></span>
<pre><code>callee.codec</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The voice codec of the callee</td>
</tr>
<tr class="odd">
<td><span id="field-callee.ip"></span>
<pre><code>callee.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The IP address of the callee</td>
</tr>
<tr class="even">
<td><span id="field-callee.jitter"></span>
<pre><code>callee.jitter</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average measured jitter for a PDU (protocol data unit) emitted by the callee</td>
</tr>
<tr class="odd">
<td><span id="field-callee.jitter.count"></span>
<pre><code>callee.jitter.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of measured jitters for PDUs (protocol data units) emitted by the callee</td>
</tr>
<tr class="even">
<td><span id="field-callee.jitter.deviation"></span>
<pre><code>callee.jitter.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the measured jitters for PDUs (protocol data units) emitted by the callee</td>
</tr>
<tr class="odd">
<td><span id="field-callee.label"></span>
<pre><code>callee.label</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The display name of the callee</td>
</tr>
<tr class="even">
<td><span id="field-callee.lost.pdus"></span>
<pre><code>callee.lost.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of lost callee PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-callee.lost.pdus.ratio"></span>
<pre><code>callee.lost.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of lost to the total number of PDUs (protocol data units) emitted by the callee</td>
</tr>
<tr class="even">
<td><span id="field-callee.mac"></span>
<pre><code>callee.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The MAC address of the Callee</td>
</tr>
<tr class="odd">
<td><span id="field-callee.rtt"></span>
<pre><code>callee.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="even">
<td><span id="field-callee.rtt.count"></span>
<pre><code>callee.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="odd">
<td><span id="field-callee.rtt.deviation"></span>
<pre><code>callee.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="even">
<td><span id="field-callee.zone.id"></span>
<pre><code>callee.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The zone ID of the callee</td>
</tr>
<tr class="odd">
<td><span id="field-callee.zone.name"></span>
<pre><code>callee.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The zone of the callee</td>
</tr>
<tr class="even">
<td><span id="field-caller"></span>
<pre><code>caller</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The VoIP caller id</td>
</tr>
<tr class="odd">
<td><span id="field-caller.codec"></span>
<pre><code>caller.codec</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The voice codec of the caller</td>
</tr>
<tr class="even">
<td><span id="field-caller.ip"></span>
<pre><code>caller.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The IP address of the caller</td>
</tr>
<tr class="odd">
<td><span id="field-caller.jitter"></span>
<pre><code>caller.jitter</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average measured jitter for a PDU (protocol data unit) emitted by the the caller</td>
</tr>
<tr class="even">
<td><span id="field-caller.jitter.count"></span>
<pre><code>caller.jitter.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of measured jitters for PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="odd">
<td><span id="field-caller.jitter.deviation"></span>
<pre><code>caller.jitter.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the measured jitters for PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="even">
<td><span id="field-caller.label"></span>
<pre><code>caller.label</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The display name of the caller</td>
</tr>
<tr class="odd">
<td><span id="field-caller.lost.pdus"></span>
<pre><code>caller.lost.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of lost caller PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-caller.lost.pdus.ratio"></span>
<pre><code>caller.lost.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of lost to the total number of PDUs (protocol data units) emitted by the caller</td>
</tr>
<tr class="odd">
<td><span id="field-caller.mac"></span>
<pre><code>caller.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The MAC address of the Caller</td>
</tr>
<tr class="even">
<td><span id="field-caller.rtt"></span>
<pre><code>caller.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the callee</td>
</tr>
<tr class="odd">
<td><span id="field-caller.rtt.count"></span>
<pre><code>caller.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units emitted by the callee</td>
</tr>
<tr class="even">
<td><span id="field-caller.rtt.deviation"></span>
<pre><code>caller.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the callee</td>
</tr>
<tr class="odd">
<td><span id="field-caller.zone.id"></span>
<pre><code>caller.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The zone ID of the caller</td>
</tr>
<tr class="even">
<td><span id="field-caller.zone.name"></span>
<pre><code>caller.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The zone of the caller</td>
</tr>
<tr class="odd">
<td><span id="field-capture.hostname"></span>
<pre><code>capture.hostname</code></pre></td>
<td><a href="#type-poller"></a>
<pre><code>poller</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The probe device hostname that captured this traffic</td>
</tr>
<tr class="even">
<td><span id="field-capture.id"></span>
<pre><code>capture.id</code></pre></td>
<td><a href="#type-poller_id"></a>
<pre><code>poller_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The probe device ID that captured this traffic</td>
</tr>
<tr class="odd">
<td><span id="field-cgp.client.pdus"></span>
<pre><code>cgp.client.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of CGP PDUs (protocol data units) at applicative level emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-cgp.dest.pdus"></span>
<pre><code>cgp.dest.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of CGP PDUs (protocol data units) at applicative level emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-cgp.pdus"></span>
<pre><code>cgp.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of CGP PDUs (protocol data units) at applicative level in both directions</td>
</tr>
<tr class="even">
<td><span id="field-cgp.server.pdus"></span>
<pre><code>cgp.server.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of CGP PDUs (protocol data units) at applicative level emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-cgp.source.pdus"></span>
<pre><code>cgp.source.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of CGP PDUs (protocol data units) at applicative level emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-channel"></span>
<pre><code>channel</code></pre></td>
<td><a href="#type-channel"></a>
<pre><code>channel</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The Citrix channel</td>
</tr>
<tr class="odd">
<td><span id="field-chunked.transfers"></span>
<pre><code>chunked.transfers</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of times the HTTP 'chunked' transfer encoding has been used</td>
</tr>
<tr class="even">
<td><span id="field-cipher"></span>
<pre><code>cipher</code></pre></td>
<td><a href="#type-ciphersuite"></a>
<pre><code>ciphersuite</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The set of cryptographic algorithms used to secure this conversation</td>
</tr>
<tr class="odd">
<td><span id="field-cipher.is_weak"></span>
<pre><code>cipher.is_weak</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Is the TLS cipher weak?</td>
</tr>
<tr class="even">
<td><span id="field-citrix.application"></span>
<pre><code>citrix.application</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>citrix
citrix_channels</code></pre></td>
<td>The published Citrix application being executed</td>
</tr>
<tr class="odd">
<td><span id="field-client.common_name"></span>
<pre><code>client.common_name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The Common Name of the client certificate</td>
</tr>
<tr class="even">
<td><span id="field-client.compressed.pdus"></span>
<pre><code>client.compressed.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The number of compressed client PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-client.compressed.pdus.ratio"></span>
<pre><code>client.compressed.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The ratio of compressions to the total number of PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.data"></span>
<pre><code>client.data</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of client data PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-client.datasource.kind"></span>
<pre><code>client.datasource.kind</code></pre></td>
<td><a href="#type-pktsourcekind"></a>
<pre><code>pktsourcekind</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (client-side)</td>
</tr>
<tr class="even">
<td><span id="field-client.datasource.name"></span>
<pre><code>client.datasource.name</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source name on which this traffic has been captured (client-side)</td>
</tr>
<tr class="odd">
<td><span id="field-client.datasource.pair"></span>
<pre><code>client.datasource.pair</code></pre></td>
<td><a href="#type-pktsourcepair"></a>
<pre><code>pktsourcepair</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type and name on which this traffic has been captured (client-side)</td>
</tr>
<tr class="even">
<td><span id="field-client.diffserv"></span>
<pre><code>client.diffserv</code></pre></td>
<td><a href="#type-diffserv"></a>
<pre><code>diffserv</code></pre></td>
<td><pre><code>icmp
other_ip
tcp
udp</code></pre></td>
<td>The client differentiated service</td>
</tr>
<tr class="odd">
<td><span id="field-client.dtt"></span>
<pre><code>client.dtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The average data-transfer time for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.dtt.count"></span>
<pre><code>client.dtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The number of data-transfer times for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.dtt.deviation"></span>
<pre><code>client.dtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The deviation of the data-transfer time for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.dupacks"></span>
<pre><code>client.dupacks</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of duplicated ACK packets from the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.dupacks.ratio"></span>
<pre><code>client.dupacks.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of duplicated ACKs to the total number of packets emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.emtu"></span>
<pre><code>client.emtu</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp
non_ip
other_ip
tcp
udp</code></pre></td>
<td>The maximum payload in a single ethernet packet emmited by the client in these conversations (this value is assumed to be the MTU of the client's network interface, although the actual MTU value might be greater)</td>
</tr>
<tr class="odd">
<td><span id="field-client.error.ip"></span>
<pre><code>client.error.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The IP address of the client, as it appears in the headers of the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-client.error.port"></span>
<pre><code>client.error.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The port of the client, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-client.error.zone.id"></span>
<pre><code>client.error.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone ID of the client, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-client.error.zone.name"></span>
<pre><code>client.error.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone of the client, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-client.expiration"></span>
<pre><code>client.expiration</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The expiration date of the client certificate</td>
</tr>
<tr class="even">
<td><span id="field-client.file"></span>
<pre><code>client.file</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the Pcap File used as traffic source (client-side)</td>
</tr>
<tr class="odd">
<td><span id="field-client.fins"></span>
<pre><code>client.fins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of FIN packets emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.fins.ratio"></span>
<pre><code>client.fins.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of client FIN packets in a connection</td>
</tr>
<tr class="odd">
<td><span id="field-client.hostname"></span>
<pre><code>client.hostname</code></pre></td>
<td><a href="#type-hostname"></a>
<pre><code>hostname</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The hostname of the client</td>
</tr>
<tr class="even">
<td><span id="field-client.interface"></span>
<pre><code>client.interface</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured (client-side)</td>
</tr>
<tr class="odd">
<td><span id="field-client.ip"></span>
<pre><code>client.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The IP address of the client</td>
</tr>
<tr class="even">
<td><span id="field-client.ja3"></span>
<pre><code>client.ja3</code></pre></td>
<td><a href="#type-tls_fingerprint"></a>
<pre><code>tls_fingerprint</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The JA3 client fingerprint</td>
</tr>
<tr class="odd">
<td><span id="field-client.keepalives"></span>
<pre><code>client.keepalives</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of keep alives from the client</td>
</tr>
<tr class="even">
<td><span id="field-client.key.bits"></span>
<pre><code>client.key.bits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of bits in the client key</td>
</tr>
<tr class="odd">
<td><span id="field-client.key.type"></span>
<pre><code>client.key.type</code></pre></td>
<td><a href="#type-keytype"></a>
<pre><code>keytype</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The type of the client key</td>
</tr>
<tr class="even">
<td><span id="field-client.mac"></span>
<pre><code>client.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The MAC address of the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.meta"></span>
<pre><code>client.meta</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of client metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
</tr>
<tr class="even">
<td><span id="field-client.os"></span>
<pre><code>client.os</code></pre></td>
<td><a href="#type-os"></a>
<pre><code>os</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The client operating system</td>
</tr>
<tr class="odd">
<td><span id="field-client.payload"></span>
<pre><code>client.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes of data (without headers) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.payload.pdus"></span>
<pre><code>client.payload.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) with payload emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.payload.ratio"></span>
<pre><code>client.payload.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The ratio of payload bytes to the entire traffic emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.pdus"></span>
<pre><code>client.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.port"></span>
<pre><code>client.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</code></pre></td>
<td>The TCP/UDP port of the client</td>
</tr>
<tr class="even">
<td><span id="field-client.rd"></span>
<pre><code>client.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average retransmission delay for PDUs emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.rd.count"></span>
<pre><code>client.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of retransmission delays for PDUs emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.rd.deviation"></span>
<pre><code>client.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the retransmission delay for PDUs emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.remote"></span>
<pre><code>client.remote</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured via rpcapd (client-side)</td>
</tr>
<tr class="even">
<td><span id="field-client.retrans.payload"></span>
<pre><code>client.retrans.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.retrans.pdus.ratio"></span>
<pre><code>client.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.retrans.traffic"></span>
<pre><code>client.retrans.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes in retransmitted PDUs emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.retrans.traffic.ratio"></span>
<pre><code>client.retrans.traffic.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmitted traffic to the entire traffic emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.rsts"></span>
<pre><code>client.rsts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of RST packets emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.rsts.ratio"></span>
<pre><code>client.rsts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of client RST packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-client.rtt"></span>
<pre><code>client.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-client.rtt.count"></span>
<pre><code>client.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-client.rtt.deviation"></span>
<pre><code>client.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-client.signalization.payload"></span>
<pre><code>client.signalization.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.signalization.pdus"></span>
<pre><code>client.signalization.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.signalization.rd"></span>
<pre><code>client.signalization.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average retransmission delay for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.signalization.rd.count"></span>
<pre><code>client.signalization.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of retransmission delays for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.signalization.rd.deviation"></span>
<pre><code>client.signalization.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.signalization.retrans.pdus.ratio"></span>
<pre><code>client.signalization.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.signalization.rtt"></span>
<pre><code>client.signalization.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-client.signalization.rtt.count"></span>
<pre><code>client.signalization.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-client.signalization.rtt.deviation"></span>
<pre><code>client.signalization.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-client.signalization.traffic"></span>
<pre><code>client.signalization.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes in signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.signature"></span>
<pre><code>client.signature</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The client signature</td>
</tr>
<tr class="even">
<td><span id="field-client.traffic"></span>
<pre><code>client.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.vlan"></span>
<pre><code>client.vlan</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the client side of the transaction (alias of client.vlans.inner)</td>
</tr>
<tr class="even">
<td><span id="field-client.vlans"></span>
<pre><code>client.vlans</code></pre></td>
<td><a href="#type-array"></a>
<pre><code>array</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The VLAN ids on the client side of the transaction. The first VLAN id represents the outer VLAN and the last VLAN id represents the inner VLAN</td>
</tr>
<tr class="odd">
<td><span id="field-client.vlans.count"></span>
<pre><code>client.vlans.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The number of VLANs on the client side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-client.vlans.inner"></span>
<pre><code>client.vlans.inner</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the client side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-client.vlans.outer"></span>
<pre><code>client.vlans.outer</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The outer VLAN id on the client side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-client.zero_windows"></span>
<pre><code>client.zero_windows</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of zero-window size packets emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.zero_windows.ratio"></span>
<pre><code>client.zero_windows.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of zero-window size to the total number of packets emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-client.zone.id"></span>
<pre><code>client.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone id of the client</td>
</tr>
<tr class="odd">
<td><span id="field-client.zone.name"></span>
<pre><code>client.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone of the client</td>
</tr>
<tr class="even">
<td><span id="field-closes"></span>
<pre><code>closes</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of TCP sessions that ended properly (by acked FIN or RST)</td>
</tr>
<tr class="odd">
<td><span id="field-command"></span>
<pre><code>command</code></pre></td>
<td><a href="#type-databasecommand"></a>
<pre><code>databasecommand</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The database command type</td>
</tr>
<tr class="even">
<td><span id="field-compressed.pdus"></span>
<pre><code>compressed.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The total number of compressed PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-compressed.pdus.ratio"></span>
<pre><code>compressed.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The ratio of compressions to the total number of PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-compressed.responses"></span>
<pre><code>compressed.responses</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of compressed HTTP responses</td>
</tr>
<tr class="odd">
<td><span id="field-ct"></span>
<pre><code>ct</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp
tls</code></pre></td>
<td>The average connection time</td>
</tr>
<tr class="even">
<td><span id="field-ct.count"></span>
<pre><code>ct.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp
tls</code></pre></td>
<td>The number of successful handshakes</td>
</tr>
<tr class="odd">
<td><span id="field-ct.deviation"></span>
<pre><code>ct.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp
tls</code></pre></td>
<td>The deviation of the connection time</td>
</tr>
<tr class="even">
<td><span id="field-data.payload"></span>
<pre><code>data.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of data in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-database"></span>
<pre><code>database</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The name of the database</td>
</tr>
<tr class="even">
<td><span id="field-dcerpc"></span>
<pre><code>dcerpc</code></pre></td>
<td><a href="#type-dcerpc"></a>
<pre><code>dcerpc</code></pre></td>
<td><pre><code>tcp
udp</code></pre></td>
<td>The identifier of the DCE/RPC service</td>
</tr>
<tr class="odd">
<td><span id="field-decrypted"></span>
<pre><code>decrypted</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of decrypted conversations</td>
</tr>
<tr class="even">
<td><span id="field-dest.common_name"></span>
<pre><code>dest.common_name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The Common Name of the destination certificate</td>
</tr>
<tr class="odd">
<td><span id="field-dest.compressed.pdus"></span>
<pre><code>dest.compressed.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The number of compressed destination PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-dest.compressed.pdus.ratio"></span>
<pre><code>dest.compressed.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The ratio of compressions to the total number of PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.data"></span>
<pre><code>dest.data</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of destination data PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-dest.datasource.kind"></span>
<pre><code>dest.datasource.kind</code></pre></td>
<td><a href="#type-pktsourcekind"></a>
<pre><code>pktsourcekind</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (destination-side)</td>
</tr>
<tr class="odd">
<td><span id="field-dest.datasource.name"></span>
<pre><code>dest.datasource.name</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source name on which this traffic has been captured (destination-side)</td>
</tr>
<tr class="even">
<td><span id="field-dest.datasource.pair"></span>
<pre><code>dest.datasource.pair</code></pre></td>
<td><a href="#type-pktsourcepair"></a>
<pre><code>pktsourcepair</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type and name on which this traffic has been captured (destination-side)</td>
</tr>
<tr class="odd">
<td><span id="field-dest.diffserv"></span>
<pre><code>dest.diffserv</code></pre></td>
<td><a href="#type-diffserv"></a>
<pre><code>diffserv</code></pre></td>
<td><pre><code>icmp
other_ip
tcp
udp</code></pre></td>
<td>The destination differentiated service</td>
</tr>
<tr class="even">
<td><span id="field-dest.dtt"></span>
<pre><code>dest.dtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The average data-transfer time for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.dtt.count"></span>
<pre><code>dest.dtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The number of data-transfer times for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.dtt.deviation"></span>
<pre><code>dest.dtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The deviation of the data-transfer time for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.dupacks"></span>
<pre><code>dest.dupacks</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of duplicated ACK packets from the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.dupacks.ratio"></span>
<pre><code>dest.dupacks.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of duplicated ACKs to the total number of packets emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.emtu"></span>
<pre><code>dest.emtu</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp
non_ip
other_ip
tcp
udp</code></pre></td>
<td>The maximum payload in a single ethernet packet emmited by the destination in these conversations (this value is assumed to be the MTU of the destination's network interface, although the actual MTU value might be greater)</td>
</tr>
<tr class="even">
<td><span id="field-dest.error.ip"></span>
<pre><code>dest.error.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The IP address of the destination, as it appears in the headers of the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-dest.error.port"></span>
<pre><code>dest.error.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The port of the destination, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-dest.error.zone.id"></span>
<pre><code>dest.error.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone ID of the destination, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-dest.error.zone.name"></span>
<pre><code>dest.error.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone of the destination, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-dest.expiration"></span>
<pre><code>dest.expiration</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The expiration date of the destination certificate</td>
</tr>
<tr class="odd">
<td><span id="field-dest.file"></span>
<pre><code>dest.file</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the Pcap File used as traffic source (destination-side)</td>
</tr>
<tr class="even">
<td><span id="field-dest.fins"></span>
<pre><code>dest.fins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of FIN packets emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.fins.ratio"></span>
<pre><code>dest.fins.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of destination FIN packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-dest.hostname"></span>
<pre><code>dest.hostname</code></pre></td>
<td><a href="#type-hostname"></a>
<pre><code>hostname</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The hostname of the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.interface"></span>
<pre><code>dest.interface</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured (destination-side)</td>
</tr>
<tr class="even">
<td><span id="field-dest.ip"></span>
<pre><code>dest.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The IP address of the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.ja3"></span>
<pre><code>dest.ja3</code></pre></td>
<td><a href="#type-tls_fingerprint"></a>
<pre><code>tls_fingerprint</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The JA3 destination fingerprint</td>
</tr>
<tr class="even">
<td><span id="field-dest.keepalives"></span>
<pre><code>dest.keepalives</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of keep alives from the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.key.bits"></span>
<pre><code>dest.key.bits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of bits in the destination key</td>
</tr>
<tr class="even">
<td><span id="field-dest.key.type"></span>
<pre><code>dest.key.type</code></pre></td>
<td><a href="#type-keytype"></a>
<pre><code>keytype</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The type of the destination key</td>
</tr>
<tr class="odd">
<td><span id="field-dest.mac"></span>
<pre><code>dest.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The MAC address of the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.meta"></span>
<pre><code>dest.meta</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of destination metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
</tr>
<tr class="odd">
<td><span id="field-dest.os"></span>
<pre><code>dest.os</code></pre></td>
<td><a href="#type-os"></a>
<pre><code>os</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The destination operating system</td>
</tr>
<tr class="even">
<td><span id="field-dest.payload"></span>
<pre><code>dest.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes of data (without headers) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.payload.pdus"></span>
<pre><code>dest.payload.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) with payload emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.payload.ratio"></span>
<pre><code>dest.payload.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The ratio of payload bytes to the entire traffic emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.pdus"></span>
<pre><code>dest.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.port"></span>
<pre><code>dest.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</code></pre></td>
<td>The TCP/UDP port of the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.rd"></span>
<pre><code>dest.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average retransmission delay for PDUs emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.rd.count"></span>
<pre><code>dest.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of retransmission delays for PDUs emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.rd.deviation"></span>
<pre><code>dest.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the retransmission delay for PDUs emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.remote"></span>
<pre><code>dest.remote</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured via rpcapd (destination-side)</td>
</tr>
<tr class="odd">
<td><span id="field-dest.retrans.payload"></span>
<pre><code>dest.retrans.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.retrans.pdus.ratio"></span>
<pre><code>dest.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.retrans.traffic"></span>
<pre><code>dest.retrans.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes in retransmitted PDUs emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.retrans.traffic.ratio"></span>
<pre><code>dest.retrans.traffic.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmitted traffic to the entire traffic emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.rsts"></span>
<pre><code>dest.rsts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of RST packets emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.rsts.ratio"></span>
<pre><code>dest.rsts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of destination RST packets in a connection</td>
</tr>
<tr class="odd">
<td><span id="field-dest.rtt"></span>
<pre><code>dest.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-dest.rtt.count"></span>
<pre><code>dest.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-dest.rtt.deviation"></span>
<pre><code>dest.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-dest.signalization.payload"></span>
<pre><code>dest.signalization.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.signalization.pdus"></span>
<pre><code>dest.signalization.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.signalization.rd"></span>
<pre><code>dest.signalization.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average retransmission delay for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.signalization.rd.count"></span>
<pre><code>dest.signalization.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of retransmission delays for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.signalization.rd.deviation"></span>
<pre><code>dest.signalization.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.signalization.retrans.pdus.ratio"></span>
<pre><code>dest.signalization.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.signalization.rtt"></span>
<pre><code>dest.signalization.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-dest.signalization.rtt.count"></span>
<pre><code>dest.signalization.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-dest.signalization.rtt.deviation"></span>
<pre><code>dest.signalization.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-dest.signalization.traffic"></span>
<pre><code>dest.signalization.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes in signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.signature"></span>
<pre><code>dest.signature</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The destination signature</td>
</tr>
<tr class="odd">
<td><span id="field-dest.traffic"></span>
<pre><code>dest.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.vlan"></span>
<pre><code>dest.vlan</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the destination side of the transaction (alias of destination.vlans.inner)</td>
</tr>
<tr class="odd">
<td><span id="field-dest.vlans"></span>
<pre><code>dest.vlans</code></pre></td>
<td><a href="#type-array"></a>
<pre><code>array</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The VLAN ids on the destination side of the transaction. The first VLAN id represents the outer VLAN and the last VLAN id represents the inner VLAN</td>
</tr>
<tr class="even">
<td><span id="field-dest.vlans.count"></span>
<pre><code>dest.vlans.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The number of VLANs on the destination side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-dest.vlans.inner"></span>
<pre><code>dest.vlans.inner</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the destination side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-dest.vlans.outer"></span>
<pre><code>dest.vlans.outer</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The outer VLAN id on the destination side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-dest.zero_windows"></span>
<pre><code>dest.zero_windows</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of zero-window size packets emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.zero_windows.ratio"></span>
<pre><code>dest.zero_windows.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of zero-window size to the total number of packets emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dest.zone.id"></span>
<pre><code>dest.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone id of the destination</td>
</tr>
<tr class="even">
<td><span id="field-dest.zone.name"></span>
<pre><code>dest.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone of the destination</td>
</tr>
<tr class="odd">
<td><span id="field-dns.rt"></span>
<pre><code>dns.rt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The average DNS response time</td>
</tr>
<tr class="even">
<td><span id="field-dns.rt.deviation"></span>
<pre><code>dns.rt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The deviation of the DNS response time</td>
</tr>
<tr class="odd">
<td><span id="field-domain"></span>
<pre><code>domain</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>citrix
citrix_channels
smb</code></pre></td>
<td>The Windows Domain of the user</td>
</tr>
<tr class="even">
<td><span id="field-domain.primary"></span>
<pre><code>domain.primary</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http
tls</code></pre></td>
<td>The primary domain name (www.example.org -&gt; example.org)</td>
</tr>
<tr class="odd">
<td><span id="field-domain.short"></span>
<pre><code>domain.short</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http
tls</code></pre></td>
<td>The primary domain name, without TLD</td>
</tr>
<tr class="even">
<td><span id="field-domain.toplevel"></span>
<pre><code>domain.toplevel</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http
tls</code></pre></td>
<td>The top-level domain name (TLD)</td>
</tr>
<tr class="odd">
<td><span id="field-dtt.count"></span>
<pre><code>dtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The total number of data-transfer times in both directions</td>
</tr>
<tr class="even">
<td><span id="field-dtt.deviation"></span>
<pre><code>dtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The deviation of the data-transfer time in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-dtt.total"></span>
<pre><code>dtt.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The sum of both client and server average data-transfer times</td>
</tr>
<tr class="even">
<td><span id="field-dupacks"></span>
<pre><code>dupacks</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of duplicated ACK packets in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-dupacks.ratio"></span>
<pre><code>dupacks.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of duplicated ACKs to the total number of packets in both directions</td>
</tr>
<tr class="even">
<td><span id="field-encryption"></span>
<pre><code>encryption</code></pre></td>
<td><a href="#type-encryption"></a>
<pre><code>encryption</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The Citrix encryption type</td>
</tr>
<tr class="odd">
<td><span id="field-end"></span>
<pre><code>end</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The timestamp of the last captured packet</td>
</tr>
<tr class="even">
<td><span id="field-ends"></span>
<pre><code>ends</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of VoIP flows that ended</td>
</tr>
<tr class="odd">
<td><span id="field-error.alerts"></span>
<pre><code>error.alerts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of error alerts (everything but close notifications)</td>
</tr>
<tr class="even">
<td><span id="field-error.code"></span>
<pre><code>error.code</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The error code, specific to some databases (MySQL, TDS and TNS)</td>
</tr>
<tr class="odd">
<td><span id="field-error.hits"></span>
<pre><code>error.hits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of hits with a response code of at least 400</td>
</tr>
<tr class="even">
<td><span id="field-error.message"></span>
<pre><code>error.message</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The database error message</td>
</tr>
<tr class="odd">
<td><span id="field-error.protocol"></span>
<pre><code>error.protocol</code></pre></td>
<td><a href="#type-ipprotocol"></a>
<pre><code>ipprotocol</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The IP protocol of the PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-error.status"></span>
<pre><code>error.status</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The database error status</td>
</tr>
<tr class="odd">
<td><span id="field-errors"></span>
<pre><code>errors</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
dns
smb
voip</code></pre></td>
<td>The number of errors</td>
</tr>
<tr class="even">
<td><span id="field-errors.ratio"></span>
<pre><code>errors.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
dns
smb
voip</code></pre></td>
<td>The ratio of errors to the total number of queries</td>
</tr>
<tr class="odd">
<td><span id="field-file"></span>
<pre><code>file</code></pre></td>
<td><a href="#type-path"></a>
<pre><code>path</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The file path</td>
</tr>
<tr class="even">
<td><span id="field-file.count"></span>
<pre><code>file.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of processed files</td>
</tr>
<tr class="odd">
<td><span id="field-file.id"></span>
<pre><code>file.id</code></pre></td>
<td><a href="#type-descriptor"></a>
<pre><code>descriptor</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The CIFS file descriptor id</td>
</tr>
<tr class="even">
<td><span id="field-fins"></span>
<pre><code>fins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of FIN packets in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-fins.ratio"></span>
<pre><code>fins.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of FIN packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-global.dtt"></span>
<pre><code>global.dtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The average data-transfer time in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-global.emtu"></span>
<pre><code>global.emtu</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp
non_ip
other_ip
tcp
udp</code></pre></td>
<td>The maximum payload in a single ethernet packet in both directions</td>
</tr>
<tr class="even">
<td><span id="field-global.rd"></span>
<pre><code>global.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average retransmission delay in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-global.rtt"></span>
<pre><code>global.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average round-trip time in both directions</td>
</tr>
<tr class="even">
<td><span id="field-global.signalization.rd"></span>
<pre><code>global.signalization.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average retransmission delay for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-global.signalization.rtt"></span>
<pre><code>global.signalization.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-has_contributed"></span>
<pre><code>has_contributed</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Did this hit contribute to the metrics of the page it is attached to?</td>
</tr>
<tr class="odd">
<td><span id="field-has_timeouted"></span>
<pre><code>has_timeouted</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>databases
http
smb</code></pre></td>
<td>Did this transaction timeout?</td>
</tr>
<tr class="even">
<td><span id="field-has_voice"></span>
<pre><code>has_voice</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>Was there any voice in the conversation?</td>
</tr>
<tr class="odd">
<td><span id="field-headers"></span>
<pre><code>headers</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of headers in both query and response PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-hit"></span>
<pre><code>hit</code></pre></td>
<td><a href="#type-uuid"></a>
<pre><code>uuid</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>This hit's unique identifier</td>
</tr>
<tr class="odd">
<td><span id="field-hit.parent"></span>
<pre><code>hit.parent</code></pre></td>
<td><a href="#type-uuid"></a>
<pre><code>uuid</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>This hit's parent's unique identifier</td>
</tr>
<tr class="even">
<td><span id="field-hit.referrer"></span>
<pre><code>hit.referrer</code></pre></td>
<td><a href="#type-uuid"></a>
<pre><code>uuid</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>This hit's referrer's unique identifier</td>
</tr>
<tr class="odd">
<td><span id="field-hit.rt"></span>
<pre><code>hit.rt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The average hit response time</td>
</tr>
<tr class="even">
<td><span id="field-hit.rt.count"></span>
<pre><code>hit.rt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of HTTP hit response times</td>
</tr>
<tr class="odd">
<td><span id="field-hit.rt.deviation"></span>
<pre><code>hit.rt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The deviation of the hit response time</td>
</tr>
<tr class="even">
<td><span id="field-hits"></span>
<pre><code>hits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of HTTP hits</td>
</tr>
<tr class="odd">
<td><span id="field-host"></span>
<pre><code>host</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The URL Host</td>
</tr>
<tr class="even">
<td><span id="field-icmp.code"></span>
<pre><code>icmp.code</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The ICMP message code</td>
</tr>
<tr class="odd">
<td><span id="field-icmp.message"></span>
<pre><code>icmp.message</code></pre></td>
<td><a href="#type-icmpmessage"></a>
<pre><code>icmpmessage</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The ICMP message</td>
</tr>
<tr class="even">
<td><span id="field-icmp.type"></span>
<pre><code>icmp.type</code></pre></td>
<td><a href="#type-icmptype"></a>
<pre><code>icmptype</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The ICMP message type</td>
</tr>
<tr class="odd">
<td><span id="field-ip.family"></span>
<pre><code>ip.family</code></pre></td>
<td><a href="#type-ipfamily"></a>
<pre><code>ipfamily</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The IP address family</td>
</tr>
<tr class="even">
<td><span id="field-ip.protocol"></span>
<pre><code>ip.protocol</code></pre></td>
<td><a href="#type-ipprotocol"></a>
<pre><code>ipprotocol</code></pre></td>
<td><pre><code>other_ip
voip</code></pre></td>
<td>The IP protocol</td>
</tr>
<tr class="odd">
<td><span id="field-is_ajax"></span>
<pre><code>is_ajax</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Is this hit requested through javascript?</td>
</tr>
<tr class="even">
<td><span id="field-is_chunked"></span>
<pre><code>is_chunked</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Does this hit use HTTP 'chunked' transfer encoding?</td>
</tr>
<tr class="odd">
<td><span id="field-is_compressed"></span>
<pre><code>is_compressed</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Is this hit compressed?</td>
</tr>
<tr class="even">
<td><span id="field-is_deepinspect"></span>
<pre><code>is_deepinspect</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Was page reconstruction activated for this hit?</td>
</tr>
<tr class="odd">
<td><span id="field-is_main"></span>
<pre><code>is_main</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Is this hit the main resource of the page?</td>
</tr>
<tr class="even">
<td><span id="field-is_root"></span>
<pre><code>is_root</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>Is this a root hit?</td>
</tr>
<tr class="odd">
<td><span id="field-keepalives"></span>
<pre><code>keepalives</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The total number of keep alives in both directions</td>
</tr>
<tr class="even">
<td><span id="field-launch.time"></span>
<pre><code>launch.time</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The average launch time for Citrix applications</td>
</tr>
<tr class="odd">
<td><span id="field-launch.time.deviation"></span>
<pre><code>launch.time.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The deviation of the launch time</td>
</tr>
<tr class="even">
<td><span id="field-layer"></span>
<pre><code>layer</code></pre></td>
<td><a href="#type-layer"></a>
<pre><code>layer</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The layer</td>
</tr>
<tr class="odd">
<td><span id="field-login.time"></span>
<pre><code>login.time</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The average login time</td>
</tr>
<tr class="even">
<td><span id="field-login.time.count"></span>
<pre><code>login.time.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of logins</td>
</tr>
<tr class="odd">
<td><span id="field-login.time.deviation"></span>
<pre><code>login.time.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The deviation of the login time</td>
</tr>
<tr class="even">
<td><span id="field-lost.pdus"></span>
<pre><code>lost.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of lost PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-lost.pdus.ratio"></span>
<pre><code>lost.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of lost to the total number of PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-metadata.payload"></span>
<pre><code>metadata.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of metadata in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-metadata.read"></span>
<pre><code>metadata.read</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of metadata read by SMB commands (directory listing commands, for example)</td>
</tr>
<tr class="even">
<td><span id="field-metadata.written"></span>
<pre><code>metadata.written</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of metadata written by SMB commands</td>
</tr>
<tr class="odd">
<td><span id="field-method"></span>
<pre><code>method</code></pre></td>
<td><a href="#type-httpquerymethod"></a>
<pre><code>httpquerymethod</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The HTTP request method</td>
</tr>
<tr class="even">
<td><span id="field-module"></span>
<pre><code>module</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The name of the Citrix module used by the client</td>
</tr>
<tr class="odd">
<td><span id="field-mos"></span>
<pre><code>mos</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The VOIP mean opinion score</td>
</tr>
<tr class="even">
<td><span id="field-netflow.hostname"></span>
<pre><code>netflow.hostname</code></pre></td>
<td><a href="#type-hostname"></a>
<pre><code>hostname</code></pre></td>
<td><pre><code>icmp
tcp
udp</code></pre></td>
<td>The hostname of the emitter</td>
</tr>
<tr class="odd">
<td><span id="field-netflow.ip"></span>
<pre><code>netflow.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>icmp
tcp
udp</code></pre></td>
<td>The IP address of the emitter</td>
</tr>
<tr class="even">
<td><span id="field-nonip.protocol"></span>
<pre><code>nonip.protocol</code></pre></td>
<td><a href="#type-ethernetprotocol"></a>
<pre><code>ethernetprotocol</code></pre></td>
<td><pre><code>non_ip</code></pre></td>
<td>The OSI layer 2 protocol</td>
</tr>
<tr class="odd">
<td><span id="field-origin.ip"></span>
<pre><code>origin.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The original client's IP, as it appears in the HTTP header</td>
</tr>
<tr class="even">
<td><span id="field-page.begin"></span>
<pre><code>page.begin</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The timestamp of the first packet in this page</td>
</tr>
<tr class="odd">
<td><span id="field-page.end"></span>
<pre><code>page.end</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The timestamp of the last packet in this page</td>
</tr>
<tr class="even">
<td><span id="field-page.errors"></span>
<pre><code>page.errors</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of errors in all the hits that contributed to these pages, errors consisting of HTTP response codes of at least 400</td>
</tr>
<tr class="odd">
<td><span id="field-page.hits"></span>
<pre><code>page.hits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of hits that contributed to these pages</td>
</tr>
<tr class="even">
<td><span id="field-page.load.time"></span>
<pre><code>page.load.time</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The average page load time</td>
</tr>
<tr class="odd">
<td><span id="field-page.load.time.deviation"></span>
<pre><code>page.load.time.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The deviation of the page load time</td>
</tr>
<tr class="even">
<td><span id="field-page.request.traffic"></span>
<pre><code>page.request.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of request traffic (headers + payload) in all the hits that contributed to these pages</td>
</tr>
<tr class="odd">
<td><span id="field-page.response.traffic"></span>
<pre><code>page.response.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of response traffic (headers + payload) in all the hits that contributed to these pages</td>
</tr>
<tr class="even">
<td><span id="field-page.timeouts"></span>
<pre><code>page.timeouts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of timeouts in all the hits that contributed to these pages</td>
</tr>
<tr class="odd">
<td><span id="field-page.traffic"></span>
<pre><code>page.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of query and response traffic (headers + payload) in all the hits that contributed to these pages</td>
</tr>
<tr class="even">
<td><span id="field-pages"></span>
<pre><code>pages</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of HTTP pages</td>
</tr>
<tr class="odd">
<td><span id="field-payload"></span>
<pre><code>payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
udp
voip</code></pre></td>
<td>The total amount of bytes of data (without headers) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-payload.pdus"></span>
<pre><code>payload.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) with payload in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-payload.ratio"></span>
<pre><code>payload.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The ratio of payload bytes to the entire traffic in both directions</td>
</tr>
<tr class="even">
<td><span id="field-pcap"></span>
<pre><code>pcap</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>dns
tcp
voip</code></pre></td>
<td>The link to the associated captured PCAP file (generated according to the configuration of zones and applications)</td>
</tr>
<tr class="odd">
<td><span id="field-pdus"></span>
<pre><code>pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
dns
icmp
non_ip
other_ip
smb
tcp
udp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level in both directions</td>
</tr>
<tr class="even">
<td><span id="field-points"></span>
<pre><code>points</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The number of points</td>
</tr>
<tr class="odd">
<td><span id="field-protostack"></span>
<pre><code>protostack</code></pre></td>
<td><a href="#type-protostack"></a>
<pre><code>protostack</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
icmp
non_ip
other_ip
smb
tcp
tls
udp
voip</code></pre></td>
<td>The protocol stack</td>
</tr>
<tr class="even">
<td><span id="field-queries"></span>
<pre><code>queries</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
dns
smb</code></pre></td>
<td>The number of queries</td>
</tr>
<tr class="odd">
<td><span id="field-query"></span>
<pre><code>query</code></pre></td>
<td><a href="#type-databasequery"></a>
<pre><code>databasequery</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The database query</td>
</tr>
<tr class="even">
<td><span id="field-query.begin"></span>
<pre><code>query.begin</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>databases
smb</code></pre></td>
<td>The timestamp of the first query packet</td>
</tr>
<tr class="odd">
<td><span id="field-query.class"></span>
<pre><code>query.class</code></pre></td>
<td><a href="#type-dnsclass"></a>
<pre><code>dnsclass</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The class of the DNS query</td>
</tr>
<tr class="even">
<td><span id="field-query.end"></span>
<pre><code>query.end</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>databases
smb</code></pre></td>
<td>The timestamp of the last query packet</td>
</tr>
<tr class="odd">
<td><span id="field-query.name"></span>
<pre><code>query.name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The name of the DNS query</td>
</tr>
<tr class="even">
<td><span id="field-query.payload"></span>
<pre><code>query.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
smb</code></pre></td>
<td>The total amount of bytes of payload in query PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-query.pdus"></span>
<pre><code>query.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
smb</code></pre></td>
<td>The total number of query PDUs (protocol data units) at applicative level</td>
</tr>
<tr class="even">
<td><span id="field-query.tcp_pdus"></span>
<pre><code>query.tcp_pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of TCP packets that form up these HTTP queries</td>
</tr>
<tr class="odd">
<td><span id="field-query.type"></span>
<pre><code>query.type</code></pre></td>
<td><a href="#type-dnstype"></a>
<pre><code>dnstype</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The type of the DNS query</td>
</tr>
<tr class="even">
<td><span id="field-query.write"></span>
<pre><code>query.write</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of data to be written</td>
</tr>
<tr class="odd">
<td><span id="field-query_256"></span>
<pre><code>query_256</code></pre></td>
<td><a href="#type-databasequery"></a>
<pre><code>databasequery</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>First 256 characters of the query</td>
</tr>
<tr class="even">
<td><span id="field-rd.count"></span>
<pre><code>rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of retransmission delays in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-rd.deviation"></span>
<pre><code>rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the retransmission delay in both directions</td>
</tr>
<tr class="even">
<td><span id="field-rd.total"></span>
<pre><code>rd.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The sum of both client and server average data-transfer times</td>
</tr>
<tr class="odd">
<td><span id="field-request.begin"></span>
<pre><code>request.begin</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The timestamp of the first request packet</td>
</tr>
<tr class="even">
<td><span id="field-request.content_length"></span>
<pre><code>request.content_length</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The average Content-Length in the headers of these HTTP requests</td>
</tr>
<tr class="odd">
<td><span id="field-request.content_length.count"></span>
<pre><code>request.content_length.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of HTTP requests with a Content-Length header</td>
</tr>
<tr class="even">
<td><span id="field-request.content_pack"></span>
<pre><code>request.content_pack</code></pre></td>
<td><a href="#type-path"></a>
<pre><code>path</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The path to the pack file that contains the HTTP request content</td>
</tr>
<tr class="odd">
<td><span id="field-request.content_type"></span>
<pre><code>request.content_type</code></pre></td>
<td><a href="#type-mimetype"></a>
<pre><code>mimetype</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The mime-type in the Content-Type header of the HTTP request</td>
</tr>
<tr class="even">
<td><span id="field-request.end"></span>
<pre><code>request.end</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The timestamp of the last request packet</td>
</tr>
<tr class="odd">
<td><span id="field-request.headers"></span>
<pre><code>request.headers</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of headers in request PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-request.payload"></span>
<pre><code>request.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of payload in request PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-request.payload.sha256"></span>
<pre><code>request.payload.sha256</code></pre></td>
<td><a href="#type-sha256"></a>
<pre><code>sha256</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The hash sha256 calculated using the bytes of payload in request PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-request.traffic"></span>
<pre><code>request.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes (headers + payload) in request PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-response.begin"></span>
<pre><code>response.begin</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>databases
http
smb</code></pre></td>
<td>The timestamp of the first response packet</td>
</tr>
<tr class="even">
<td><span id="field-response.category"></span>
<pre><code>response.category</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The HTTP response mime-type's category</td>
</tr>
<tr class="odd">
<td><span id="field-response.class"></span>
<pre><code>response.class</code></pre></td>
<td><a href="#type-dnsclass"></a>
<pre><code>dnsclass</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The class of the DNS response</td>
</tr>
<tr class="even">
<td><span id="field-response.code"></span>
<pre><code>response.code</code></pre></td>
<td><a href="#type-dnscode"></a>
<pre><code>dnscode</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The DNS response code</td>
</tr>
<tr class="odd">
<td><span id="field-response.content_length"></span>
<pre><code>response.content_length</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The average Content-Length in the headers of these HTTP responses</td>
</tr>
<tr class="even">
<td><span id="field-response.content_length.count"></span>
<pre><code>response.content_length.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of HTTP responses with a Content-Length header</td>
</tr>
<tr class="odd">
<td><span id="field-response.content_pack"></span>
<pre><code>response.content_pack</code></pre></td>
<td><a href="#type-path"></a>
<pre><code>path</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The path to the pack file that contains the HTTP response content</td>
</tr>
<tr class="even">
<td><span id="field-response.content_type"></span>
<pre><code>response.content_type</code></pre></td>
<td><a href="#type-mimetype"></a>
<pre><code>mimetype</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The mime-type in the Content-Type header of the HTTP response</td>
</tr>
<tr class="odd">
<td><span id="field-response.end"></span>
<pre><code>response.end</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>databases
http
smb</code></pre></td>
<td>The timestamp of the first response packet</td>
</tr>
<tr class="even">
<td><span id="field-response.headers"></span>
<pre><code>response.headers</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes of headers in response PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-response.payload"></span>
<pre><code>response.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
http
smb</code></pre></td>
<td>The total amount of bytes of payload in response PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-response.payload.sha256"></span>
<pre><code>response.payload.sha256</code></pre></td>
<td><a href="#type-sha256"></a>
<pre><code>sha256</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The hash sha256 calculated using the bytes of payload in response PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-response.pdus"></span>
<pre><code>response.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>databases
smb</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-response.read"></span>
<pre><code>response.read</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of data read by SMB commands</td>
</tr>
<tr class="odd">
<td><span id="field-response.status"></span>
<pre><code>response.status</code></pre></td>
<td><a href="#type-httpstatus"></a>
<pre><code>httpstatus</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The HTTP response code</td>
</tr>
<tr class="even">
<td><span id="field-response.status.category"></span>
<pre><code>response.status.category</code></pre></td>
<td><a href="#type-httpstatuscategory"></a>
<pre><code>httpstatuscategory</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The category of the response status code</td>
</tr>
<tr class="odd">
<td><span id="field-response.tcp_pdus"></span>
<pre><code>response.tcp_pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of TCP packets that form up these HTTP responses</td>
</tr>
<tr class="even">
<td><span id="field-response.traffic"></span>
<pre><code>response.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The total amount of bytes (headers + payload) in response PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-response.type"></span>
<pre><code>response.type</code></pre></td>
<td><a href="#type-dnstype"></a>
<pre><code>dnstype</code></pre></td>
<td><pre><code>dns</code></pre></td>
<td>The type of the DNS response</td>
</tr>
<tr class="even">
<td><span id="field-response.written"></span>
<pre><code>response.written</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The total amount of bytes of data effectively written by SMB commands</td>
</tr>
<tr class="odd">
<td><span id="field-resumed"></span>
<pre><code>resumed</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of resumed sessions</td>
</tr>
<tr class="even">
<td><span id="field-retrans.payload"></span>
<pre><code>retrans.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes of data (without headers) in retransmitted PDUs in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-retrans.pdus.ratio"></span>
<pre><code>retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmissions to the total number of PDUs (protocol data units) with payload in both directions</td>
</tr>
<tr class="even">
<td><span id="field-retrans.traffic"></span>
<pre><code>retrans.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
icmp
non_ip
other_ip
tcp
udp
voip</code></pre></td>
<td>The total amount of bytes in retransmitted PDUs in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-retrans.traffic.ratio"></span>
<pre><code>retrans.traffic.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmitted traffic to the entire traffic in both directions</td>
</tr>
<tr class="even">
<td><span id="field-rows.integrated"></span>
<pre><code>rows.integrated</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of integrated rows</td>
</tr>
<tr class="odd">
<td><span id="field-rows.integrated.per_minute"></span>
<pre><code>rows.integrated.per_minute</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of integrated rows per minute</td>
</tr>
<tr class="even">
<td><span id="field-rows.total"></span>
<pre><code>rows.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The total number of analyzed rows</td>
</tr>
<tr class="odd">
<td><span id="field-rows.total.per_minute"></span>
<pre><code>rows.total.per_minute</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of total rows per minute</td>
</tr>
<tr class="even">
<td><span id="field-rows.truncated"></span>
<pre><code>rows.truncated</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of truncated rows</td>
</tr>
<tr class="odd">
<td><span id="field-rows.truncated.per_minute"></span>
<pre><code>rows.truncated.per_minute</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>flows</code></pre></td>
<td>The number of truncated rows per minute</td>
</tr>
<tr class="even">
<td><span id="field-rsts"></span>
<pre><code>rsts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of RST packets in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-rsts.ratio"></span>
<pre><code>rsts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of RST packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-rtt.count"></span>
<pre><code>rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of round-trip times in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-rtt.deviation"></span>
<pre><code>rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the round-trip time in both directions</td>
</tr>
<tr class="even">
<td><span id="field-rtt.total"></span>
<pre><code>rtt.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The sum of both client and server average round-trip times</td>
</tr>
<tr class="odd">
<td><span id="field-server.common_name"></span>
<pre><code>server.common_name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The Common Name of the server certificate</td>
</tr>
<tr class="even">
<td><span id="field-server.compressed.pdus"></span>
<pre><code>server.compressed.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The number of compressed server PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-server.compressed.pdus.ratio"></span>
<pre><code>server.compressed.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The ratio of compressions to the total number of PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.data"></span>
<pre><code>server.data</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of server data PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-server.datasource.kind"></span>
<pre><code>server.datasource.kind</code></pre></td>
<td><a href="#type-pktsourcekind"></a>
<pre><code>pktsourcekind</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (server-side)</td>
</tr>
<tr class="even">
<td><span id="field-server.datasource.name"></span>
<pre><code>server.datasource.name</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source name on which this traffic has been captured (server-side)</td>
</tr>
<tr class="odd">
<td><span id="field-server.datasource.pair"></span>
<pre><code>server.datasource.pair</code></pre></td>
<td><a href="#type-pktsourcepair"></a>
<pre><code>pktsourcepair</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type and name on which this traffic has been captured (server-side)</td>
</tr>
<tr class="even">
<td><span id="field-server.diffserv"></span>
<pre><code>server.diffserv</code></pre></td>
<td><a href="#type-diffserv"></a>
<pre><code>diffserv</code></pre></td>
<td><pre><code>icmp
other_ip
tcp
udp</code></pre></td>
<td>The server differentiated service</td>
</tr>
<tr class="odd">
<td><span id="field-server.dtt"></span>
<pre><code>server.dtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The average data-transfer time for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.dtt.count"></span>
<pre><code>server.dtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The number of data-transfer times for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.dtt.deviation"></span>
<pre><code>server.dtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The deviation of the data-transfer time for PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.dupacks"></span>
<pre><code>server.dupacks</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of duplicated ACK packets from the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.dupacks.ratio"></span>
<pre><code>server.dupacks.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of duplicated ACKs to the total number of packets emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.emtu"></span>
<pre><code>server.emtu</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp
non_ip
other_ip
tcp
udp</code></pre></td>
<td>The maximum payload in a single ethernet packet emmited by the server in these conversations (this value is assumed to be the MTU of the server's network interface, although the actual MTU value might be greater)</td>
</tr>
<tr class="odd">
<td><span id="field-server.error.ip"></span>
<pre><code>server.error.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The IP address of the server, as it appears in the headers of the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-server.error.port"></span>
<pre><code>server.error.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The port of the server, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-server.error.zone.id"></span>
<pre><code>server.error.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone ID of the server, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-server.error.zone.name"></span>
<pre><code>server.error.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone of the server, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-server.expiration"></span>
<pre><code>server.expiration</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The expiration date of the server certificate</td>
</tr>
<tr class="even">
<td><span id="field-server.file"></span>
<pre><code>server.file</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the Pcap File used as traffic source (server-side)</td>
</tr>
<tr class="odd">
<td><span id="field-server.fins"></span>
<pre><code>server.fins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of FIN packets emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.fins.ratio"></span>
<pre><code>server.fins.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of server FIN packets in a connection</td>
</tr>
<tr class="odd">
<td><span id="field-server.hostname"></span>
<pre><code>server.hostname</code></pre></td>
<td><a href="#type-hostname"></a>
<pre><code>hostname</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The hostname of the server</td>
</tr>
<tr class="even">
<td><span id="field-server.interface"></span>
<pre><code>server.interface</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured (server-side)</td>
</tr>
<tr class="odd">
<td><span id="field-server.ip"></span>
<pre><code>server.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The IP address of the server</td>
</tr>
<tr class="even">
<td><span id="field-server.ja3"></span>
<pre><code>server.ja3</code></pre></td>
<td><a href="#type-tls_fingerprint"></a>
<pre><code>tls_fingerprint</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The JA3 server fingerprint</td>
</tr>
<tr class="odd">
<td><span id="field-server.keepalives"></span>
<pre><code>server.keepalives</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of keep alives from the server</td>
</tr>
<tr class="even">
<td><span id="field-server.key.bits"></span>
<pre><code>server.key.bits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of bits in the server key</td>
</tr>
<tr class="odd">
<td><span id="field-server.key.type"></span>
<pre><code>server.key.type</code></pre></td>
<td><a href="#type-keytype"></a>
<pre><code>keytype</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The type of the server key</td>
</tr>
<tr class="even">
<td><span id="field-server.mac"></span>
<pre><code>server.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The MAC address of the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.meta"></span>
<pre><code>server.meta</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of server metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
</tr>
<tr class="even">
<td><span id="field-server.os"></span>
<pre><code>server.os</code></pre></td>
<td><a href="#type-os"></a>
<pre><code>os</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The server operating system</td>
</tr>
<tr class="odd">
<td><span id="field-server.payload"></span>
<pre><code>server.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes of data (without headers) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.payload.pdus"></span>
<pre><code>server.payload.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) with payload emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.payload.ratio"></span>
<pre><code>server.payload.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The ratio of payload bytes to the entire traffic emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.pdus"></span>
<pre><code>server.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.port"></span>
<pre><code>server.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</code></pre></td>
<td>The TCP/UDP port of the server</td>
</tr>
<tr class="even">
<td><span id="field-server.rd"></span>
<pre><code>server.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average retransmission delay for PDUs emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.rd.count"></span>
<pre><code>server.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of retransmission delays for PDUs emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.rd.deviation"></span>
<pre><code>server.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the retransmission delay for PDUs emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.remote"></span>
<pre><code>server.remote</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured via rpcapd (server-side)</td>
</tr>
<tr class="even">
<td><span id="field-server.retrans.payload"></span>
<pre><code>server.retrans.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.retrans.pdus.ratio"></span>
<pre><code>server.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.retrans.traffic"></span>
<pre><code>server.retrans.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes in retransmitted PDUs emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.retrans.traffic.ratio"></span>
<pre><code>server.retrans.traffic.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmitted traffic to the entire traffic emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.rsts"></span>
<pre><code>server.rsts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of RST packets emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.rsts.ratio"></span>
<pre><code>server.rsts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of server RST packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-server.rt"></span>
<pre><code>server.rt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
smb
tcp
tls</code></pre></td>
<td>The average server response time (SRT)</td>
</tr>
<tr class="odd">
<td><span id="field-server.rt.count"></span>
<pre><code>server.rt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
smb
tcp
tls</code></pre></td>
<td>The number of server response times</td>
</tr>
<tr class="even">
<td><span id="field-server.rt.deviation"></span>
<pre><code>server.rt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
smb
tcp
tls</code></pre></td>
<td>The deviation of the server response time</td>
</tr>
<tr class="odd">
<td><span id="field-server.rtt"></span>
<pre><code>server.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-server.rtt.count"></span>
<pre><code>server.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-server.rtt.deviation"></span>
<pre><code>server.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.last_code"></span>
<pre><code>server.signalization.last_code</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>Last SIP or MGCP response code</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.payload"></span>
<pre><code>server.signalization.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.pdus"></span>
<pre><code>server.signalization.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.rd"></span>
<pre><code>server.signalization.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average retransmission delay for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.rd.count"></span>
<pre><code>server.signalization.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of retransmission delays for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.rd.deviation"></span>
<pre><code>server.signalization.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.retrans.pdus.ratio"></span>
<pre><code>server.signalization.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.rt"></span>
<pre><code>server.signalization.rt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average server response time for signalization PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.rt.count"></span>
<pre><code>server.signalization.rt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of server response times for signalization PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.rt.deviation"></span>
<pre><code>server.signalization.rt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the server response time for signalization PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.rtt"></span>
<pre><code>server.signalization.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.rtt.count"></span>
<pre><code>server.signalization.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="even">
<td><span id="field-server.signalization.rtt.deviation"></span>
<pre><code>server.signalization.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-server.signalization.traffic"></span>
<pre><code>server.signalization.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes in signalization PDUs (protocol data units) emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.signature"></span>
<pre><code>server.signature</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The server signature</td>
</tr>
<tr class="odd">
<td><span id="field-server.traffic"></span>
<pre><code>server.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.vlan"></span>
<pre><code>server.vlan</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the server side of the transaction (alias of server.vlans.inner)</td>
</tr>
<tr class="odd">
<td><span id="field-server.vlans"></span>
<pre><code>server.vlans</code></pre></td>
<td><a href="#type-array"></a>
<pre><code>array</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The VLAN ids on the server side of the transaction. The first VLAN id represents the outer VLAN and the last VLAN id represents the inner VLAN</td>
</tr>
<tr class="even">
<td><span id="field-server.vlans.count"></span>
<pre><code>server.vlans.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The number of VLANs on the server side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-server.vlans.inner"></span>
<pre><code>server.vlans.inner</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the server side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-server.vlans.outer"></span>
<pre><code>server.vlans.outer</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The outer VLAN id on the server side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-server.zero_windows"></span>
<pre><code>server.zero_windows</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of zero-window size packets emitted by the server</td>
</tr>
<tr class="even">
<td><span id="field-server.zero_windows.ratio"></span>
<pre><code>server.zero_windows.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of zero-window size to the total number of packets emitted by the server</td>
</tr>
<tr class="odd">
<td><span id="field-server.zone.id"></span>
<pre><code>server.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone id of the server</td>
</tr>
<tr class="even">
<td><span id="field-server.zone.name"></span>
<pre><code>server.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone of the server</td>
</tr>
<tr class="odd">
<td><span id="field-server_name"></span>
<pre><code>server_name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The Server Name Indication of the conversation</td>
</tr>
<tr class="even">
<td><span id="field-signalization.pdus"></span>
<pre><code>signalization.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-signalization.rd.count"></span>
<pre><code>signalization.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of retransmission delays for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-signalization.rd.deviation"></span>
<pre><code>signalization.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the retransmission delay for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-signalization.rd.total"></span>
<pre><code>signalization.rd.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The sum of both client and server average retransmission delays for signalization PDUs (protocol data units)</td>
</tr>
<tr class="even">
<td><span id="field-signalization.retrans.pdus.ratio"></span>
<pre><code>signalization.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of retransmissions to the total number of signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-signalization.rtt.count"></span>
<pre><code>signalization.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of round-trip times for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="even">
<td><span id="field-signalization.rtt.deviation"></span>
<pre><code>signalization.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-signalization.rtt.total"></span>
<pre><code>signalization.rtt.total</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The sum of both client and server average round-trip times</td>
</tr>
<tr class="even">
<td><span id="field-signalization.traffic"></span>
<pre><code>signalization.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes in signalization PDUs (protocol data units) in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-smb.command"></span>
<pre><code>smb.command</code></pre></td>
<td><a href="#type-smbcommand"></a>
<pre><code>smbcommand</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The SMB command</td>
</tr>
<tr class="even">
<td><span id="field-smb.command.code"></span>
<pre><code>smb.command.code</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The raw SMB command</td>
</tr>
<tr class="odd">
<td><span id="field-smb.sha256"></span>
<pre><code>smb.sha256</code></pre></td>
<td><a href="#type-sha256"></a>
<pre><code>sha256</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The sha256 hash</td>
</tr>
<tr class="even">
<td><span id="field-smb.status"></span>
<pre><code>smb.status</code></pre></td>
<td><a href="#type-smbstatus"></a>
<pre><code>smbstatus</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The SMB status</td>
</tr>
<tr class="odd">
<td><span id="field-smb.subcommand"></span>
<pre><code>smb.subcommand</code></pre></td>
<td><a href="#type-smbsubcommand"></a>
<pre><code>smbsubcommand</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The SMB subcommand</td>
</tr>
<tr class="even">
<td><span id="field-smb.subcommand.code"></span>
<pre><code>smb.subcommand.code</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The raw SMB subcommand</td>
</tr>
<tr class="odd">
<td><span id="field-smb.version"></span>
<pre><code>smb.version</code></pre></td>
<td><a href="#type-smb_version"></a>
<pre><code>smb_version</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The SMB protocol version</td>
</tr>
<tr class="even">
<td><span id="field-software"></span>
<pre><code>software</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The software in the Server header of the HTTP response</td>
</tr>
<tr class="odd">
<td><span id="field-source.common_name"></span>
<pre><code>source.common_name</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The Common Name of the source certificate</td>
</tr>
<tr class="even">
<td><span id="field-source.compressed.pdus"></span>
<pre><code>source.compressed.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The number of compressed source PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-source.compressed.pdus.ratio"></span>
<pre><code>source.compressed.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
<td>The ratio of compressions to the total number of PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.data"></span>
<pre><code>source.data</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of source data PDUs (protocol data units)</td>
</tr>
<tr class="odd">
<td><span id="field-source.datasource.kind"></span>
<pre><code>source.datasource.kind</code></pre></td>
<td><a href="#type-pktsourcekind"></a>
<pre><code>pktsourcekind</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (source-side)</td>
</tr>
<tr class="even">
<td><span id="field-source.datasource.name"></span>
<pre><code>source.datasource.name</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source name on which this traffic has been captured (source-side)</td>
</tr>
<tr class="odd">
<td><span id="field-source.datasource.pair"></span>
<pre><code>source.datasource.pair</code></pre></td>
<td><a href="#type-pktsourcepair"></a>
<pre><code>pktsourcepair</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The packet source type and name on which this traffic has been captured (source-side)</td>
</tr>
<tr class="even">
<td><span id="field-source.diffserv"></span>
<pre><code>source.diffserv</code></pre></td>
<td><a href="#type-diffserv"></a>
<pre><code>diffserv</code></pre></td>
<td><pre><code>icmp
other_ip
tcp
udp</code></pre></td>
<td>The source differentiated service</td>
</tr>
<tr class="odd">
<td><span id="field-source.dtt"></span>
<pre><code>source.dtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The average data-transfer time for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.dtt.count"></span>
<pre><code>source.dtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The number of data-transfer times for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.dtt.deviation"></span>
<pre><code>source.dtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls</code></pre></td>
<td>The deviation of the data-transfer time for PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.dupacks"></span>
<pre><code>source.dupacks</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of duplicated ACK packets from the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.dupacks.ratio"></span>
<pre><code>source.dupacks.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of duplicated ACKs to the total number of packets emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.emtu"></span>
<pre><code>source.emtu</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>icmp
non_ip
other_ip
tcp
udp</code></pre></td>
<td>The maximum payload in a single ethernet packet emmited by the source in these conversations (this value is assumed to be the MTU of the source's network interface, although the actual MTU value might be greater)</td>
</tr>
<tr class="odd">
<td><span id="field-source.error.ip"></span>
<pre><code>source.error.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The IP address of the source, as it appears in the headers of the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-source.error.port"></span>
<pre><code>source.error.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The port of the source, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-source.error.zone.id"></span>
<pre><code>source.error.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone ID of the source, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="even">
<td><span id="field-source.error.zone.name"></span>
<pre><code>source.error.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>icmp</code></pre></td>
<td>The zone of the source, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
</tr>
<tr class="odd">
<td><span id="field-source.expiration"></span>
<pre><code>source.expiration</code></pre></td>
<td><a href="#type-time"></a>
<pre><code>time</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The expiration date of the source certificate</td>
</tr>
<tr class="even">
<td><span id="field-source.file"></span>
<pre><code>source.file</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the Pcap File used as traffic source (source-side)</td>
</tr>
<tr class="odd">
<td><span id="field-source.fins"></span>
<pre><code>source.fins</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of FIN packets emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.fins.ratio"></span>
<pre><code>source.fins.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of source FIN packets in a connection</td>
</tr>
<tr class="odd">
<td><span id="field-source.hostname"></span>
<pre><code>source.hostname</code></pre></td>
<td><a href="#type-hostname"></a>
<pre><code>hostname</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The hostname of the source</td>
</tr>
<tr class="even">
<td><span id="field-source.interface"></span>
<pre><code>source.interface</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured (source-side)</td>
</tr>
<tr class="odd">
<td><span id="field-source.ip"></span>
<pre><code>source.ip</code></pre></td>
<td><a href="#type-ip"></a>
<pre><code>ip</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The IP address of the source</td>
</tr>
<tr class="even">
<td><span id="field-source.ja3"></span>
<pre><code>source.ja3</code></pre></td>
<td><a href="#type-tls_fingerprint"></a>
<pre><code>tls_fingerprint</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The JA3 source fingerprint</td>
</tr>
<tr class="odd">
<td><span id="field-source.keepalives"></span>
<pre><code>source.keepalives</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of keep alives from the source</td>
</tr>
<tr class="even">
<td><span id="field-source.key.bits"></span>
<pre><code>source.key.bits</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The number of bits in the source key</td>
</tr>
<tr class="odd">
<td><span id="field-source.key.type"></span>
<pre><code>source.key.type</code></pre></td>
<td><a href="#type-keytype"></a>
<pre><code>keytype</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The type of the source key</td>
</tr>
<tr class="even">
<td><span id="field-source.mac"></span>
<pre><code>source.mac</code></pre></td>
<td><a href="#type-mac"></a>
<pre><code>mac</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The MAC address of the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.meta"></span>
<pre><code>source.meta</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The total number of source metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
</tr>
<tr class="even">
<td><span id="field-source.os"></span>
<pre><code>source.os</code></pre></td>
<td><a href="#type-os"></a>
<pre><code>os</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The source operating system</td>
</tr>
<tr class="odd">
<td><span id="field-source.payload"></span>
<pre><code>source.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes of data (without headers) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.payload.pdus"></span>
<pre><code>source.payload.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) with payload emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.payload.ratio"></span>
<pre><code>source.payload.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
tcp
tls
udp
voip</code></pre></td>
<td>The ratio of payload bytes to the entire traffic emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.pdus"></span>
<pre><code>source.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</code></pre></td>
<td>The total number of PDUs (protocol data units) at applicative level emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.port"></span>
<pre><code>source.port</code></pre></td>
<td><a href="#type-port"></a>
<pre><code>port</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</code></pre></td>
<td>The TCP/UDP port of the source</td>
</tr>
<tr class="even">
<td><span id="field-source.rd"></span>
<pre><code>source.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average retransmission delay for PDUs emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.rd.count"></span>
<pre><code>source.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of retransmission delays for PDUs emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.rd.deviation"></span>
<pre><code>source.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the retransmission delay for PDUs emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.remote"></span>
<pre><code>source.remote</code></pre></td>
<td><a href="#type-pktsourcename"></a>
<pre><code>pktsourcename</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The name of the network interface on which this traffic has been captured via rpcapd (source-side)</td>
</tr>
<tr class="even">
<td><span id="field-source.retrans.payload"></span>
<pre><code>source.retrans.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.retrans.pdus.ratio"></span>
<pre><code>source.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.retrans.traffic"></span>
<pre><code>source.retrans.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total amount of bytes in retransmitted PDUs emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.retrans.traffic.ratio"></span>
<pre><code>source.retrans.traffic.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of retransmitted traffic to the entire traffic emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.rsts"></span>
<pre><code>source.rsts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of RST packets emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.rsts.ratio"></span>
<pre><code>source.rsts.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of source RST packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-source.rtt"></span>
<pre><code>source.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average round-trip time for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-source.rtt.count"></span>
<pre><code>source.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of round-trip times for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-source.rtt.deviation"></span>
<pre><code>source.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The deviation of the round-trip time for PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-source.signalization.payload"></span>
<pre><code>source.signalization.payload</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.signalization.pdus"></span>
<pre><code>source.signalization.pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total number of signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.signalization.rd"></span>
<pre><code>source.signalization.rd</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average retransmission delay for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.signalization.rd.count"></span>
<pre><code>source.signalization.rd.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of retransmission delays for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.signalization.rd.deviation"></span>
<pre><code>source.signalization.rd.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.signalization.retrans.pdus.ratio"></span>
<pre><code>source.signalization.retrans.pdus.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.signalization.rtt"></span>
<pre><code>source.signalization.rtt</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The average round-trip time for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-source.signalization.rtt.count"></span>
<pre><code>source.signalization.rtt.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The number of round-trip times for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="odd">
<td><span id="field-source.signalization.rtt.deviation"></span>
<pre><code>source.signalization.rtt.deviation</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the destination</td>
</tr>
<tr class="even">
<td><span id="field-source.signalization.traffic"></span>
<pre><code>source.signalization.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>The total amount of bytes in signalization PDUs (protocol data units) emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.signature"></span>
<pre><code>source.signature</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The source signature</td>
</tr>
<tr class="even">
<td><span id="field-source.traffic"></span>
<pre><code>source.traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.vlan"></span>
<pre><code>source.vlan</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the source side of the transaction (alias of source.vlans.inner)</td>
</tr>
<tr class="even">
<td><span id="field-source.vlans"></span>
<pre><code>source.vlans</code></pre></td>
<td><a href="#type-array"></a>
<pre><code>array</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The VLAN ids on the source side of the transaction. The first VLAN id represents the outer VLAN and the last VLAN id represents the inner VLAN</td>
</tr>
<tr class="odd">
<td><span id="field-source.vlans.count"></span>
<pre><code>source.vlans.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The number of VLANs on the source side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-source.vlans.inner"></span>
<pre><code>source.vlans.inner</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The inner VLAN id on the source side of the transaction</td>
</tr>
<tr class="odd">
<td><span id="field-source.vlans.outer"></span>
<pre><code>source.vlans.outer</code></pre></td>
<td><a href="#type-vlan"></a>
<pre><code>vlan</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The outer VLAN id on the source side of the transaction</td>
</tr>
<tr class="even">
<td><span id="field-source.zero_windows"></span>
<pre><code>source.zero_windows</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of zero-window size packets emitted by the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.zero_windows.ratio"></span>
<pre><code>source.zero_windows.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of zero-window size to the total number of packets emitted by the source</td>
</tr>
<tr class="even">
<td><span id="field-source.zone.id"></span>
<pre><code>source.zone.id</code></pre></td>
<td><a href="#type-zone_id"></a>
<pre><code>zone_id</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone id of the source</td>
</tr>
<tr class="odd">
<td><span id="field-source.zone.name"></span>
<pre><code>source.zone.name</code></pre></td>
<td><a href="#type-zone"></a>
<pre><code>zone</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>The zone of the source</td>
</tr>
<tr class="even">
<td><span id="field-successes"></span>
<pre><code>successes</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
databases
dns
smb
voip</code></pre></td>
<td>The number of successes</td>
</tr>
<tr class="odd">
<td><span id="field-successes.ratio"></span>
<pre><code>successes.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix
databases
dns
smb
voip</code></pre></td>
<td>The ratio of successes</td>
</tr>
<tr class="even">
<td><span id="field-syns"></span>
<pre><code>syns</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of SYN packets emitted by the client</td>
</tr>
<tr class="odd">
<td><span id="field-syns.ratio"></span>
<pre><code>syns.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The average number of SYN packets in a connection</td>
</tr>
<tr class="even">
<td><span id="field-system"></span>
<pre><code>system</code></pre></td>
<td><a href="#type-databasesystem"></a>
<pre><code>databasesystem</code></pre></td>
<td><pre><code>databases</code></pre></td>
<td>The database system</td>
</tr>
<tr class="odd">
<td><span id="field-tcp_pdus"></span>
<pre><code>tcp_pdus</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The number of TCP packets that form up the HTTP queries and responses</td>
</tr>
<tr class="even">
<td><span id="field-time_exclusion.any"></span>
<pre><code>time_exclusion.any</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>Was there any time exclusion?</td>
</tr>
<tr class="odd">
<td><span id="field-time_exclusion.business_hours"></span>
<pre><code>time_exclusion.business_hours</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>Was there a business hours time exclusion?</td>
</tr>
<tr class="even">
<td><span id="field-time_exclusion.maintenance_windows"></span>
<pre><code>time_exclusion.maintenance_windows</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>citrix
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
voip</code></pre></td>
<td>Was there a maintenance windows time exclusion?</td>
</tr>
<tr class="odd">
<td><span id="field-timeouts"></span>
<pre><code>timeouts</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>citrix</code></pre></td>
<td>The number of flows that timeouted</td>
</tr>
<tr class="even">
<td><span id="field-tls.version"></span>
<pre><code>tls.version</code></pre></td>
<td><a href="#type-tls_version"></a>
<pre><code>tls_version</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The TLS protocol version</td>
</tr>
<tr class="odd">
<td><span id="field-tls.version.is_weak"></span>
<pre><code>tls.version.is_weak</code></pre></td>
<td><a href="#type-bool"></a>
<pre><code>bool</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>Is the TLS protocol version weak?</td>
</tr>
<tr class="even">
<td><span id="field-tls.version.major"></span>
<pre><code>tls.version.major</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The TLS protocol major version</td>
</tr>
<tr class="odd">
<td><span id="field-tls.version.minor"></span>
<pre><code>tls.version.minor</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tls</code></pre></td>
<td>The TLS protocol minor version</td>
</tr>
<tr class="even">
<td><span id="field-traffic"></span>
<pre><code>traffic</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>dns
http
icmp
non_ip
other_ip
tcp
tls
udp
voip</code></pre></td>
<td>The total amount of bytes in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-tree"></span>
<pre><code>tree</code></pre></td>
<td><a href="#type-path"></a>
<pre><code>path</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The tree this CIFS command relates to</td>
</tr>
<tr class="even">
<td><span id="field-tree.id"></span>
<pre><code>tree.id</code></pre></td>
<td><a href="#type-descriptor"></a>
<pre><code>descriptor</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The id of the tree this CIFS command relates to</td>
</tr>
<tr class="odd">
<td><span id="field-unclosed"></span>
<pre><code>unclosed</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The number of TCP sessions that didn't properly end</td>
</tr>
<tr class="even">
<td><span id="field-url"></span>
<pre><code>url</code></pre></td>
<td><a href="#type-url"></a>
<pre><code>url</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The path, query and fragment parts of the URL</td>
</tr>
<tr class="odd">
<td><span id="field-url.base"></span>
<pre><code>url.base</code></pre></td>
<td><a href="#type-url"></a>
<pre><code>url</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The URL without the query string and fragment</td>
</tr>
<tr class="even">
<td><span id="field-url.path"></span>
<pre><code>url.path</code></pre></td>
<td><a href="#type-path"></a>
<pre><code>path</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The URL path</td>
</tr>
<tr class="odd">
<td><span id="field-user"></span>
<pre><code>user</code></pre></td>
<td><a href="#type-string"></a>
<pre><code>string</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
smb</code></pre></td>
<td>The user</td>
</tr>
<tr class="even">
<td><span id="field-user.experience"></span>
<pre><code>user.experience</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The end-user experience (sum of RTTs, DTTs and SRT)</td>
</tr>
<tr class="odd">
<td><span id="field-user_agent"></span>
<pre><code>user_agent</code></pre></td>
<td><a href="#type-useragent"></a>
<pre><code>useragent</code></pre></td>
<td><pre><code>http</code></pre></td>
<td>The user-agent</td>
</tr>
<tr class="even">
<td><span id="field-uuid"></span>
<pre><code>uuid</code></pre></td>
<td><a href="#type-uuid"></a>
<pre><code>uuid</code></pre></td>
<td><pre><code>citrix
citrix_channels
databases
dns
http
smb
tcp
tls
voip</code></pre></td>
<td>The unique identifier of this TCP session</td>
</tr>
<tr class="odd">
<td><span id="field-voice.count"></span>
<pre><code>voice.count</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>voip</code></pre></td>
<td>Number of packets where we had voice in the conversation</td>
</tr>
<tr class="even">
<td><span id="field-warnings"></span>
<pre><code>warnings</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The number of warnings (mainly client-side)</td>
</tr>
<tr class="odd">
<td><span id="field-warnings.ratio"></span>
<pre><code>warnings.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>smb</code></pre></td>
<td>The ratio of warnings to the total number of SMB queries</td>
</tr>
<tr class="even">
<td><span id="field-zero_windows"></span>
<pre><code>zero_windows</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The total number of zero-window size packets in both directions</td>
</tr>
<tr class="odd">
<td><span id="field-zero_windows.ratio"></span>
<pre><code>zero_windows.ratio</code></pre></td>
<td><a href="#type-number"></a>
<pre><code>number</code></pre></td>
<td><pre><code>tcp</code></pre></td>
<td>The ratio of zero-window size to the total number of packets in both directions</td>
</tr>
</tbody>
</table>

## Types

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th>Type Name</th>
<th>JSON Type</th>
<th>Available Values</th>
<th>Custom Values Allowed</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre><code>alerttypes</code></pre></td>
<td><pre><code>array&lt;str&gt;</code></pre></td>
<td><a href="#alerttypes-items">items</a></td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>application</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>application_id</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>array</code></pre></td>
<td><pre><code>array&lt;int&gt;</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>bool</code></pre></td>
<td><pre><code>bool</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>calldirection</code></pre></td>
<td><pre><code>int|null</code></pre></td>
<td><a href="#calldirection-items">items</a></td>
<td>No</td>
</tr>
<tr class="odd">
<td><pre><code>callstate</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#callstate-items">items</a></td>
<td>No</td>
</tr>
<tr class="even">
<td><pre><code>channel</code></pre></td>
<td><pre><code>int|null</code></pre></td>
<td><a href="#channel-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>ciphersuite</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#ciphersuite-items">items</a></td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>databasecommand</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#databasecommand-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>databasequery</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>databasesystem</code></pre></td>
<td><pre><code>str</code></pre></td>
<td><a href="#databasesystem-items">items</a></td>
<td>No</td>
</tr>
<tr class="odd">
<td><pre><code>dcerpc</code></pre></td>
<td><pre><code>str</code></pre></td>
<td><a href="#dcerpc-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>descriptor</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>diffserv</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>dnsclass</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#dnsclass-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>dnscode</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#dnscode-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>dnstype</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#dnstype-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>encryption</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#encryption-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>ethernetprotocol</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#ethernetprotocol-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>hostname</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>httpquerymethod</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#httpquerymethod-items">items</a></td>
<td>No</td>
</tr>
<tr class="odd">
<td><pre><code>httpstatus</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#httpstatus-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>httpstatuscategory</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#httpstatuscategory-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>icmpmessage</code></pre></td>
<td><pre><code>tuple&lt;int, int&gt;</code></pre></td>
<td><a href="#icmpmessage-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>icmptype</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#icmptype-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>ip</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>ipfamily</code></pre></td>
<td><pre><code>int|null</code></pre></td>
<td><a href="#ipfamily-items">items</a></td>
<td>No</td>
</tr>
<tr class="odd">
<td><pre><code>ipprotocol</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#ipprotocol-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>keytype</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#keytype-items">items</a></td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>layer</code></pre></td>
<td><pre><code>str</code></pre></td>
<td><a href="#layer-items">items</a></td>
<td>No</td>
</tr>
<tr class="even">
<td><pre><code>mac</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>mimetype</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>number</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>os</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#os-items">items</a></td>
<td>No</td>
</tr>
<tr class="even">
<td><pre><code>path</code></pre></td>
<td><pre><code>str|null</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>pktsourcekind</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#pktsourcekind-items">items</a></td>
<td>No</td>
</tr>
<tr class="even">
<td><pre><code>pktsourcename</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>pktsourcepair</code></pre></td>
<td><pre><code>tuple&lt;int, str&gt;</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>poller</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>poller_id</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>port</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>protostack</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>sha256</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>smb_version</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>smbcommand</code></pre></td>
<td><pre><code>tuple&lt;int, int&gt;</code></pre></td>
<td><a href="#smbcommand-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>smbstatus</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#smbstatus-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="even">
<td><pre><code>smbsubcommand</code></pre></td>
<td><pre><code>tuple&lt;int, int, int&gt;</code></pre></td>
<td><a href="#smbsubcommand-items">items</a></td>
<td>Yes</td>
</tr>
<tr class="odd">
<td><pre><code>storage</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>string</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>time</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>tls_fingerprint</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>tls_version</code></pre></td>
<td><pre><code>int</code></pre></td>
<td><a href="#tls_version-items">items</a></td>
<td>No</td>
</tr>
<tr class="even">
<td><pre><code>url</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>useragent</code></pre></td>
<td><pre><code>str|null</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>uuid</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>vlan</code></pre></td>
<td><pre><code>int|null</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="even">
<td><pre><code>zone</code></pre></td>
<td><pre><code>str</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
<tr class="odd">
<td><pre><code>zone_id</code></pre></td>
<td><pre><code>int</code></pre></td>
<td>-</td>
<td>-</td>
</tr>
</tbody>
</table>

## Values

### Type [alerttypes](#type-alerttypes)

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Close Notify</code></pre></td>
<td><pre><code>0</code></pre></td>
<td>This message notifies the recipient that the sender will not send any more messages on this connection.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unexpected Message</code></pre></td>
<td><pre><code>1</code></pre></td>
<td>An inappropriate message was received.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bad MAC Record</code></pre></td>
<td><pre><code>2</code></pre></td>
<td>This alert is returned if a record is received with an incorrect MAC.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Decryption Failed</code></pre></td>
<td><pre><code>3</code></pre></td>
<td>This alert was used in some earlier versions of TLS, and may have permitted certain attacks against the CBC mode.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Record Overflow</code></pre></td>
<td><pre><code>4</code></pre></td>
<td>A TLSCiphertext record was received that had a length more than 2^14+2048 bytes, or a record decrypted to a TLSCompressed record with more than 2^14+1024 bytes.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Decompression Failure</code></pre></td>
<td><pre><code>5</code></pre></td>
<td>The decompression function received improper input (e.g., data that would expand to excessive length).</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Handshake Failure</code></pre></td>
<td><pre><code>6</code></pre></td>
<td>Reception of a handshake failure alert message indicates that the sender was unable to negotiate an acceptable set of security parameters given the options available.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>No Certificate</code></pre></td>
<td><pre><code>7</code></pre></td>
<td>This alert was used in SSLv3 but not any version of TLS.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bad Certificate</code></pre></td>
<td><pre><code>8</code></pre></td>
<td>A certificate was corrupt, contained signatures that did not verify correctly, etc.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unsupported Certificate</code></pre></td>
<td><pre><code>9</code></pre></td>
<td>A certificate was of an unsupported type.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Certificate Revoked</code></pre></td>
<td><pre><code>10</code></pre></td>
<td>A certificate was revoked by its signer.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Certificate Expired</code></pre></td>
<td><pre><code>11</code></pre></td>
<td>A certificate has expired or is not currently valid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Certificate Unknown</code></pre></td>
<td><pre><code>12</code></pre></td>
<td>Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Illegal Parameter</code></pre></td>
<td><pre><code>13</code></pre></td>
<td>A field in the handshake was out of range or inconsistent with other fields.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Unknown CA</code></pre></td>
<td><pre><code>14</code></pre></td>
<td>A valid certificate chain or partial chain was received, but the certificate was not accepted because the CA certificate could not be located or couldn't be matched with a known, trusted CA.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Access Denied</code></pre></td>
<td><pre><code>15</code></pre></td>
<td>A valid certificate was received, but when access control was applied, the sender decided not to proceed with negotiation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Decode Error</code></pre></td>
<td><pre><code>16</code></pre></td>
<td>A message could not be decoded because some field was out of the specified range or the length of the message was incorrect.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Decrypt Error</code></pre></td>
<td><pre><code>17</code></pre></td>
<td>A handshake cryptographic operation failed, including being unable to correctly verify a signature or validate a Finished message.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Export Restriction</code></pre></td>
<td><pre><code>18</code></pre></td>
<td>This alert was used in some earlier versions of TLS.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Protocol Version</code></pre></td>
<td><pre><code>19</code></pre></td>
<td>The protocol version the client has attempted to negotiate is recognized but not supported.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Insufficient Security</code></pre></td>
<td><pre><code>20</code></pre></td>
<td>Returned instead of a handshake failure when a negotiation has failed specifically because the server requires ciphers more secure than those supported by the client.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Internal Error</code></pre></td>
<td><pre><code>21</code></pre></td>
<td>An internal error unrelated to the peer or the correctness of the protocol (such as a memory allocation failure) makes it impossible to continue.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>User Cancelled</code></pre></td>
<td><pre><code>22</code></pre></td>
<td>This handshake is being canceled for some reason unrelated to a protocol failure.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>No Renegotiation</code></pre></td>
<td><pre><code>23</code></pre></td>
<td>Sent by the client in response to a hello request or by the server in response to a client hello after initial handshaking.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Unsupported Extension</code></pre></td>
<td><pre><code>24</code></pre></td>
<td>Sent by clients that receive an extended server hello containing an extension that they did not put in the corresponding client hello.</td>
</tr>
</tbody>
</table>

### Type [calldirection](#type-calldirection)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Unknown</code></pre></td>
<td><pre><code>None</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Inbound</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Outbound</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
</tbody>
</table>

### Type [callstate](#type-callstate)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>In ring</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Hang down</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Dial</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Out ring</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Voice</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Hang up</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Closed</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
</tbody>
</table>

### Type [channel](#type-channel)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Category</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXSCRN</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>0 - 0x0</code></pre></td>
<td>CTXSCRN</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXLPT1</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>1 - 0x1</code></pre></td>
<td>CTXLPT1: Printer mapping for non-spooling client (Thin client devices) - vdcpm30N.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXLPT2</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>2 - 0x2</code></pre></td>
<td>CTXLPT2: Printer mapping for non-spooling client (Thin client devices) - vdcpm30N.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXSBR</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>3 - 0x3</code></pre></td>
<td>CTXSBR: Browser acceleration - vdtw30n.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXCPM</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>4 - 0x4</code></pre></td>
<td>CTXCPM: Printer mapping for client spooler - vdcpm30N.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCOM1</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>5 - 0x5</code></pre></td>
<td>CTXCOM1: Printer mapping for non-spooling client (Thin client devices) - vdcom30N.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXCOM2</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>6 - 0x6</code></pre></td>
<td>CTXCOM2: Printer mapping for non-spooling client (Thin client devices) - vdcom30N.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCCM</code></pre></td>
<td>Peripherals forwarding (like USB)</td>
<td><pre><code>7 - 0x7</code></pre></td>
<td>CTXCCM: Client COM port mapping - vdcom30N.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXTW</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>8 - 0x8</code></pre></td>
<td>CTXTW: Remote Windows screen update (ThinWire) - vdtw30n.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCDM</code></pre></td>
<td>Peripherals forwarding (like USB)</td>
<td><pre><code>9 - 0x9</code></pre></td>
<td>CTXCDM: Client drive mapping - vdcdm30n.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SHADOW</code></pre></td>
<td>Unknown</td>
<td><pre><code>10 - 0xA</code></pre></td>
<td>SHADOW</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXOEM</code></pre></td>
<td>Implementation and usage defined by O.E.M.</td>
<td><pre><code>11 - 0xB</code></pre></td>
<td>CTXOEM: Used by Original Equipment Manufacturers</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXOEM2</code></pre></td>
<td>Implementation and usage defined by O.E.M.</td>
<td><pre><code>12 - 0xC</code></pre></td>
<td>CTXOEM2: Used by Original Equipment Manufacturers</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCLIP</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>13 - 0xD</code></pre></td>
<td>CTXCLIP: Client clipboard - vdclipn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXCAM</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>14 - 0xE</code></pre></td>
<td>CTXCAM: Client audio mapping - vdcamN.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXDRTP</code></pre></td>
<td>Unknown</td>
<td><pre><code>15 - 0xF</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXTWI</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>16 - 0x10</code></pre></td>
<td>CTXTWI: Seamless Windows screen update data (ThinWire)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXZLFK</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>17 - 0x11</code></pre></td>
<td>CTXZLFK: Local Text Echo and Keyboard Feedback / Screen latency reduction (fonts) - vdzlcn.dll, vdfon30n.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXTUI</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>18 - 0x12</code></pre></td>
<td>Transparent User Interface</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCTL</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>19 - 0x13</code></pre></td>
<td>CTXCTL: Citrix control virtual channel - vdctln.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXSCRD</code></pre></td>
<td>Authentication related</td>
<td><pre><code>20 - 0x14</code></pre></td>
<td>CTXSCRD: Smartcard - vdscardn.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXEUEM</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>21 - 0x15</code></pre></td>
<td>CTXEUEM: End user experience monitoring - vdeuemn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXLIC</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>22 - 0x16</code></pre></td>
<td>CTXLIC: License management - wfica32.exe</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXMM</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>23 - 0x17</code></pre></td>
<td>CTXMM: Windows Multimedia redirection - vdmmn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXSSPI</code></pre></td>
<td>Authentication related</td>
<td><pre><code>24 - 0x18</code></pre></td>
<td>CTXSSPI: Kerberos</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXTWN</code></pre></td>
<td>Printer and scanner management</td>
<td><pre><code>25 - 0x19</code></pre></td>
<td>CTXTWN: TWAIN redirection - vdtwn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CITRIXD</code></pre></td>
<td>Unknown</td>
<td><pre><code>26 - 0x1A</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PNPREDI</code></pre></td>
<td>Unknown</td>
<td><pre><code>27 - 0x1B</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXSENS</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>28 - 0x1C</code></pre></td>
<td>Location and sensor</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXMTCH</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>29 - 0x1D</code></pre></td>
<td>CTXMTCH: Multitouch</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXLFP</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>30 - 0x1E</code></pre></td>
<td>CTXLFP: Framehawk Display channel over UDP-like transport</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXGUSB</code></pre></td>
<td>Peripherals forwarding (like USB)</td>
<td><pre><code>31 - 0x1F</code></pre></td>
<td>CTXGUSB: USB redirection - vdgusbn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXFLSH</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>32 - 0x20</code></pre></td>
<td>CTXFLSH: Flash redirection - vdflash.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXFLS2</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>33 - 0x21</code></pre></td>
<td>CTXFLS2</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXD3D</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>34 - 0x22</code></pre></td>
<td>CTXD3D: Direct3D virtual channel adapter - vd3dn.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXPN</code></pre></td>
<td>Unknown</td>
<td><pre><code>35 - 0x23</code></pre></td>
<td>CTXPN: Program Neighborhood - vdpnn.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXZLC</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>36 - 0x24</code></pre></td>
<td>CTXZLC: Screen latency reduction (screen) - vdzlcn.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXSPMK</code></pre></td>
<td>Unknown</td>
<td><pre><code>37 - 0x25</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CARANOC</code></pre></td>
<td>Unknown</td>
<td><pre><code>38 - 0x26</code></pre></td>
<td>CARANOC</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AURTCX</code></pre></td>
<td>Unknown</td>
<td><pre><code>39 - 0x27</code></pre></td>
<td>AURTCX</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IMP1166</code></pre></td>
<td>Unknown</td>
<td><pre><code>40 - 0x28</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SPECIAL_THINWIRE</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>41 - 0x29</code></pre></td>
<td>SPECIAL_THINWIRE</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ESCAPE</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>42 - 0x2A</code></pre></td>
<td>ESCAPE</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BASE</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>43 - 0x2B</code></pre></td>
<td>BASE</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXVFM</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>44 - 0x2C</code></pre></td>
<td>CTXVFM: Video server (not ThinWire, deprecated)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXCM</code></pre></td>
<td>Core Citrix channels (updates, licensing, configuration, ...)</td>
<td><pre><code>45 - 0x2D</code></pre></td>
<td>CTXCM: Client management (auto client update) - vdcmN.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CTXPASS</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>46 - 0x2E</code></pre></td>
<td>CTXPASS: Transparent key pass-through - vdkbhook.dll</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXTW1</code></pre></td>
<td>Audio and video management</td>
<td><pre><code>47 - 0x2F</code></pre></td>
<td>CTXTW1: Seamless Windows screen update (ThinWire) - vdtwin.dll</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSPXSBE</code></pre></td>
<td>Unknown</td>
<td><pre><code>48 - 0x30</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MHA_VC</code></pre></td>
<td>Unknown</td>
<td><pre><code>49 - 0x31</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>EVDSSO</code></pre></td>
<td>Unknown</td>
<td><pre><code>50 - 0x32</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CTXMOB</code></pre></td>
<td>Unknown</td>
<td><pre><code>51 - 0x33</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSPCTRL</code></pre></td>
<td>Unknown</td>
<td><pre><code>52 - 0x34</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSPMIX</code></pre></td>
<td>Unknown</td>
<td><pre><code>53 - 0x35</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSPSBEX</code></pre></td>
<td>Unknown</td>
<td><pre><code>54 - 0x36</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSPXMIX</code></pre></td>
<td>Unknown</td>
<td><pre><code>55 - 0x37</code></pre></td>
<td></td>
</tr>
</tbody>
</table>

### Type [ciphersuite](#type-ciphersuite)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>null with null null</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with null MD5</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with null SHA</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA export with RC4 40 MD5</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with RC4 128 MD5</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with RC4 128 SHA</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA export with RC2 CBC 40 MD5</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with IDEA CBC SHA</code></pre></td>
<td><pre><code>7 - 0x7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA export with DES40 CBC SHA</code></pre></td>
<td><pre><code>8 - 0x8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with DES CBC SHA</code></pre></td>
<td><pre><code>9 - 0x9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>10 - 0xA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS export with DES40 CBC SHA</code></pre></td>
<td><pre><code>11 - 0xB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with DES CBC SHA</code></pre></td>
<td><pre><code>12 - 0xC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>13 - 0xD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA export with DES40 CBC SHA</code></pre></td>
<td><pre><code>14 - 0xE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with DES CBC SHA</code></pre></td>
<td><pre><code>15 - 0xF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>16 - 0x10</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS export with DES40 CBC SHA</code></pre></td>
<td><pre><code>17 - 0x11</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with DES CBC SHA</code></pre></td>
<td><pre><code>18 - 0x12</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>19 - 0x13</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA export with DES40 CBC SHA</code></pre></td>
<td><pre><code>20 - 0x14</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with DES CBC SHA</code></pre></td>
<td><pre><code>21 - 0x15</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>22 - 0x16</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon export with RC4 40 MD5</code></pre></td>
<td><pre><code>23 - 0x17</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with RC4 128 MD5</code></pre></td>
<td><pre><code>24 - 0x18</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon export with DES40 CBC SHA</code></pre></td>
<td><pre><code>25 - 0x19</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with DES CBC SHA</code></pre></td>
<td><pre><code>26 - 0x1A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>27 - 0x1B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 with DES CBC SHA</code></pre></td>
<td><pre><code>30 - 0x1E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>31 - 0x1F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 with RC4 128 SHA</code></pre></td>
<td><pre><code>32 - 0x20</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 with IDEA CBC SHA</code></pre></td>
<td><pre><code>33 - 0x21</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 with DES CBC MD5</code></pre></td>
<td><pre><code>34 - 0x22</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 with 3DES EDE CBC MD5</code></pre></td>
<td><pre><code>35 - 0x23</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 with RC4 128 MD5</code></pre></td>
<td><pre><code>36 - 0x24</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 with IDEA CBC MD5</code></pre></td>
<td><pre><code>37 - 0x25</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with DES CBC 40 SHA</code></pre></td>
<td><pre><code>38 - 0x26</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with RC2 CBC 40 SHA</code></pre></td>
<td><pre><code>39 - 0x27</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with RC4 40 SHA</code></pre></td>
<td><pre><code>40 - 0x28</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with DES CBC 40 MD5</code></pre></td>
<td><pre><code>41 - 0x29</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with RC2 CBC 40 MD5</code></pre></td>
<td><pre><code>42 - 0x2A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KRB5 export with RC4 40 MD5</code></pre></td>
<td><pre><code>43 - 0x2B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with null SHA</code></pre></td>
<td><pre><code>44 - 0x2C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with null SHA</code></pre></td>
<td><pre><code>45 - 0x2D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with null SHA</code></pre></td>
<td><pre><code>46 - 0x2E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>47 - 0x2F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 128 CBC SHA</code></pre></td>
<td><pre><code>48 - 0x30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49 - 0x31</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 128 CBC SHA</code></pre></td>
<td><pre><code>50 - 0x32</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>51 - 0x33</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 128 CBC SHA</code></pre></td>
<td><pre><code>52 - 0x34</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>53 - 0x35</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 256 CBC SHA</code></pre></td>
<td><pre><code>54 - 0x36</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>55 - 0x37</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 256 CBC SHA</code></pre></td>
<td><pre><code>56 - 0x38</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>57 - 0x39</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 256 CBC SHA</code></pre></td>
<td><pre><code>58 - 0x3A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with null SHA256</code></pre></td>
<td><pre><code>59 - 0x3B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>60 - 0x3C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>61 - 0x3D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>62 - 0x3E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>63 - 0x3F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>64 - 0x40</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>65 - 0x41</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>66 - 0x42</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>67 - 0x43</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>68 - 0x44</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>69 - 0x45</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 128 CBC SHA</code></pre></td>
<td><pre><code>70 - 0x46</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with DES CBC SHA</code></pre></td>
<td><pre><code>73 - 0x49</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA export1024 with RC4 56 MD5</code></pre></td>
<td><pre><code>96 - 0x60</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA export1024 with RC2 CBC 56 MD5</code></pre></td>
<td><pre><code>97 - 0x61</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA export1024 with DES CBC SHA</code></pre></td>
<td><pre><code>98 - 0x62</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS export1024 with DES CBC SHA</code></pre></td>
<td><pre><code>99 - 0x63</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA export1024 with RC4 56 SHA</code></pre></td>
<td><pre><code>100 - 0x64</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS export1024 with RC4 56 SHA</code></pre></td>
<td><pre><code>101 - 0x65</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with RC4 128 SHA</code></pre></td>
<td><pre><code>102 - 0x66</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>103 - 0x67</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>104 - 0x68</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>105 - 0x69</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>106 - 0x6A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>107 - 0x6B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>108 - 0x6C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 256 CBC SHA256</code></pre></td>
<td><pre><code>109 - 0x6D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>GOSTR341094 with 28147 CNT IMIT</code></pre></td>
<td><pre><code>128 - 0x80</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>GOSTR341001 with 28147 CNT IMIT</code></pre></td>
<td><pre><code>129 - 0x81</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>GOSTR341094 with null GOSTR3411</code></pre></td>
<td><pre><code>130 - 0x82</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>GOSTR341001 with null GOSTR3411</code></pre></td>
<td><pre><code>131 - 0x83</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>132 - 0x84</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>133 - 0x85</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>134 - 0x86</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>135 - 0x87</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>136 - 0x88</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 256 CBC SHA</code></pre></td>
<td><pre><code>137 - 0x89</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with RC4 128 SHA</code></pre></td>
<td><pre><code>138 - 0x8A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>139 - 0x8B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 128 CBC SHA</code></pre></td>
<td><pre><code>140 - 0x8C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 256 CBC SHA</code></pre></td>
<td><pre><code>141 - 0x8D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with RC4 128 SHA</code></pre></td>
<td><pre><code>142 - 0x8E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>143 - 0x8F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 128 CBC SHA</code></pre></td>
<td><pre><code>144 - 0x90</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 256 CBC SHA</code></pre></td>
<td><pre><code>145 - 0x91</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with RC4 128 SHA</code></pre></td>
<td><pre><code>146 - 0x92</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>147 - 0x93</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 128 CBC SHA</code></pre></td>
<td><pre><code>148 - 0x94</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 256 CBC SHA</code></pre></td>
<td><pre><code>149 - 0x95</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with seed CBC SHA</code></pre></td>
<td><pre><code>150 - 0x96</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with seed CBC SHA</code></pre></td>
<td><pre><code>151 - 0x97</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with seed CBC SHA</code></pre></td>
<td><pre><code>152 - 0x98</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with seed CBC SHA</code></pre></td>
<td><pre><code>153 - 0x99</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with seed CBC SHA</code></pre></td>
<td><pre><code>154 - 0x9A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with seed CBC SHA</code></pre></td>
<td><pre><code>155 - 0x9B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>156 - 0x9C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>157 - 0x9D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>158 - 0x9E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>159 - 0x9F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>160 - 0xA0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>161 - 0xA1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>162 - 0xA2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>163 - 0xA3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>164 - 0xA4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>165 - 0xA5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>166 - 0xA6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>167 - 0xA7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>168 - 0xA8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>169 - 0xA9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>170 - 0xAA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>171 - 0xAB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>172 - 0xAC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>173 - 0xAD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>174 - 0xAE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>175 - 0xAF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with null SHA256</code></pre></td>
<td><pre><code>176 - 0xB0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with null SHA384</code></pre></td>
<td><pre><code>177 - 0xB1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>178 - 0xB2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>179 - 0xB3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with null SHA256</code></pre></td>
<td><pre><code>180 - 0xB4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with null SHA384</code></pre></td>
<td><pre><code>181 - 0xB5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>182 - 0xB6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>183 - 0xB7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with null SHA256</code></pre></td>
<td><pre><code>184 - 0xB8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with null SHA384</code></pre></td>
<td><pre><code>185 - 0xB9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>186 - 0xBA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>187 - 0xBB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>188 - 0xBC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>189 - 0xBD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>190 - 0xBE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>191 - 0xBF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>192 - 0xC0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>193 - 0xC1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>194 - 0xC2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>195 - 0xC3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>196 - 0xC4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 256 CBC SHA256</code></pre></td>
<td><pre><code>197 - 0xC5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>empty renegotiation info SCSV</code></pre></td>
<td><pre><code>255 - 0xFF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AES 128 GCM SHA256</code></pre></td>
<td><pre><code>4865 - 0x1301</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AES 256 GCM SHA384</code></pre></td>
<td><pre><code>4866 - 0x1302</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>4867 - 0x1303</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AES 128 CCM SHA256</code></pre></td>
<td><pre><code>4868 - 0x1304</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AES 128 CCM 8 SHA256</code></pre></td>
<td><pre><code>4869 - 0x1305</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>fallback SCSV</code></pre></td>
<td><pre><code>22016 - 0x5600</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with null SHA</code></pre></td>
<td><pre><code>49153 - 0xC001</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with RC4 128 SHA</code></pre></td>
<td><pre><code>49154 - 0xC002</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49155 - 0xC003</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49156 - 0xC004</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49157 - 0xC005</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with null SHA</code></pre></td>
<td><pre><code>49158 - 0xC006</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with RC4 128 SHA</code></pre></td>
<td><pre><code>49159 - 0xC007</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49160 - 0xC008</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49161 - 0xC009</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49162 - 0xC00A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with null SHA</code></pre></td>
<td><pre><code>49163 - 0xC00B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with RC4 128 SHA</code></pre></td>
<td><pre><code>49164 - 0xC00C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49165 - 0xC00D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49166 - 0xC00E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49167 - 0xC00F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with null SHA</code></pre></td>
<td><pre><code>49168 - 0xC010</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with RC4 128 SHA</code></pre></td>
<td><pre><code>49169 - 0xC011</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49170 - 0xC012</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49171 - 0xC013</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49172 - 0xC014</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH anon with null SHA</code></pre></td>
<td><pre><code>49173 - 0xC015</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH anon with RC4 128 SHA</code></pre></td>
<td><pre><code>49174 - 0xC016</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH anon with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49175 - 0xC017</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH anon with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49176 - 0xC018</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH anon with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49177 - 0xC019</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SRP SHA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49178 - 0xC01A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SRP SHA RSA with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49179 - 0xC01B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SRP SHA DSS with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49180 - 0xC01C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SRP SHA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49181 - 0xC01D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SRP SHA RSA with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49182 - 0xC01E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SRP SHA DSS with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49183 - 0xC01F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SRP SHA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49184 - 0xC020</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SRP SHA RSA with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49185 - 0xC021</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SRP SHA DSS with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49186 - 0xC022</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>49187 - 0xC023</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>49188 - 0xC024</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>49189 - 0xC025</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>49190 - 0xC026</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>49191 - 0xC027</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>49192 - 0xC028</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>49193 - 0xC029</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>49194 - 0xC02A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>49195 - 0xC02B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>49196 - 0xC02C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>49197 - 0xC02D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>49198 - 0xC02E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>49199 - 0xC02F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>49200 - 0xC030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>49201 - 0xC031</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>49202 - 0xC032</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with RC4 128 SHA</code></pre></td>
<td><pre><code>49203 - 0xC033</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with 3DES EDE CBC SHA</code></pre></td>
<td><pre><code>49204 - 0xC034</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 128 CBC SHA</code></pre></td>
<td><pre><code>49205 - 0xC035</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 256 CBC SHA</code></pre></td>
<td><pre><code>49206 - 0xC036</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 128 CBC SHA256</code></pre></td>
<td><pre><code>49207 - 0xC037</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 256 CBC SHA384</code></pre></td>
<td><pre><code>49208 - 0xC038</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with null SHA</code></pre></td>
<td><pre><code>49209 - 0xC039</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with null SHA256</code></pre></td>
<td><pre><code>49210 - 0xC03A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with null SHA384</code></pre></td>
<td><pre><code>49211 - 0xC03B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49212 - 0xC03C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49213 - 0xC03D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49214 - 0xC03E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49215 - 0xC03F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49216 - 0xC040</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49217 - 0xC041</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49218 - 0xC042</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49219 - 0xC043</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49220 - 0xC044</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49221 - 0xC045</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49222 - 0xC046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49223 - 0xC047</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49224 - 0xC048</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49225 - 0xC049</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49226 - 0xC04A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49227 - 0xC04B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49228 - 0xC04C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49229 - 0xC04D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49230 - 0xC04E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49231 - 0xC04F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49232 - 0xC050</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49233 - 0xC051</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49234 - 0xC052</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49235 - 0xC053</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49236 - 0xC054</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49237 - 0xC055</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49238 - 0xC056</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49239 - 0xC057</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49240 - 0xC058</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49241 - 0xC059</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49242 - 0xC05A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49243 - 0xC05B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49244 - 0xC05C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49245 - 0xC05D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49246 - 0xC05E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49247 - 0xC05F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49248 - 0xC060</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49249 - 0xC061</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49250 - 0xC062</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49251 - 0xC063</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49252 - 0xC064</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49253 - 0xC065</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49254 - 0xC066</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49255 - 0xC067</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49256 - 0xC068</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49257 - 0xC069</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49258 - 0xC06A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49259 - 0xC06B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49260 - 0xC06C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49261 - 0xC06D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with ARIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49262 - 0xC06E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with ARIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49263 - 0xC06F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with ARIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49264 - 0xC070</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with ARIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49265 - 0xC071</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49266 - 0xC072</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49267 - 0xC073</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49268 - 0xC074</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49269 - 0xC075</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49270 - 0xC076</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49271 - 0xC077</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49272 - 0xC078</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49273 - 0xC079</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49274 - 0xC07A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49275 - 0xC07B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49276 - 0xC07C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49277 - 0xC07D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49278 - 0xC07E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH RSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49279 - 0xC07F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49280 - 0xC080</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE DSS with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49281 - 0xC081</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49282 - 0xC082</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH DSS with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49283 - 0xC083</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49284 - 0xC084</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DH anon with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49285 - 0xC085</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49286 - 0xC086</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49287 - 0xC087</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49288 - 0xC088</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH ECDSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49289 - 0xC089</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49290 - 0xC08A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49291 - 0xC08B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49292 - 0xC08C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDH RSA with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49293 - 0xC08D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49294 - 0xC08E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49295 - 0xC08F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49296 - 0xC090</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49297 - 0xC091</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with CAMELLIA 128 GCM SHA256</code></pre></td>
<td><pre><code>49298 - 0xC092</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with CAMELLIA 256 GCM SHA384</code></pre></td>
<td><pre><code>49299 - 0xC093</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49300 - 0xC094</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49301 - 0xC095</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49302 - 0xC096</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49303 - 0xC097</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49304 - 0xC098</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49305 - 0xC099</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with CAMELLIA 128 CBC SHA256</code></pre></td>
<td><pre><code>49306 - 0xC09A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with CAMELLIA 256 CBC SHA384</code></pre></td>
<td><pre><code>49307 - 0xC09B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 128 CCM</code></pre></td>
<td><pre><code>49308 - 0xC09C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 256 CCM</code></pre></td>
<td><pre><code>49309 - 0xC09D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 128 CCM</code></pre></td>
<td><pre><code>49310 - 0xC09E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 256 CCM</code></pre></td>
<td><pre><code>49311 - 0xC09F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 128 CCM 8</code></pre></td>
<td><pre><code>49312 - 0xC0A0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with AES 256 CCM 8</code></pre></td>
<td><pre><code>49313 - 0xC0A1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 128 CCM 8</code></pre></td>
<td><pre><code>49314 - 0xC0A2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with AES 256 CCM 8</code></pre></td>
<td><pre><code>49315 - 0xC0A3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 128 CCM</code></pre></td>
<td><pre><code>49316 - 0xC0A4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 256 CCM</code></pre></td>
<td><pre><code>49317 - 0xC0A5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 128 CCM</code></pre></td>
<td><pre><code>49318 - 0xC0A6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with AES 256 CCM</code></pre></td>
<td><pre><code>49319 - 0xC0A7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 128 CCM 8</code></pre></td>
<td><pre><code>49320 - 0xC0A8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with AES 256 CCM 8</code></pre></td>
<td><pre><code>49321 - 0xC0A9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK DHE with AES 128 CCM 8</code></pre></td>
<td><pre><code>49322 - 0xC0AA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK DHE with AES 256 CCM 8</code></pre></td>
<td><pre><code>49323 - 0xC0AB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 128 CCM</code></pre></td>
<td><pre><code>49324 - 0xC0AC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 256 CCM</code></pre></td>
<td><pre><code>49325 - 0xC0AD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 128 CCM 8</code></pre></td>
<td><pre><code>49326 - 0xC0AE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with AES 256 CCM 8</code></pre></td>
<td><pre><code>49327 - 0xC0AF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECJPAKE with AES 128 CCM 8</code></pre></td>
<td><pre><code>49407 - 0xC0FF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52392 - 0xCCA8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52393 - 0xCCA9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52394 - 0xCCAA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52395 - 0xCCAB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52396 - 0xCCAC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52397 - 0xCCAD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with CHACHA20 POLY1305 SHA256</code></pre></td>
<td><pre><code>52398 - 0xCCAE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 128 GCM SHA256</code></pre></td>
<td><pre><code>53249 - 0xD001</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 256 GCM SHA384</code></pre></td>
<td><pre><code>53250 - 0xD002</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 128 CCM 8 SHA256</code></pre></td>
<td><pre><code>53251 - 0xD003</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with AES 128 CCM SHA256</code></pre></td>
<td><pre><code>53253 - 0xD005</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58384 - 0xE410</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA with SALSA20 SHA1</code></pre></td>
<td><pre><code>58385 - 0xE411</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58386 - 0xE412</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE RSA with SALSA20 SHA1</code></pre></td>
<td><pre><code>58387 - 0xE413</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58388 - 0xE414</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE ECDSA with SALSA20 SHA1</code></pre></td>
<td><pre><code>58389 - 0xE415</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PSK with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58390 - 0xE416</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PSK with SALSA20 SHA1</code></pre></td>
<td><pre><code>58391 - 0xE417</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58392 - 0xE418</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECDHE PSK with SALSA20 SHA1</code></pre></td>
<td><pre><code>58393 - 0xE419</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58394 - 0xE41A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RSA PSK with SALSA20 SHA1</code></pre></td>
<td><pre><code>58395 - 0xE41B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58396 - 0xE41C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE PSK with SALSA20 SHA1</code></pre></td>
<td><pre><code>58397 - 0xE41D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with ESTREAM SALSA20 SHA1</code></pre></td>
<td><pre><code>58398 - 0xE41E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHE RSA with SALSA20 SHA1</code></pre></td>
<td><pre><code>58399 - 0xE41F</code></pre></td>
</tr>
</tbody>
</table>

### Type [databasecommand](#type-databasecommand)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SELECT</code></pre></td>
<td><pre><code>256 - 0x100</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>INSERT</code></pre></td>
<td><pre><code>512 - 0x200</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>UPDATE</code></pre></td>
<td><pre><code>768 - 0x300</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DELETE</code></pre></td>
<td><pre><code>1024 - 0x400</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CREATE</code></pre></td>
<td><pre><code>1280 - 0x500</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CREATE TABLE</code></pre></td>
<td><pre><code>1281 - 0x501</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CREATE INDEX</code></pre></td>
<td><pre><code>1282 - 0x502</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CREATE VIEW</code></pre></td>
<td><pre><code>1283 - 0x503</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DROP</code></pre></td>
<td><pre><code>1536 - 0x600</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DROP TABLE</code></pre></td>
<td><pre><code>1537 - 0x601</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DROP INDEX</code></pre></td>
<td><pre><code>1538 - 0x602</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DROP VIEW</code></pre></td>
<td><pre><code>1539 - 0x603</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ALTER</code></pre></td>
<td><pre><code>1792 - 0x700</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ALTER TABLE</code></pre></td>
<td><pre><code>1793 - 0x701</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PREPARE</code></pre></td>
<td><pre><code>2048 - 0x800</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EXECUTE</code></pre></td>
<td><pre><code>2304 - 0x900</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BEGIN</code></pre></td>
<td><pre><code>61440 - 0xF000</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>COMMIT</code></pre></td>
<td><pre><code>61696 - 0xF100</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ROLLBACK</code></pre></td>
<td><pre><code>61952 - 0xF200</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>FETCH</code></pre></td>
<td><pre><code>62208 - 0xF300</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CLOSE</code></pre></td>
<td><pre><code>62464 - 0xF400</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EMPTY</code></pre></td>
<td><pre><code>62720 - 0xF500</code></pre></td>
</tr>
</tbody>
</table>

### Type [databasesystem](#type-databasesystem)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DB2 (DRDA)</code></pre></td>
<td><pre><code>DRDA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MongoDB</code></pre></td>
<td><pre><code>MongoDB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MySQL / MariaDB</code></pre></td>
<td><pre><code>MySQL</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PostgreSQL</code></pre></td>
<td><pre><code>PostgreSQL</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft SQL Server / Sybase</code></pre></td>
<td><pre><code>TDS(msg)</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Oracle</code></pre></td>
<td><pre><code>TNS</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IBM Informix</code></pre></td>
<td><pre><code>Informix</code></pre></td>
</tr>
</tbody>
</table>

### Type [dcerpc](#type-dcerpc)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Category</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IUnknown Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000000-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IClassFactory Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000001-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IBindCtx Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>0000000e-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IEnumUnknown Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000100-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IPersist Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>0000010c-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IDataObject Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>0000010e-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IID_IRemUnknown Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000131-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - ILocalSystemActivator Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000132-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IRunDown Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000134-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IInterfaceFromWindowProp Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000135-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - ISCMActivator Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000136-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IDLLHost Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000141-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IID_IRemUnknown2 Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>00000143-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - ISystemActivator Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>000001a0-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - IDispatch Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020400-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - ITypeInfo Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020401-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - ITypeLib Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020402-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - ITypeComp Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020403-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - IEnumVARIANT Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020404-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - ITypeLib2 Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020411-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Automation Protocol - ITypeInfo2 Interface</code></pre></td>
<td>MS OLE Automation</td>
<td><pre><code>00020412-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IShellView Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>000214e3-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IShellFolder Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>000214e6-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - ICommDlgBrowser Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>000214f1-0000-0000-c000-000000000046</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdate4 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>004c6a2b-0c19-4c69-9f5c-a269b2560db9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDiskMgr CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>0144084b-e09e-4f45-a56b-dcdc9f379f5e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHostMgr3 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>01454b97-c6a5-4685-bea8-9779c88ab990</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQOutgoingQueueManagement</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>0188401c-247a-4fed-99c6-bf14119d7055</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQCollection Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>0188ac2f-ecb3-4173-9779-635ca2039c72</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostPropertyCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>0191775e-bcff-445a-b4f4-3bdda54e2816</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Shadow Copy Management Protocol - IVssEnumMgmtObject interface</code></pre></td>
<td>MS Volume Shadow Copy</td>
<td><pre><code>01954e6b-9254-4e6e-808c-c9e05d007696</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IEnumWbemClassObject Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>027947e1-d731-11ce-a357-000000000001</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsRemovable Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>0316560b-5db4-4ed9-bbb5-213436ddc0d9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostElementSchemaCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>0344cdda-151e-4cbf-82da-66ae61e97754</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Telnet Server Remote Administration Protocol (MS-TSRAP) - IID_IManageTelnetSessions Interface</code></pre></td>
<td>MS Telnet Server</td>
<td><pre><code>034634fd-ba3f-11d1-856a-00a0c944138c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>038374ff-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IDataCollectorCollection Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837502-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IPerformanceCounterDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837506-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - ITraceDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>0383750b-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - ITraceDataProviderCollection Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837510-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - ITraceDataProvider Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837512-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IConfigurationDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837514-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IAlertDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837516-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IApiTracingDataCollector Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>0383751a-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IDataCollectorSet Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837520-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IDataCollectorSetCollection Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837524-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IValueMapItem Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837533-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IValueMap Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837534-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - Ischedule Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>0383753a-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IScheduleCollection Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>0383753d-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IDataManager Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837541-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IFolderAction Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837543-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Logs and Alerts Protocol - IFolderActionCollection Interface</code></pre></td>
<td>MS Perf Logs &amp; Alerts</td>
<td><pre><code>03837544-098b-11d8-9414-505054503030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Universal Plug and Play (UPNP) - IUPnPHttpHeaderControl Interface</code></pre></td>
<td>MS UPNP</td>
<td><pre><code>0405af4f-8b5c-447c-80f2-b75984a31f3c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - ISearchRoot Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>04c18ccf-1f57-4cbd-88cc-3900f5195ce3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSearcher3 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>04c6895d-eaf2-4034-97f3-311de9be413a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterSetup Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>04d55210-b6ac-4248-9e69-2a569d1d2ab6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Server - Gopher Publishing Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>04fcb220-fcfd-11cd-bec8-00aa0047ae4e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Security Center</code></pre></td>
<td>MS Security</td>
<td><pre><code>06bba54a-be05-49f9-b0a0-30f790261023</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IWMPContentProviderFactory Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>06e333e4-667e-466d-9e34-4a8d5e36e012</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - System Attendant Service - Version 1.0</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>06ed1d30-d3d3-11cd-b80e-00aa004b9c30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Data Services (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactory2 Interface</code></pre></td>
<td>MS Remote Data Services</td>
<td><pre><code>070669eb-b52f-11d1-9270-00c04fbbbfb3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConstantValue Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>0716caf8-7d05-4a46-8099-77594be91394</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Program Compatibility Assistant Service - PcaSvc Interface</code></pre></td>
<td>MS Misc Services</td>
<td><pre><code>0767a036-0d22-48aa-ba69-b619480f38cb</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileManagementJob Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>0770687e-9f36-4d6f-8778-599d188461c9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDisk Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>07e5c822-f00c-47a1-8fce-b244da56fd06</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>07f7438c-7709-4ca5-b518-91279288134e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsService Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>0818a8ef-9ba9-40d8-a6f9-e22833cc771e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - IMessenger Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>081e7188-c080-4ff3-9238-29f66d6cabfd</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostChildElementCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>08a90f5f-0702-48d6-b45f-02a9885a9768</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostChangeHandler Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>09829352-87c2-418d-8d79-4133969a489d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Scheduler Service - idletask operations</code></pre></td>
<td>MS Scheduler</td>
<td><pre><code>0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceHba Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>0ac13689-3134-47c6-a17c-4669216801be</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Portmapper Service - localepmp Interface</code></pre></td>
<td>MS Portmapper</td>
<td><pre><code>0b0a6584-9e0f-11cf-a3cf-00805f68cb1b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Authorization API Protocol (MS-RAA) - authzr Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Print System Asynchronous Notification Protocol (MS-PAN) - IRPCAsyncNotify Interface</code></pre></td>
<td>MS Print</td>
<td><pre><code>0b6edbfa-4a24-4fc6-8a23-942b1eca65d1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateServiceManager2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>0bb8531d-7e8d-424f-986c-a0b8f60a3e7b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdateEntryCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>0d521700-a372-4bef-828b-3d00c10adebd</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Cryptographic Services - ICertProtect</code></pre></td>
<td>MS Crypto</td>
<td><pre><code>0d72a7d4-6148-11d1-b4aa-00c04fb66ea0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostSectionGroup Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>0dd8a158-ebe6-4008-a1d9-b7ecc8f1104b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTableRead Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>0e3d6630-b46b-11d1-9d2d-006008b0e5ca</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTableWrite Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>0e3d6631-b46b-11d1-9d2d-006008b0e5ca</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Information Store - exchange_store_information Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Data Services (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactory Interface</code></pre></td>
<td>MS Remote Data Services</td>
<td><pre><code>0eac4842-8763-11cf-a743-00aa00a3f00d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Transaction Coordinator (DTC) - ITransaction Interface</code></pre></td>
<td>MS DTC</td>
<td><pre><code>0fb15084-af41-11ce-bd2b-204c4f4f5020</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumLMMountPoint Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>100da538-3f4a-45ab-b852-709148152789</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - ICommDlgBrowser2 Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>10339516-2894-11d2-9039-00c04f8eeb3e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Queue Manager to Queue Manager Protocol - qm2qm Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>1088a980-eae5-11d0-8d9b-00a02453c337</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsProviderInterface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>10c5e575-7984-4e81-a56b-431f5f92ae42</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SoftICE DriverStudio Remote Control - winice.dat</code></pre></td>
<td>SI DriverStudio RC</td>
<td><pre><code>10d1800c-af75-4249-b7a2-484dec69ed3a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Information Store - Function I</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>10f24e8e-0fa6-11d2-a910-00c04f990f3b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Protected Storage Service</code></pre></td>
<td>MS Storage</td>
<td><pre><code>11220835-5b26-4d94-ae86-c3e475a809de</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Trusted Platform Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardManager Interface</code></pre></td>
<td>MS TPM Smart Card Mgt</td>
<td><pre><code>112b1dff-d9dc-41f7-869f-d67fee7cb591</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdate3 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>112eda6b-95b3-476f-9d90-aee82c6b8181</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IEnumVdsObject Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>118610b7-8d94-4030-b5b8-500889788e4e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - LSM Notification Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>11899a43-2b68-4a76-92e3-a3d6ad8c26ce</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterStorage3 Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>11942d87-a1de-4e7f-83fb-a840d9c5928d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - LSMAPI - TermSrvPrivate Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>11f25515-c879-400a-989e-b074d5f092fe</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterStorage2 Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>12108a88-6858-4467-b92f-e6cf4568dfb6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Print System Remote Protocol (MS-RPRN) - Winspool Interface or IPSec Policy Agent Endpoint</code></pre></td>
<td>MS Indeterminate</td>
<td><pre><code>12345678-1234-abcd-ef00-0123456789ab</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Netlogon Remote Protocol (MS-NRPC) - Netlogon Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>12345678-1234-abcd-ef00-01234567cffb</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Local Security Authority Remote Protocol - lsarpc Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>12345778-1234-abcd-ef00-0123456789ab</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Security Account Manager (SAMR) - samr Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>12345778-1234-abcd-ef00-0123456789ac</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - SessEnvPublicRpc Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>1257b580-ce2f-4109-82d6-a9459d0bf6bc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmActionCommand Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>12937789-e247-4917-9c20-f3ee9c7ee783</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft PSFactoryBuffer Interface</code></pre></td>
<td>MS Svchost</td>
<td><pre><code>1299cf18-c4f5-4b6a-bb0f-2299f0398e27</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQApplication2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>12a30900-7300-11d2-b0e6-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Secondary Logon Service</code></pre></td>
<td>MS Security</td>
<td><pre><code>12b81e99-f207-4a4c-85d3-77b42f76fd14</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Secure Desktop LRPC interface</code></pre></td>
<td>MS Secure Desktop</td>
<td><pre><code>12e65dd8-887f-41ef-91bf-8d816c42c2e7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Intersite Messaging Service - ismserv_ip</code></pre></td>
<td>MS Intersite Messaging</td>
<td><pre><code>130ceefb-e466-11d1-b78b-00c04fa32883</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IVolumeClient3 Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>135698d2-3a37-4d26-99df-e2bb6ae3ac61</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumWTDiskLunMapping Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>1396de6f-a794-4b11-b93f-6b69a5b47bae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsPack2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>13b50bff-290a-47dd-8558-b7c58db1a71a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdate2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>144fe9b0-d23d-4a8b-8634-fb4457533b7a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Information Store - Function II</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>1453c42c-0fa6-11d2-a910-00c04f990f3b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft ExtendedError Remote Data Structure (MS-EERR) - ExtendedError Interface</code></pre></td>
<td>MS EERR</td>
<td><pre><code>14a8831c-bc82-11d2-8a64-0008c7457e5d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceIscsi Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>14fbe036-3ed7-4e10-90e9-a5ff991aff01</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateService2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>1518b460-6518-4172-940f-c75883b24ceb</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange Directory Referral (Request For Response - RFR) - exchange_ds_rfr Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>1544f5e0-613c-11d1-93df-00c04fd7bd09</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaBase Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>1568a795-3924-4118-b74b-68d8f0fa5daf</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmStorageModuleDefinition Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>15a81350-497d-4aba-80e9-d4dbcc5521fe</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceSw Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>15fc031c-0652-4306-b2c3-f558b8f837e2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Active Directory Backup and Restore Services - JetRest Interface</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>16e0cf3a-a604-11d0-96b1-00a0c91ece30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Messenger Service Remote Protocol - msgsvc operations for name management methods</code></pre></td>
<td>MS Messenger</td>
<td><pre><code>17fdd703-1827-4e34-79d4-24a55c53bb37</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDisk3 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>1822a95e-1c2b-4d02-ab25-cc116dd9dbde</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogSession Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>182c40fa-32e4-11d0-818b-00a0c9231c29</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>18f70770-8e64-11cf-9af1-0020af6e72f4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumPortal Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>1995785d-2a1e-492f-8923-e621eaca39d9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Database Service</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>1a190310-bb9c-11cd-90f8-00aa00466520</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Trusted Platform Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardManagerStatusCallback Interface</code></pre></td>
<td>MS TPM Smart Card Mgt</td>
<td><pre><code>1a1bb35f-abb8-451c-a1ae-33d98f1bef4a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Security and Acceleration (ISA) - Management Console</code></pre></td>
<td>MS ISA</td>
<td><pre><code>1a77dcb2-97b3-4ffb-9ee7-8f42529841ab</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Queue Manager Remote Read Protocol - RemoteRead Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>1a9134dd-7b39-45ba-ad88-44d01ca47f28</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Deployment Services Control Protocol (MS-WDSC) - WdsRpcInterface Interface</code></pre></td>
<td>MS Deployment Services</td>
<td><pre><code>1a927394-352e-4553-ae3f-7cf4aafca620</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>1aa7f844-c7f5-11d0-a376-00c04fc9da04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IFolderView2 Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>1af3a467-214f-4298-908e-06b03e0b39f9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISnsMgr Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>1b1c4d1c-abc4-4d3a-8c22-547fba3aa8a0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmMutableCollection Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>1bb617b8-3886-49dc-af82-a6c90fa35dda</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumeOnline Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>1be2275a-b315-4f70-9e44-879b3a2a53f2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - WBEM providers - IWbemProviderInitSink Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>1be41571-91dd-11d1-aeb2-00c04fb68820</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - WBEM providers - IWbemProviderInit Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>1be41572-91dd-11d1-aeb2-00c04fb68820</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - POP3 - Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>1be617c0-31a5-11cf-a7d8-00805f48a135</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemFetchSmartEnum Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>1c1c45ee-4395-11d2-b60b-00104b703efd</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Active Directory DSROLE Service</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>1cbcad78-df0b-4934-b558-87839ea501c9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalog64BitSupport Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>1d118904-94b3-4a64-9fa6-ed432666a7b9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Debugging Helper Service</code></pre></td>
<td>MS Debugging</td>
<td><pre><code>1d55b526-c137-46c5-ab79-638f2a68e869</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVDisk Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>1e062b84-e5e6-4b4b-8a25-67b81e8f13e8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - LSMAPI - TermSrvAdmin Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>1e665584-40fe-4450-8f6e-802362399694</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IImport2 Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>1f7b1697-ecb2-4cbb-8a0e-75c427f4a6f0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Task Scheduler Service Remote Protocol - ATSvc</code></pre></td>
<td>MS Scheduler</td>
<td><pre><code>1ff70682-0a51-30e8-076d-740be8cee98b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - AppInfo Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>201ef99a-7fa0-444c-9399-19ba84f12a1a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenTemplate Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>205bebf8-dd93-452a-95a6-32b566b35828</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service (RRAS) Management Protocol - rasrpc Interface</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>20610036-fa22-11cf-9823-00a0c911e5df</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft DFS Replication Helper Protocol - IServerHealthReport2 Interface</code></pre></td>
<td>MS DFS Replication</td>
<td><pre><code>20d15747-6c48-4254-a358-65039fd8c63c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Shadow Copy Management Protocol - IVssDifferentialSoftwareSnapshotMgmt Interface</code></pre></td>
<td>MS Volume Shadow Copy</td>
<td><pre><code>214a0f28-b737-4026-b847-4f9e37d79529</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMConfig Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>21546ae8-4da5-445e-987f-627fea39c5e8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Unified Background Process Manager - ubpmtaskhostchannel Interface</code></pre></td>
<td>MS UBPM</td>
<td><pre><code>22716894-fd8e-4462-9783-09e6d9531f16</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - AppHostAdminManager</code></pre></td>
<td>MS IIS</td>
<td><pre><code>228fb8f7-fb53-4fd5-8c7b-ff59de606c5b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmObject Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>22bcef93-4a3f-4183-89f9-2f8b8a628aee</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Profile Service - INotifyNetworkEvents Interface</code></pre></td>
<td>MS Network Profile</td>
<td><pre><code>22d2e146-1a68-40b8-949c-8fd848b415e6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateServiceManager Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>23857e3c-02ba-44a3-9423-b1c900805f37</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Tracker Service Protocol - IProcessDump Interface</code></pre></td>
<td>MS COM+ Tracker</td>
<td><pre><code>23c9dd26-2355-4fe2-84de-f779a238adbd</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMAP4 Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>2465e9e0-a873-11d0-930b-00a0c90ab17c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISnsMgr CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>24f9c1a9-b22e-4e24-bec9-4af0a4d96736</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Trend Micro ServerProtect</code></pre></td>
<td>TM SRVPROTECT</td>
<td><pre><code>25288888-bd5b-11d1-9d53-0080c83a5c2c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Profile Service - IEnumNetwork Interface</code></pre></td>
<td>MS Network Profile</td>
<td><pre><code>26656eaa-54eb-4e6f-8f85-4f0ef901a406</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmReportManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>27b899fe-6ffa-4481-a184-d3daade8a02b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdate4 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>27e94b0d-5139-49a2-9a61-93522dc54652</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IDirectoryEnum Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>28bc8d5e-ca4b-4f54-973c-ed9622d2b3ac</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterNetwork2 Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>2931c32c-f731-4c56-9feb-3d5f1c5e72bf</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IWamAdmin Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>29822ab7-f302-11d0-9953-00c04fd919c1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IWamAdmin2 Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>29822ab8-f302-11d0-9953-00c04fd919c1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Profile Service - INetworkInterface Interface</code></pre></td>
<td>MS Network Profile</td>
<td><pre><code>2a1c9eb2-df62-4154-b800-63278fcb8037</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IResourceManager2 Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>2a3eb639-d134-422d-90d8-aaa1b5216202</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Profile Service - INotifyNetworkInterfaceEvents Interface</code></pre></td>
<td>MS Network Profile</td>
<td><pre><code>2abc0864-9677-42e5-882a-d415c556c284</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsHbaPort Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>2abd757f-2851-4997-9a13-47d2a885d6ca</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - AppHostWritableAdminManager</code></pre></td>
<td>MS IIS</td>
<td><pre><code>2b72133b-3f5b-4602-8952-803546ce3344</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Transaction Coordinator (DTC) - WinRM Interface</code></pre></td>
<td>MS DTC</td>
<td><pre><code>2b7ee790-e8c8-4820-97db-cdff70129887</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemRefreshingServices Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>2c9273e0-1dc3-11d3-b364-00105a1f8177</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransaction2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>2ce0c5b0-6e67-11d2-b0e6-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostMethodSchema Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>2d9915fb-9d42-4328-b782-1b46819fab9e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmActionReport Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>2dbe63c4-b340-48a0-a5b0-158e07fc567e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Group Policy Client Service - IGroupPolicyUtilities Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>2eb08e3e-639f-4fba-97b1-14f878961076</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdatesSettings Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>2ee48f22-af3c-405f-8970-f71be12ee9a2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Licensing - LCRPC Operations</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>2f59a331-bf7d-48cb-9ec5-7c090d76e8b8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Dynamic Data Exchange Service - nddeapi</code></pre></td>
<td>MS Network DDE</td>
<td><pre><code>2f5f3220-c126-1076-b549-074d078619da</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Telephony Remote Protocol - tapsrv Interface</code></pre></td>
<td>MS Telephony</td>
<td><pre><code>2f5f6520-ca46-1067-b319-00dd010662da</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Telephony Remote Protocol - remotesp Interface</code></pre></td>
<td>MS Telephony</td>
<td><pre><code>2f5f6521-ca47-1068-b319-00dd010662db</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Unimodem LRPC Endpoint</code></pre></td>
<td>MS Telephony</td>
<td><pre><code>2f5f6521-cb55-1059-b446-00df0bce31db</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Firewall - FwRpc Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>2fb92682-6599-42dc-ae13-bd2ca89bd11c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Link Tracking - Workstation Protocol</code></pre></td>
<td>MS DLT</td>
<td><pre><code>300f3532-38cc-11d0-a3f0-0020af6b0add</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Name Resolution Proxy (NRP) RPC interface - NRP Server Endpoint - NameResolutionProxy Interface</code></pre></td>
<td>MS Name Resolution Proxy</td>
<td><pre><code>30adc50c-5cbc-46ce-9a0e-91914789e23c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IStatusNotify Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>312cc019-d5cd-4ca7-8c10-9e0a661f147e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostMappingExtension Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>31a83ea0-c0e4-4a2c-8a01-353cc2a4c60a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft WinLogon - Profile Mapper</code></pre></td>
<td>MS Security</td>
<td><pre><code>326731e3-c1c0-4a69-ae20-7d9044a4ea5c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPropertyCondition Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>326af66f-2ac0-4f68-bf8c-4759f054fa29</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SoftICE DriverStudio Remote Control</code></pre></td>
<td>SI DriverStudio RC</td>
<td><pre><code>32d90706-b698-4029-b236-e18ebff582b1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Unified Background Process Manager - ubpmrpc Interface</code></pre></td>
<td>MS UBPM</td>
<td><pre><code>33511f95-5b84-4dcc-b6cc-3f4b21da53e1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Registry Protocol / Microsoft Remote Shutdown Protocol - WinReg Interface</code></pre></td>
<td>MS Remote Services</td>
<td><pre><code>338cd001-2244-31f1-aaaa-900038001003</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQQueueManagement</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>33b6d07e-f27d-42fa-b2d7-bf82e11e9374</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Offline Files Provider - IOfflineFilesEventsFilter Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>33fc4e1b-0716-40fa-ba65-6e62a84a846f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Licensing Logging Service - llsrpc Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>342cfd40-3c6c-11ce-a893-08002b2e9c6d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumIDMethod Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>345b026b-5802-4e38-ac75-795e08b0b83f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft WinHttp Auto-Proxy Service</code></pre></td>
<td>MS WinHttp Auto-Proxy</td>
<td><pre><code>3473dd4d-2e88-4006-9cba-22570909dd10</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDisk2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>348a0821-69bb-4889-a101-6a9bde6fa720</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IExplorerBrowserEvents Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>361bbdc7-e6ee-4e13-be58-58e2240c810f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Service Control Manager Remote Protocol (MS-SCMR) - svcctl Interface</code></pre></td>
<td>MS SCM</td>
<td><pre><code>367abb81-9844-35f1-ad32-98f038001003</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft WinLogin - Profile Mapper</code></pre></td>
<td>MS Security</td>
<td><pre><code>369ce4f0-0fdc-11d3-bde8-00c04f8eee78</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConfigLocation Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>370af178-7758-4dad-8146-7391f6e18585</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuota Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>377f739d-9647-4b8e-97d2-5ffce6d759cd</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Task Scheduler Service Remote Protocol - SASec</code></pre></td>
<td>MS Scheduler</td>
<td><pre><code>378e52b0-c0a9-11cf-822d-00aa0051e40f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Undocumented Interface 2</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>37fc1b02-da36-4b27-a745-bf2f58a98ff6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsAdvancedDisk3 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>3858c0d5-0f35-4bf5-9714-69874963bc36</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsIscsiInitiatorPortal</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>38a0a9ab-7cc8-4693-ac07-1f28bd03c3da</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Message Transfer Agent (MTA) Service - exchange_mta_qadmin Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>38a94e72-a9bc-11d2-8faf-00c04fa378ff</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmReportJob Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>38e87280-715c-4c7d-a280-ea1651a19fef</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Directory Services Setup Remote Protocol (MS-DSSP)</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>3919286a-b10c-11d0-9ba8-00c04fd92ef5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmDerivedObjectsResult Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>39322a2d-38ee-4d0d-8095-421a80849a82</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQManagement</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>39ce96fe-f4c5-4484-a143-4c2d5d324229</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IDMRemoteServer Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>3a410f21-553f-11d1-8e5e-00a0c92c9d5d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - ICategoryCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>3a56bfb8-576c-43f7-9335-fe4838fd7e37</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsPack Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>3b69d7f5-9d94-4648-91ca-79939ba263bf</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsObjectManagement3 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>3bbed8d9-2c9a-4b21-8936-acb2f995be6c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft DHCP Client Service</code></pre></td>
<td>MS DHCP</td>
<td><pre><code>3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DHCPv6 Client Service</code></pre></td>
<td>MS DHCP</td>
<td><pre><code>3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTGeneral2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>3c73848a-a679-40c5-b101-c963e67f9949</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Trusted Platform Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardManager3 Interface</code></pre></td>
<td>MS TPM Smart Card Mgt</td>
<td><pre><code>3c745a97-f375-4150-be17-5950f694c699</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Recipient Update Service Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>3cb4be69-9ba1-448c-9a44-a1f759a1878a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterFirewall Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>3cfee98c-fb4b-44c6-bd98-a1db14abca3f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Licensing</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>3d267954-eeb7-11d1-b94e-00c04fa3080d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Associates - Antivirus / e-Trust Antivirus / Threat Manager</code></pre></td>
<td>CA AntiVir</td>
<td><pre><code>3d742890-397c-11cf-9bf1-00805f88cb72</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft OLE Container - IAsyncOperation / IDataObjectAsyncCapability Interface</code></pre></td>
<td>MS OLE Container</td>
<td><pre><code>3d8b0590-f691-11d2-8ea9-006097df5bd4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Protected Storage Service - BackupKey Remote Protocol - BackupKey Interface</code></pre></td>
<td>MS Storage</td>
<td><pre><code>3dde7c30-165d-11d1-ab8f-00805f14db40</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IContainerControl Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>3f3b1b86-dbbe-11d1-9da6-00805f85cfe3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft SQL Server RPC</code></pre></td>
<td>MS SQL Server</td>
<td><pre><code>3f99b900-4d87-101b-99b7-aa0004007f07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Audio Service - Audio Server</code></pre></td>
<td>MS Audio</td>
<td><pre><code>3faf4738-3a21-4307-b46c-fdda9bb8c0d5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumSession Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>40cc8569-6d23-4005-9958-e37f08ae192b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDisk2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>40f73c8b-687d-4a13-8d96-3d7f2e683936</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Queue Manager Management Protocol - qmmgmt Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>41208ee0-e970-11d1-9b9e-00e02c064c39</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Service Control Manager - ISCM</code></pre></td>
<td>MS SCM</td>
<td><pre><code>412f241e-c12a-11ce-abff-0020af6e7a17</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterUpdate Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>4142dd5d-3472-4370-8641-de7856431fb0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaTemplateManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>4173ac41-172d-4d52-963c-fdc7e415f717</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Server</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>41f5fae1-e0ac-414c-a721-0d287466cb23</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemWCOSmartEnum Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>423ec01e-2e35-11d2-b604-00104b703efd</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileGroupManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>426677d5-018c-485c-8a51-20b86d00bdc4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaObject Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>42dc3511-61d5-48ae-b6dc-59fc00c0a8d6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumSession2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>442931d5-e522-4e64-a181-74e98a4e1748</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemContext Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>44aca674-e8fc-11d0-a07c-00c04fb68820</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemCallResult Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>44aca675-e8fc-11d0-a07c-00c04fb68820</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Gateway Server Protocol - TsProxyRpcInterface Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>44e265dd-7daf-42cd-8560-3cdb6e7a2729</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostPropertySchema</code></pre></td>
<td>MS IIS</td>
<td><pre><code>450386db-7409-4667-935e-384dbbee2a9e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogUtils Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>456129e2-1078-11d2-b0f9-00805fc73204</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DNS Client Service - Windows XP and above - DnsResolver</code></pre></td>
<td>MS DNS</td>
<td><pre><code>45776b01-5956-4485-9f80-f428f7d60129</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Administrative Interface: WINS protocol - winsif Interface</code></pre></td>
<td>MS WINS</td>
<td><pre><code>45f52c28-7f9f-101a-b52b-08002b2efabe</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateIdentity Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>46297823-9940-4c09-aed9-cd3ea6d05968</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Data Services (RDS) Transport Protocol (superseded by SOAP and DCOM) - IDataFactory3 Interface</code></pre></td>
<td>MS Remote Data Services</td>
<td><pre><code>4639db2a-bfc5-11d2-9318-00c04fbbbfb3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - System Attendant Service - Version 16.0</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>469d6ec0-0d87-11ce-b13f-00aa003bac6c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPropertyDefinition2 Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>47782152-d16c-4229-b4e1-0ddfe308b9f6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICapabilitySupport Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>47cde9a1-0bf6-11d2-8016-00c04fb9988e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMCalendar Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>481e06cf-ab04-4498-8ffe-124a0a34296d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Winlogon - IProfileDialog</code></pre></td>
<td>MS Security</td>
<td><pre><code>4825ea41-51e3-4c2a-8406-8f2d2698395f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaManagerEx Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>4846cb01-d430-494f-abb4-b1054999fb09</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - LSM Session Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>484809d6-4239-471b-b5bc-61df8c23ac48</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterSetup Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>491260b5-05c9-40d9-b7f2-1f7bdae0927f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - TermSrv Listener Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>497d95a6-2d27-4bf5-9bbd-a6046957133c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdate3 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>49ebd502-4a96-41bd-9e3e-4c5057f4250c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdates2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>4a2f5c31-cfd9-410e-b7fb-29a653973a0f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSubscription Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>4a6b0e15-2e38-11d1-9965-00c04fbbb345</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSubscription2 Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>4a6b0e16-2e38-11d1-9965-00c04fbbb345</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmProperty Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>4a73fee4-4102-4fcc-9ffb-38614f9ee768</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceInitialization Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>4afc3636-db01-4052-80c3-03bbcb8d3c69</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Simple Service Discovery Protocol (SSDP) Service - ssdpsrv Interface</code></pre></td>
<td>MS SSDP</td>
<td><pre><code>4b112204-0e19-11d3-b42b-0000f81feb9f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Server Service Remote Protocol (MS-SRVS) - srvsvc Interface</code></pre></td>
<td>MS Sharing</td>
<td><pre><code>4b324fc8-1670-01d3-1278-5a47bf6ee188</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft DFS Replication Helper Protocol - IADProxy Interface</code></pre></td>
<td>MS DFS Replication</td>
<td><pre><code>4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IVolumeClient2 Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>4bdafc52-fe6a-11d2-93f8-00105a11164a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmActionEventLog Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>4c8f96c3-5d94-4f37-a4f4-f56ab463546f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSearcher2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>4cbdcb2d-1589-4beb-bd1c-3e582ff0add0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - Remote Activation</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>4d9f4ab8-7d1c-11cf-861e-0020af6e7c57</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Link Tracking - Central Manager Protocol</code></pre></td>
<td>MS DLT</td>
<td><pre><code>4da1c422-943d-11d1-acae-00c04fc2aa3f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumePlex Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>4daa0135-e1d1-40f1-aaa5-3cc1e53221c3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumeMF2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>4dbcee9a-6343-4651-b85f-5e75d74d983c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConfigException Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>4dfa1df3-8900-4bc7-bbb5-d1a458c52410</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSystem Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>4e14fb9f-2e22-11d1-9964-00c04fbbb345</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISnapshotMgr Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>4e65a71e-4ede-4886-be67-3c90a08d1f29</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Tracker Service Protocol - IComTrackingInfoEvents Interface</code></pre></td>
<td>MS COM+ Tracker</td>
<td><pre><code>4e6cdcc9-fb25-4fd5-9cc5-c9f4b6559cec</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISnapshotMgr CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>4e7645fa-1a95-416c-b38f-ad574a3c3e57</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsLibraryControl1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>4e934f30-341a-11d1-8fb1-00a024cb6019</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMAccounting Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>4f7ca01c-a9e5-45b6-b142-2332a1339c1d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - NNTP Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>4f82f460-0e21-11cf-909e-00805f48a135</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed File System (DFS) - netdfs Interface</code></pre></td>
<td>MS DFS</td>
<td><pre><code>4fc742e0-4a10-11cf-8273-00aa004ae673</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateExceptionCollection : IDispatch Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>503626a3-8e14-4729-9355-0fe664bd2321</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computer Associates BrightStor - Message Engine [Vulnerability 1]</code></pre></td>
<td>CA BrightStor</td>
<td><pre><code>506b1890-14c8-11d1-bbc3-00805fa6962e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows DNS Server</code></pre></td>
<td>MS DNS</td>
<td><pre><code>50abc2a4-574d-40b3-9d66-ee4fd5fba076</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPipelineModuleDefinition Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>515c1277-2c81-440e-8fcf-367921ed4f59</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Key Management Server (KMS) - RequestActivation Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>51c82175-844e-4750-b0d8-ec255555bc06</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service AsyncEMSMDB Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>5261574a-4572-206e-b268-6b199213b4e4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDiskMgr Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>52ba97e7-9364-4134-b9cb-f8415213bdd8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Server Cluster - Configuration Protocol (MC-CCFG) - IClusCfgAsyncEvictCleanup Interface</code></pre></td>
<td>MS Server Cluster</td>
<td><pre><code>52c80b95-c1ad-4240-8d89-72e9fa84025e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Undocumented Interface 4</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>52d3f3f5-248c-4d74-a01f-a06e41d5cd59</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDiskPartitionMF Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>538684e0-ba3d-4bc0-aca9-164aff85c2a9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - TSVIPPublic Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>53b46b02-c73b-4a3e-8dee-b16b80672fc0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - WWW Publishing Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>53e75790-d96b-11cd-ba18-08002b2dfead</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemLoginHelper Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>541679ab-2e5f-11d3-b34e-00104bcc4b4a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) - ICertRequestD2 - Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>5422fd3a-d4b8-4cef-a12e-e87d4ca22e90</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateDownloadContent</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>54a2cb2d-9a0c-48b6-8a50-9abb69ee2d02</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumWTDisk Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>56e65ea5-cdff-4391-ba76-006e42c2d746</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Licensing Logging Service - lls_license Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>57674cd0-5200-11ce-a897-08002b2e9c6d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDiskMgr2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>592381e5-8d3c-42e9-b7de-4e77a1f75ae4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMMachineGroup Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>59602eb6-57b0-4fd8-aa4b-ebf06971fe15</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Messenger Service Remote Protocol - msgsvcsend operations for the NetrSendMessage method</code></pre></td>
<td>MS Messenger</td>
<td><pre><code>5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConstantValueCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>5b5a68e6-8b9f-45e1-8199-a95ffccdffff</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Management Service - qmrepl Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>5b5b3580-b0e0-11d1-b92d-0060081e87f0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DHCP Server - dhcpsrv2 Interface</code></pre></td>
<td>MS DHCP</td>
<td><pre><code>5b821720-f63b-11d0-aad2-00c04fc324db</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - FTP Publishing Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>5c89f409-09cc-101a-89f3-02608c4d2361</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - Legacy - WinStation_RPC Operations</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>5ca4a760-ebb1-11cf-8611-00a0245420ed</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Protected Storage Service - Password Recovery</code></pre></td>
<td>MS Storage</td>
<td><pre><code>5cbe92cb-f4be-45c9-9fc9-33e73e557b20</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreen Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>5f6325d3-ce88-4733-84c1-2d6aefc5ea07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteSstpCertCheck</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>5ff9bdf6-bd91-4d8b-a614-d6317acc8dd8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Fax Client Interface</code></pre></td>
<td>MS Fax</td>
<td><pre><code>6099fc12-3eff-11d0-abd0-00c04fd91a4e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteIPV6Config</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>6139d8a4-e508-4ebb-bac7-d7f275145897</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdate2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>615c4269-7a48-43bd-96b7-bf6ca27d6c3e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - DShellFolderViewEvents Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>62112aa2-ebe4-11cf-a5fb-0020afe7292d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Wireless Configuration Service</code></pre></td>
<td>MS Remote Services</td>
<td><pre><code>621dff68-3c39-4c6c-aae3-e68e2c6503ad</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft System Event Notification Service - SensNotify</code></pre></td>
<td>MS Event</td>
<td><pre><code>629b9f66-556c-11d1-8dd2-00aa004abd5e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Associates BrightStor ARCserve Backup Tape Engine</code></pre></td>
<td>CA BrightStor</td>
<td><pre><code>62b93df0-8b02-11ce-876c-00805f842837</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft System Event Notification Service - SensApi</code></pre></td>
<td>MS Event</td>
<td><pre><code>63fbe424-2029-11d1-8db8-00aa004abd5e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumResourceGroup Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>640038f1-d626-40d8-b52b-09660601d045</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQOutgoingQueueManagement Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>64c478fb-f9b0-4695-8a7f-439ac94326d3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Portmapper Service - FwIdl</code></pre></td>
<td>MS Portmapper</td>
<td><pre><code>64fe0b7f-9ef5-4553-a7db-9a1975777554</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostElement Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>64ff8ccc-b287-4dae-b08a-a72cbf45f453</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DNS Client Service - Windows 2000 and before</code></pre></td>
<td>MS DNS</td>
<td><pre><code>65a93890-fab9-43a3-b2a5-1e330ac28f11</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft IManagedObject Interface Protocol - IRemoteDispatch: IDispatch Interface</code></pre></td>
<td>MS IManagedObject</td>
<td><pre><code>6619a740-8154-43be-a186-0319578e02db</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteNetworkConfig</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>66a2db1b-d706-11d0-a37b-00c04fc9da04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteRouterRestart</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>66a2db20-d706-11d0-a37b-00c04fc9da04</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteSetDNSConfig</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>66a2db21-d706-11d0-a37b-00c04fc9da04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteICFICSConfig</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>66a2db22-d706-11d0-a37b-00c04fc9da04</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumSnapshot Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>66c9b082-7794-4948-839a-d8a5a616378f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdates Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>673425bf-c082-4c7c-bdfd-569464b8e0ce</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemContext - Unmarshaler Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>674b6698-ee92-11d0-ad71-00c04fd8fdff</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumeMF3 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>6788faf9-214e-4b85-ba59-266953616e09</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - System Attendant Service - Version 3.0</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>67df7c70-0f04-11ce-b13f-00aa003bac6c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service - IRemoteStringIdConfig</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>67e08fc2-2984-4b62-b92e-fc1aae64bbbb</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IInputObject Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>68284faa-6a48-11d0-8c78-00c04fd918b4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmReportScheduler Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>6879caf9-6617-4484-8719-71c3d8645f94</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Cryptographic Services - IKeySvc2</code></pre></td>
<td>MS Crypto</td>
<td><pre><code>68b58241-c259-4f03-a2e5-a2651dcbc930</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Intersite Messaging Service - ismapi Interface</code></pre></td>
<td>MS Intersite Messaging</td>
<td><pre><code>68dcd486-669e-11d1-ab0c-00c04fc2dcd2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsObjectInfo1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>69ab7050-3059-11d1-8faf-00a024cb6019</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdate Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>6a92b07a-d821-4682-b423-5c805022cc4d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdatesSettings2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>6abc136a-c3ca-4384-8171-cb2b1e59b8dc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumConnection Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>6aea6b26-0680-411d-8877-a148df3087d5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Firewall and Advanced Security Protocol (MS-FASP) - RemoteFW Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>6b5bdd1e-528c-422c-af8c-a4079be4fe48</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Common Internet File System (CIFS) - Browser Auxiliary Protocol - Browser Interface</code></pre></td>
<td>MS CIFS Browser</td>
<td><pre><code>6bffd098-a112-3610-9833-012892020162</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DHCP Server - dhcpsrv Interface</code></pre></td>
<td>MS DHCP</td>
<td><pre><code>6bffd098-a112-3610-9833-46c3f874532d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Workstation Service Remote Protocol - wkssvc Interface</code></pre></td>
<td>MS Remote Services</td>
<td><pre><code>6bffd098-a112-3610-9833-46c3f87e345a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IContainerControl2 Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>6c935649-30a6-4211-8687-c4c83e5fe1c7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmAction Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>6cd6408a-ae60-463b-9ef1-e117534d69dc</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IServiceProvider Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>6d5140c1-7436-11ce-8034-00aa006009fa</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsAdvancedDisk Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>6e6f6b40-977c-4069-bddd-ac710059f8c0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPathMapper Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>6f4dbfff-6920-4821-a6c3-b7e94c1fd60c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDiskMgr4 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>703e6b03-7ad1-4ded-ba0d-e90496ebc5de</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Directory Service Protocol - dscomm2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>708cca10-9569-11d1-b2a5-0060977d8118</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IMSAdminBaseW Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>70b51430-b6ca-11d0-b9b9-00a0c922e750</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdate5 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>70cf5c82-8642-42bb-9dbc-0cfd263c6c4f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolume2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>72ae6713-dcbb-4a03-b36b-371f6ac6b53d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - ISearchJob Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>7366ea16-7a1a-4ea2-b042-973d3e9cd99b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Transaction Coordinator (DTC) - DTCPing Interface</code></pre></td>
<td>MS DTC</td>
<td><pre><code>75687379-aaaa-44f6-9512-080ac70f8ad9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsOpenDisk Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>75c8f324-f715-4fe3-a28e-f9011b61a4a1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateService Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>76b3b17e-aed6-4da5-85f0-83587f81abe3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Undocumented Interface 1</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>76c0d124-a18e-49d4-adf1-d8c6ba868ea6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Queue Manager Client Protocol - qmcomm2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>76d12b80-3467-11d3-91ff-0090272f9ea3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Print System Asynchronous Remote Protocol (MS-PAR) - IRemoteWinspool Interface</code></pre></td>
<td>MS Print</td>
<td><pre><code>76f03f96-cdfd-44fc-a22c-64950a001209</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Directory Service Protocol - dscomm Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>77df7a80-f298-11d0-8358-00a024c480a8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft OCSP Administration Protocol (MS-OCSPA) - IOCSPAdminD Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>784b693d-95f3-420b-8126-365c098659f2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostMethod Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>7883ca1c-1112-4447-84c3-52fbeb38069d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Directory Replication Service (DRS) Remote Protocol - DSAOP Methods</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>7c44d7d4-31d5-424c-bd5e-2b3e1f323d22</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IIISApplicationAdmin Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>7c4e1804-e342-483d-a43e-a850cfcc8d18</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemObjectSink Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>7c857801-7381-11cf-884d-00aa004b2e24</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IImageInformation Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>7c907864-346c-4aeb-8f3f-57da289f969f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - IRobustNtmsMediaServices1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>7d07f313-a53f-459a-bb12-012c15b1846e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing Service</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>7e048d38-ac08-4ff1-8e6b-f35dbab88d4a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IAlternateLaunch Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>7f43b400-1a0e-4d57-bbc9-6b0c65f7a889</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Firewall - Fw_Resource_Indication Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>7f9d11bf-7fb9-436b-a812-b2d50c5d4c03</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventClass3 Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>7fb7ea43-2d76-4ea8-8cd9-3decc270295e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueManagement Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>7fbe7759-5760-444d-b8a5-5e7ab9a84cce</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Certificate Services Remote Administration Protocol - ICertAdminD2 Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>7fe0d935-dda6-443f-85d0-1cfb58fe41dd</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Administrative Interface: WINS protocol - winsi2 Interface</code></pre></td>
<td>MS WINS</td>
<td><pre><code>811109bf-a4e1-11d1-ab54-00a0c91e9b45</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft IManagedObject Interface Protocol - IServicedComponentInfo Interface</code></pre></td>
<td>MS IManagedObject</td>
<td><pre><code>8165b19e-8d3a-4d0b-80c8-97de310db583</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSession Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>816858a4-260d-4260-933a-2585f1abc76b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - ICategory Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>81ddc1b8-9d35-47a6-b471-5b80f519223b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumVolume Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>81fe3594-2495-4c91-95bb-eb5785614ec7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft EventLog Remoting Service - eventlog Interface</code></pre></td>
<td>MS Event</td>
<td><pre><code>82273fdc-e32a-18c3-3f78-827929dc23ea</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmActionEmail2 Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>8276702f-2532-4839-89bf-4872609a2ea4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IMSAdminBase2W Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>8298d101-f992-43b7-8eca-5052d885b995</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Inetinfo - IISAdmin Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>82ad4280-036b-11cf-972c-00aa006887b0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsAdviseSink Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>8326cd1d-cf59-4936-b786-5efc08798e25</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConfigLocationCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>832a32f7-b3ea-4b8c-b260-9a2923001184</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Assistance Initiation Protocol - IPCHCollection Interface</code></pre></td>
<td>MS Remote Assistance</td>
<td><pre><code>833e4100-aff7-4ac3-aac2-9f24c1457bce</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Assistance Initiation Protocol - ISAFSession Interface</code></pre></td>
<td>MS Remote Assistance</td>
<td><pre><code>833e41aa-aff7-4ac3-aac2-9f24c1457bce</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Assistance Initiation Protocol - IPCHService Interface</code></pre></td>
<td>MS Remote Assistance</td>
<td><pre><code>833e4200-aff7-4ac3-aac2-9f24c1457bce</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Function I</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>8384fc47-956a-4d1e-ab2a-1205014f96ec</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsSubSystemImportTarget Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>83bfb87f-43fb-4903-baa6-127f01029eec</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - System Attendant Service - Version 6.0</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>83d72bf0-0d89-11ce-b13f-00aa003bac6c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows File Protection Service</code></pre></td>
<td>MS Security</td>
<td><pre><code>83da7c00-e84f-11d2-9807-00c04f8ec850</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Administrative Interface - Network Policy Server (NPS) Protocol - IIASDataStoreComServer Interface</code></pre></td>
<td>MS Remote Services</td>
<td><pre><code>83e05bd5-aec1-4e58-ae50-e819c7296f67</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsUpdateAgentInfo Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>85713fa1-7796-4fa2-be3b-e2d6124dd373</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterLog Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>85923ca7-1b6b-4e83-a2e4-f5ba3bfbb8a3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDisk Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>866a78bc-a2fb-4ac4-94d5-db3041b4ed75</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Task Scheduler Service Remote Protocol - ITaskSchedulerService</code></pre></td>
<td>MS Scheduler</td>
<td><pre><code>86d35949-83c9-4044-b424-db363231fd0c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - IClientSink Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>879c8bbe-41b0-11d1-be11-00c04fb6bf70</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - LSM Enumeration Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>88143fd0-c28d-4b2b-8fef-8d882f6a9390</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolume Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>88306bb2-e71f-478c-86a2-79da200a0f11</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISnapshot Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>883343f1-ceed-4e3a-8c1b-f0dadfce281e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Associates BrightStor - Backup Agent RPC Server</code></pre></td>
<td>CA BrightStor</td>
<td><pre><code>88435ee0-861a-11ce-b86b-00001b27f656</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterLog Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>88e7ac6d-c561-4f03-9a60-39dd768f867d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Shutdown Protocol - InitShutdown Interface</code></pre></td>
<td>MS Remote Shutdown</td>
<td><pre><code>894de0c0-0d55-11d3-a322-00c04fa321a1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsObjectManagement2 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>895a2c86-270d-489d-a6c0-dc2a9b35280e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service - exchange_store_admin2 Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>89742ace-a9ed-11cf-9c0c-08002be7ae86</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed File System Replication Protocol (DFS-R) - FrsTransport Interface</code></pre></td>
<td>MS File Replication</td>
<td><pre><code>897e2e5f-93f3-4376-9c9c-fd2277495c27</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ILocalDeviceMgr Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>8ad608a4-6c16-4405-8879-b27910a68995</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>8bb68c7d-19d8-4ffb-809e-be4fc1734014</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - CLSID_WbemLevel1Login</code></pre></td>
<td>MS WMI</td>
<td><pre><code>8bc3f05e-d86b-11d0-a075-00c04fb68820</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IKnownFolderManager Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>8be2d872-86aa-4d47-b776-32cca40c7018</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostPropertySchemaCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>8bed2c68-a5fb-4b28-8581-a0dc5267419f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumVolume2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>8c58f6b3-4736-432a-891d-389de3505c7c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Application Management Service</code></pre></td>
<td>MS AMS</td>
<td><pre><code>8c7daf44-b6dc-11d1-9a4c-0020af6e7c57</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - SMTP Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>8cfb5d70-31a4-11cf-a7d8-00805f48a135</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Cryptographic Service</code></pre></td>
<td>MS Crypto</td>
<td><pre><code>8d0ffe72-d252-11d0-bf8f-00c04fd9126b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISessionManager Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>8d7ae740-b9c5-49fc-a11e-89171907cb86</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Plug and Play Service - pnp Interface</code></pre></td>
<td>MS Plug and Play</td>
<td><pre><code>8d9f4e40-a03d-11ce-8f69-08003e30051b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsSession1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>8da03f40-3419-11d1-8fb1-00a024cb6019</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IRegister Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>8db2180e-bd29-11d1-8b7e-00c04fd7a924</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileGroup Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>8dd04909-0e34-4d55-afaa-89e1f1a1bbb9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Routing and Remote Access Service (RRAS) Management Protocol - dimsvc Interface</code></pre></td>
<td>MS Remote Access</td>
<td><pre><code>8f09f000-b7ed-11ce-bbd2-00001a181cad</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSearcher Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>8f45abf1-f9ae-4b95-a933-f0f66e5056ea</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDisk3 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>8f4b2f5d-ec15-4357-992f-473ef10975b9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConfigManager</code></pre></td>
<td>MS IIS</td>
<td><pre><code>8f6d760f-f0cb-4d69-b5f6-848b33e9bdc6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft W32Time Remote Protocol (MS-W32T) / Network Time Protocol Authentication Extensions (MS-SNTP) - W32Time Interface</code></pre></td>
<td>MS W32Time</td>
<td><pre><code>8fb6d884-2388-11d0-8c35-00c04fda2795</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDiskOnline Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>90681b1d-6a7f-48e8-9061-31b7aa125322</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Transaction Coordinator (DTC) - Connection Manager: OleTx Transports Protocol - IXnRemote Operations</code></pre></td>
<td>MS DTC</td>
<td><pre><code>906b0ce0-c70b-1067-b317-00dd010662da</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSession3 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>918efd1e-b5d8-4c90-8540-aeb9bdc56f9d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Certificate Services - ICertPassage Remote Protocol - ICertPassage Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>91ae6020-9e3c-11cf-8d7c-00aa00c091be</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateSession2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>91caf7b0-eb23-49ed-9937-c52d817f46f7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Security Configuration Editor Service</code></pre></td>
<td>MS Security</td>
<td><pre><code>93149ca2-973b-11d1-8c39-00c04fb984f9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Veritas Backup Exec Service</code></pre></td>
<td>VR BKPSVC</td>
<td><pre><code>93841fd0-16ce-11ce-850d-02608c44967b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service EMSMDBPOOL Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>938fe036-ede6-4f6c-966e-a3d7300279c8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMPolicy Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>943991a5-b3fe-41fa-9696-7f7b656ee34b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemServices Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>9556dc99-828c-11cf-a37e-00aa003240c7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft WinLogon - IRPCSCLogon</code></pre></td>
<td>MS Security</td>
<td><pre><code>95958c94-a424-4055-b62b-b7f4d5c47770</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmCommittableCollection Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>96deb3b5-8b91-4a2a-9d93-80a35d8aa847</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IRegister2 Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>971668dc-c3fe-4ea1-9643-0c7230f494a1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Protocol - ITransactionStream Interface</code></pre></td>
<td>MS COM+</td>
<td><pre><code>97199110-db2e-11d1-a251-0000f805ca53</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsAdvancedDisk2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>9723f420-9355-42de-ab66-e31bb15beeac</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Portmapper Service</code></pre></td>
<td>MS Portmapper</td>
<td><pre><code>975201b0-59ca-11d0-a8d5-00a0c90d8051</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - InetInfo Service - Version 2.0</code></pre></td>
<td>MS IIS</td>
<td><pre><code>97f83d5c-1994-11d1-a90d-00c04fb960f8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IReplicationUtil Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>98315903-7be5-11d2-adc1-00a02463d6e7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsCreatePartitionEx Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>9882f547-cfc3-420b-9750-00dfbec50662</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSystem2 Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>99cc098f-a48a-4e9c-8e58-965c0afc19d5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service - exchange_store_admin3 Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>99e64010-b032-11d0-97a4-00c04fd6551d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IOXIDResolver/IObjectExporter Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>99fcfec4-5260-101b-bbcb-00aa0021347a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaTemplateImported Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>9a2bf113-a329-44cc-809a-5c00fce8da40</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemClassObject Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>9a653086-174f-11d2-b5f9-00104b703efd</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsSwProvider Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>9aa58360-ce33-4f92-b658-ed24b14425b8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateServiceCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>9b0353aa-0e52-44ff-b8b0-1f7fa0437f88</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - Process Launcher</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>9b8699ae-0e44-47b1-8e7f-86a461d7ecdc</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostAdminManager Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>9be77978-73ed-4a9a-87fd-13f09fec1b13</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsDiskPartitionMF2 Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>9cbe50ca-f2d2-4bf4-ace1-96896b729625</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Message Transfer Agent (MTA) Service</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>9e8ee830-4459-11ce-979b-00aa005ffebe</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Mail Transfer Agent (MTA) exchange_mta Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>9e8ee830-4559-11ce-979b-00aa005ffebe</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft WinLogon - GetUserToken Service</code></pre></td>
<td>MS Security</td>
<td><pre><code>a002b3a0-c9b7-11d1-ae88-0080c75e4ec1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Replication Service (FRS) - PerfFrs Interface</code></pre></td>
<td>MS File Replication</td>
<td><pre><code>a00c021c-2be2-11d2-b678-0000f87a8f8e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSystemInitialize Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>a0e8f27a-888c-11d1-b763-00c04fb926af</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmQuotaTemplate Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>a2efab31-295e-46bb-b976-e86d58b52e8b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemBackupRestoreEx : IWbemBackupRestore Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>a359dec5-e813-4834-8a2a-ba7f1d777d76</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Desktop Protocol: Smart Card Virtual Channel Extension (MS-RDPESC) - type_scard_pack Interface</code></pre></td>
<td>MS Remote</td>
<td><pre><code>a35af600-9cf4-11cd-a076-08002b2bd711</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateException Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>a376dd5e-09d4-427f-af7c-fed5b6e1c1d6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateExceptionCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>a37d00f5-7bb0-4953-b414-f9e98326f2e8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service - exchange_store_admin1 Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>a4f1db00-ca47-1067-b31e-00dd010662da</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service EMSMDB Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>a4f1db00-ca47-1067-b31f-00dd010662da</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - InetInfo Service - Version 3.0</code></pre></td>
<td>MS IIS</td>
<td><pre><code>a520d06e-11de-11d2-ab59-00c04fa3590c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumDisk2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>a5ecfc73-0013-4a9e-951c-59bf9735fdda</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterCleanup Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>a6d3e32b-9814-4409-8de3-cfa673e6d3de</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateHistoryEntryCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>a7f04f3c-a290-435b-aadf-a116c3357a5c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogTableInfo Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>a8927a41-d3ce-11d1-8472-006008b0e5ca</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Remote VSS Protocol (MS-FSRVP) - FileServerVssAgent Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>a8e0653c-2744-4389-a61d-7373df8b2292</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Security and Acceleration (ISA) - AD-LDS - ISASTGCTRL</code></pre></td>
<td>MS ISA</td>
<td><pre><code>a9b96d49-2c75-4917-a178-06b6f08261cc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Information Store - Undocumented Interface 1</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>a9e05b20-6f57-4e24-a540-52412017e6ff</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - COM GUID/UUID Service - IADMCOMSINK Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>a9e69612-b80d-11d0-b9b9-00a0c922e750</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Domain Name System (DNS) Server</code></pre></td>
<td>MS DNS</td>
<td><pre><code>aae9ac90-ce13-11cf-919e-08002be23c64</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISessionManager CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>ad069971-edc5-4357-a132-430dad479d2b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileGroupImported Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>ad55f10b-5f11-4be7-94ef-d9ee2e470ded</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostConfigFile Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>ada4e6fb-e025-401e-a5d0-c3134a281f07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Shadow Copy Management Protocol - IVssEnumObject Interface</code></pre></td>
<td>MS Volume Shadow Copy</td>
<td><pre><code>ae1c7110-2f60-11d3-8a39-00c04f72d8e3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Print System Asynchronous Notification Protocol (MS-PAN) - IRPCRemoteObject Interface</code></pre></td>
<td>MS Print</td>
<td><pre><code>ae33069b-a2a8-46ee-a235-ddfd339be281</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Transaction Coordinator (DTC) - Remote Management Interface</code></pre></td>
<td>MS DTC</td>
<td><pre><code>afa8bd80-7d8a-11c9-bef4-08002b102989</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmClassificationRule Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>afc052c2-5315-45ab-841b-c6db0e120148</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Central Access Policy Identifier (ID) - Retrieval Protocol (MS-CAPR) - lsacap Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>afc07e2e-311c-4435-808c-c483ffeec7c9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHost Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>b0076fec-a921-4034-a8ba-090bc6d03bde</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsObjectManagement1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>b057dc50-3059-11d1-8faf-00a024cb6019</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHostMgr Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>b06a64e3-814e-4ff9-afac-597ad32517c7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsIscsiInitiatorAdapter Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>b07fedd4-1682-4440-9189-a39b55194dc5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ILocalDeviceMgr2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>b0d1ac4b-f87a-49b2-938f-d439248575b2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IConnectionPointContainer Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>b196b284-bab4-101a-b69c-00aa00341d07</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IEnumConnectionPoints Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>b196b285-bab4-101a-b69c-00aa00341d07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IConnectionPoint Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>b196b286-bab4-101a-b69c-00aa00341d07</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - IEnumConnections Interface (obsolete)</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>b196b287-bab4-101a-b69c-00aa00341d07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Security and Acceleration (ISA) - Management Console (MMC)</code></pre></td>
<td>MS ISA</td>
<td><pre><code>b347203c-14bb-4878-8b7a-0a12f9b8076a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdate Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>b383cd1a-5ce9-4504-9f63-764b1236f191</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Commerce Server Staging (CSS) - Replication Service</code></pre></td>
<td>MS CSS</td>
<td><pre><code>b3df47c0-a95a-11cf-aa26-00aa00c148b9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Function II</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>b4757e80-a0e4-46b4-876a-3ae4a548ee07</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVdProvider</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>b481498c-8354-45f9-84a0-0bdd2832a91f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHost2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>b4fa8e86-2517-4a88-bd67-75447219eee4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdatesSettings3 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>b587f5c3-f57e-485f-bbf5-0d181c5cd0dc</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Tracker Service Protocol - IGetTrackingData Interface</code></pre></td>
<td>MS COM+ Tracker</td>
<td><pre><code>b60040e0-bcf3-11d1-861d-0080c729264d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceUninstallDisk Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>b6b22da8-f903-4be7-b492-c09d875ac9da</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostSectionDefinitionCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>b7d381ee-8860-47a1-8af4-1f33b2b1f325</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostMethodInstance Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>b80f3c42-60e0-4ae0-9007-f52852d3dbed</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Group Key Distribution Protocol (MS-GKDI) - ISDKey Interface</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>b9785960-524f-11df-8b6d-83dcded72085</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Management API - ClusAPI Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>b97db8b2-4c63-11cf-bff6-08002be23f2f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Portmapper Service - IROT Interface</code></pre></td>
<td>MS Portmapper</td>
<td><pre><code>b9e79e60-3d52-11ce-aaa1-00006901293f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Topology Information Server Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>b9fadb8d-53a1-41d7-b763-88d884b6b829</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTGeneral CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>baa4a577-202d-49c7-a6bb-10ee914ee199</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmClassifierModuleDefinition Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>bb36ea26-6318-4b8c-8592-f72dd602e7a5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsNotifySink Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>bb39332c-bfee-4380-ad8a-badc8aff5bb6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumDisk Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>bb39e296-ad26-42c5-9890-5325333bb11e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Active Directory Technical Specification - Claims Interface</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>bba9cb76-eb0c-462c-aa1b-5d8c34415701</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateDownloadContentCollection  Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>bc5513c8-b3b8-4bf7-a4d4-361c0d8c88ba</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMResourceGroup Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>bc681469-9dd9-4bf4-9b3d-709f69efe431</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IIISCertObj Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>bd0c73bc-805b-4043-9c30-9a28d64dd7d2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Function III</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>bd5790c9-d855-42b0-990f-3dfed8c184b3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Terminal Server Services - Runtime Interface - TermSrv Interface</code></pre></td>
<td>MS Terminal Server</td>
<td><pre><code>bde95fdf-eee0-45de-9e12-e5a61cd0d4fe</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateHistoryEntry Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>be56a644-af0e-4e0e-a311-c1d8e695cbff</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQManagement Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>be5f0241-e489-4957-8cc4-a452fcf3e23e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenException Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>bee7ce02-df77-4515-9389-78f01c5afc1a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Information Store - Undocumented Interface 2</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>bf6dd426-77b4-44b3-984e-d413fc075562</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Admin Service</code></pre></td>
<td>MS IIS</td>
<td><pre><code>bfa951d1-2f0e-11d3-bfd1-00c04fa3490a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ISessionManager2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>c10a76d8-1fe4-4c2f-b70d-665265215259</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdate5 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>c1c2f21a-d2f4-4902-b5c6-8a081c19a890</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IImport Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>c2be6970-df9e-11d1-8b87-00c04fd7a924</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateHistoryEntry2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>c2bfb780-4539-4132-ab8c-0a8772013ab6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Administrative Interface - Network Policy Server (NPS) Protocol - IIASDataStoreComServer2 Interface</code></pre></td>
<td>MS Remote Services</td>
<td><pre><code>c323be28-e546-4c23-a81b-d6ad8d8fac7b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Audio Service - Audio Remote Procedure Call (RPC)</code></pre></td>
<td>MS Audio</td>
<td><pre><code>c386ca3e-9061-4a72-821e-498d83be188f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft IManagedObject Interface Protocol - IManagedObject : IUnknown Interface</code></pre></td>
<td>MS IManagedObject</td>
<td><pre><code>c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - CLSID_WbemBackupRestore</code></pre></td>
<td>MS WMI</td>
<td><pre><code>c49e32c6-bc8b-11d2-85d4-00105a1f8304</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemBackupRestoreEx Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>c49e32c7-bc8b-11d2-85d4-00105a1f8304</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft DFS Replication Helper Protocol - IADProxy2 Interface</code></pre></td>
<td>MS DFS Replication</td>
<td><pre><code>c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostSectionDefinition Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>c5c04795-321c-4014-8fd6-d44658799393</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IResourceManager Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>c5cebee2-9df5-4cdd-a08c-c2471bc144b4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Encrypting File System Remote (EFSR) Protocol - lsarpc Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>c681d488-d850-11d0-8c52-00c04fd90f7e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Portmapper Service - IMachineActivatorControl Interface</code></pre></td>
<td>MS Portmapper</td>
<td><pre><code>c6f3ee72-ce7e-11d1-b71e-00c04fc3111a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - ICatalogUtils2 interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>c726744e-5735-4f08-8286-c510ee638fb6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterStorage2 Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>c72b09db-4d53-4f41-8dcc-2d752ab56f7c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - exchange_unknown Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>c840a7dc-42c0-1a10-b4b9-08002b2fe182</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostElementCollection</code></pre></td>
<td>MS IIS</td>
<td><pre><code>c8550bff-5281-4b1e-ac34-99b6fa38464d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - ICommDlgBrowser3 Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>c8ad25a1-3294-41ee-8165-71174bd01c57</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Web Distributed Authoring and Versioning (WebDAV) Client Service - davclntrpc Interface</code></pre></td>
<td>MS WDAV</td>
<td><pre><code>c8cb7687-e6d3-11d2-a958-00c04f682e16</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Protected Storage Service - IPStoreProv</code></pre></td>
<td>MS Storage</td>
<td><pre><code>c9378ff1-16f7-11d0-a0b2-00aa0061426a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateDownloadContent2 Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>c97ad11b-f257-420b-9d9f-377f733f6f68</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmRule Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>cb0df960-16f5-4495-9079-3f9360d831df</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Service Witness Protocol - Witness Interface</code></pre></td>
<td>MS Witness</td>
<td><pre><code>ccd8c074-d0e5-4a40-92b4-d074faa6ba28</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IFolderView Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>cde725b0-ccc9-4519-917e-325d72fab4ce</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IExport Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>cfadac84-e12c-11d1-b34c-00c04f990d54</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenTemplateManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>cfe36cba-1949-4e74-a14f-f1d580ceaf13</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsMediaServices1 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>d02e4be0-3419-11d1-8fb1-00a024cb6019</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Replication Service (FRS) - NtFrsApi Interface</code></pre></td>
<td>MS File Replication</td>
<td><pre><code>d049b186-814f-11d1-9a3c-00c04fc9b232</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IVolumeClient Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>d2d79df5-3400-11d0-b40b-00aa005ff586</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IDMNotify Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>d2d79df7-3400-11d0-b40b-00aa005ff586</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmClassificationManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>d2dc89da-ee91-48a0-85d8-cc72a56f7d04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft IPSEC Policy Agent</code></pre></td>
<td>MS Security</td>
<td><pre><code>d335b8f6-cb31-11d0-b0f9-006097ba4e54</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Procedure Call (RPC) Locator Service - NsiC</code></pre></td>
<td>MS Locator</td>
<td><pre><code>d3fbb514-0e3b-11cb-8fad-08002b1d29c3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - ISearchResult</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>d40cff62-e08c-4498-941a-01e25f0fd33c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemLoginClientID Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>d4781cd6-e5d3-44df-ad94-930efe48a887</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsAsync Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>d5d23b6d-5a55-4492-9889-397a3c2d2dbc</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterCleanup Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>d6105110-8917-41a5-aa32-8e0aa2933dc9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - Removable Storage Manager Class</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>d61a27c6-8f53-11d0-bfa0-00a024151983</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmActionEmail Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>d646567d-26ae-4caa-9f84-4e0aad207fca</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Connection Firewall</code></pre></td>
<td>MS ICFW</td>
<td><pre><code>d674a233-5829-49dd-90f0-60cf9ceb7129</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumeShrink Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>d68168c9-82a2-4f85-b6e9-74707c49a58f</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTDiskMgr3 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>d6bd6d63-e8cb-4905-ab34-8a278c93197a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostMethodCollection Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>d6c7cd8f-bb8d-4f96-b591-d3a5f1320269</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Procedure Call (RPC) Locator Service - NsiS</code></pre></td>
<td>MS Locator</td>
<td><pre><code>d6d70ef0-0e3b-11cb-acc3-08002b1d29c3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Procedure Call (RPC) Locator Service - NsiM</code></pre></td>
<td>MS Locator</td>
<td><pre><code>d6d70ef0-0e3b-11cb-acc3-08002b1d29c4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IWTGeneral Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>d71b2cae-33e8-4567-ae96-3ccf31620be2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQPrivateEvent Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7ab3341-c9d3-11d1-bb47-0080c7c5a2c0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQuery Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e072-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQQuery</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e073-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQMessage Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e074-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQMessage</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e075-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueue Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e076-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQEvent Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e077-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - DMSMQEventEvents Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e078-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQQueue</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e079-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQEvent</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07a-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfo Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07b-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQQueueInfo</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07c-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfos Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07d-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQQueueInfos</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07e-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransaction Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e07f-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQTransaction Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e080-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQCoordinatedTransactionDispenser Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e081-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQCoordinatedTransactionDispenser</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e082-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransactionDispenser Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e083-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQTransactionDispenser</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e084-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQApplication Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e085-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQApplication</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d7d6e086-dccd-11d0-aa4b-0060970debae</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Domain Name System (DNS) Server - Interface version 5.0</code></pre></td>
<td>MS DNS</td>
<td><pre><code>d7f9e1c0-2247-11d1-ba89-00c04fd91268</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmReport Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>d8cc81d9-46b8-4fa4-bfa5-4aa9dec9b638</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Shutdown Protocol - WindowsShutdown Interface</code></pre></td>
<td>MS Remote Shutdown</td>
<td><pre><code>d95afe70-a6d5-4259-822e-2c84da1ddb0d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQMessage2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>d9933be0-a567-11d2-b0f3-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsHwProvider Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>d99bdaae-b13a-4178-9fdb-e27f16b4603e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) - ICertRequestD - Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>d99e6e70-fc88-11d0-b498-00a0c90312f3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Certificate Services Remote Administration Protocol - ICertAdminD Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>d99e6e71-fc88-11d0-b498-00a0c90312f3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IInstallationBehavior Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>d9a59339-e245-4dbd-9686-4d5763e39624</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Store Service - Admin Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>da107c01-2b50-44d7-9d5f-bfd4fd8e95ed</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Performance Counter Query Protocol (MS-PCQ) - PerflibV2 Interface</code></pre></td>
<td>MS Performance</td>
<td><pre><code>da5a86c5-12c2-4943-ab30-7f74a813d853</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Removable Storage Manager (RSM) Remote Protocol - INtmsLibraryControl2 Interface</code></pre></td>
<td>MS Removable Storage</td>
<td><pre><code>db90832f-6910-4d46-9f5e-9fd6bfa73903</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemClassObject : Iunknown Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>dc12a681-737f-11cf-884d-00aa004b2e24</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Associates BrightStor - Message Engine [Vulnerability 2]</code></pre></td>
<td>CA BrightStor</td>
<td><pre><code>dc246bf0-7a7a-11ce-9f88-00805fe43838</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHostMgr2 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>dd6f0a28-248f-4dd3-afe9-71aed8f685c4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IUpdateServiceRegistration Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>dde02280-12b3-4e0b-937b-6747f6acb286</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostCollectionSchema Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>de095db1-5368-4d11-81f6-efef619b7bcf</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Disk Management Remote Protocol - IVolumeClient4 Interface</code></pre></td>
<td>MS Disk Management</td>
<td><pre><code>deb01010-3a37-4d26-99df-e2bb6ae3ac61</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Encrypting File System Remote (EFSR) Protocol - efsrpc Interface</code></pre></td>
<td>MS Security</td>
<td><pre><code>df1941c5-fe89-4e79-bf10-463657acf44d</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IExplorerBrowser Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>dfd3b6b5-c10c-4be9-85f6-a66969f402f6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceLoader Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>e0393303-90d4-4a97-ab71-e9b671ee2729</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Explorer - Browser - IExplorerPaneVisibility Interface</code></pre></td>
<td>MS Explorer Browser</td>
<td><pre><code>e07010ec-bc17-44c0-97b0-46c7c95b9edc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenTemplateImported Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>e1010359-3e5d-4ecd-9fe4-ef48622fdf30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumHost Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>e141fd54-b79e-4938-a6bb-d523c3d49ff1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHostMgr CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>e14efe0b-fd3b-41ea-8e3b-88930445b944</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - ClusterNetwork2 Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>e1568352-586d-43e4-933f-8e6dc4de317a</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - Endpoint Mapper Service (EPM)</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>e1af8308-5d1f-11c9-91a4-08002b14a0fa</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumSnsServer Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>e2842c88-07c3-4eb0-b1a9-d3d95e76fef2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Procedure Call Location Services Extensions (MS-RPCL) - Deprecated - LocToLoc Interface</code></pre></td>
<td>MS Locator</td>
<td><pre><code>e33c0cc4-0482-101a-bc0c-02608c6ba218</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Directory Replication Service (DRS) Remote Protocol - DRSUAPI Methods</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>e3514235-4b06-11d1-ab04-00c04fc2dcd2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterUpdate Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>e3c9b851-c442-432b-8fc6-a7faafc09d3b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Background Intelligent Transfer Service (BITS) - Peer Authentication Protocol - BitsPeerAuth Interface</code></pre></td>
<td>MS BITS</td>
<td><pre><code>e3d0d746-d2af-40fd-8a7a-0d7078bb7092</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Distributed Component Object Model (DCOM) - ILocalObjectExporter Interface</code></pre></td>
<td>MS DCOM Services</td>
<td><pre><code>e60c73e6-88f9-11cf-9af1-0020af6e72f4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ILocalDeviceMgr3 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>e645744b-cae5-4712-acaf-13057f7195af</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft DFS Replication Helper Protocol - IServerHealthReport Interface</code></pre></td>
<td>MS DFS Replication</td>
<td><pre><code>e65e8028-83e8-491b-9af7-aaf6bd51a0ce</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Client Service for NetWare - NWWKS</code></pre></td>
<td>MS Network</td>
<td><pre><code>e67ab081-9844-3521-9d32-834f038001c0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostPathMapper Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>e7927575-5cc3-403b-822e-328a6b904bee</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IAutomaticUpdatesResults Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>e7a4d634-7942-4dd9-a111-82228ba33901</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - ResourceManager Class</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>e8bcffac-b864-4574-b2e8-f1fb21dfdc18</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - ServiceControl</code></pre></td>
<td>MS IIS</td>
<td><pre><code>e8fb8620-588f-11d2-9d61-00c04f79c5fe</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPropertyDefinitionValue Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>e946d148-bd67-4178-8e22-1c44925ed710</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft SHAREDFAX Fax Server and FaxObs Server Interfaces</code></pre></td>
<td>MS Fax</td>
<td><pre><code>ea0a3165-4834-11d2-a6f8-00c04fa346cc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostPropertyException Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>eafe4895-a929-41ea-b14d-613e23f62b71</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQuery2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b0e-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfos2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b0f-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQCoordinatedTransactionDispenser2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b10-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransactionDispenser2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b11-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQEvent2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b12-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransaction3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b13-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQCoordinatedTransactionDispenser3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b14-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQTransactionDispenser3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b15-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQDestination Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b16-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQPrivateDestination Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b17-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQDestination</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b18-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQuery3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b19-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQMessage3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1a-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueue3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1b-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQEvent3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1c-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfo3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1d-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfos3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1e-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQApplication3 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b1f-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueue4 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b20-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfo4 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b21-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfos4 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b22-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQMessage4 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b23-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQuery4 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>eba96b24-2168-11d3-898c-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Active Directory Backup and Restore Services - JetBack Interface</code></pre></td>
<td>MS Active Directory</td>
<td><pre><code>ecec0d70-a603-11d0-96b1-00a0c91ece30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostProperty Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>ed35f7a1-5024-4e7b-a44d-07ddaf4b524d</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IWindowsDriverUpdateEntry Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>ed8bfe40-a60b-42ea-9652-817dfcfa23ec</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmPropertyDefinition Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>ede0150f-e9a3-419c-877c-01fe5d24c5d3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsVolumeMF Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>ee2d5ded-6236-4169-931d-b9778ce03dc6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileManagementJobManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>ee321ecb-d95e-48e9-907c-c7685a013235</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueue2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>ef0574e0-06d8-11d3-b100-00e02c074f6b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostElementSchema Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>ef13d885-642c-4709-99ec-b89561c6bc69</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Update Agent Management Protocol - IStringCollection Interface</code></pre></td>
<td>MS Update Agent</td>
<td><pre><code>eff90582-2ddc-480f-a06d-60f3fbc362c3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IEnumCachedInitiator Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>f093fe3d-8131-4b73-a742-ef54c20b337b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Remote Assistance Initiation Protocol - IRASrv Interface</code></pre></td>
<td>MS Remote Assistance</td>
<td><pre><code>f120a684-b926-447f-9df4-c966cb785648</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Remote Administration Protocol Protocol - IExport2 Interface</code></pre></td>
<td>MS COM+ Remote Admin</td>
<td><pre><code>f131ea3e-b7be-480e-a60d-51cb2785779e</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - ILocalDeviceMgr CLSID</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>f1d3a46c-2e1b-4d84-97da-b3742ad67871</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Failover Cluster: Setup and Validation Protocol - IClusterFirewall Interface</code></pre></td>
<td>MS Failover Cluster</td>
<td><pre><code>f1d6c29c-8fbe-4691-8724-f6d8deaeafc8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemRemoteRefresher Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>f1e9c5b2-f59b-11d2-b362-00105a1f8177</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Undocumented Interface 5</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>f1f21151-7185-4170-ac8d-9bb077c29bd3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Undocumented Interface 3</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>f224209f-9076-40f7-98ad-5416dbfa178e</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows Management Instrumentation (WMI) - Remote Protocol - IWbemLevel1Login Interface</code></pre></td>
<td>MS WMI</td>
<td><pre><code>f309ad18-d86a-11d0-a075-00c04fb68820</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMProtocol Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>f31931a9-832d-481c-9503-887a0e6a79f0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenBase Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>f3637e80-5b22-4a2b-a637-bbb642b41cfc</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmSetting Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>f411d4fd-14be-4260-8c40-03b7c95e608a</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEnumEventObject Interface Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>f4a07d63-2e25-11d1-9964-00c04fbbb345</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Cryptographic Services - ICatDBSvc</code></pre></td>
<td>MS Crypto</td>
<td><pre><code>f50aac00-c7f3-428e-a022-a6b71bfb9d43</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Replication Service (FRS) - exchange_drs - frsrpc Interface</code></pre></td>
<td>MS File Replication</td>
<td><pre><code>f5cc59b4-4264-101a-8c59-08002b2f8426</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange Name Service Provider Interface (NSPI) Proxy - exchange_nsp Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>f5cc5a18-4264-101a-8c59-08002b2f8426</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Active Directory Extended Directory Service (XDS) - exchange_xds Interface</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>f5cc5a7c-4264-101a-8c59-08002b2f8426</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - IMSAdminBaseW - IMSAdminBase3W Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>f612954d-3b0b-4c56-9563-227b7be624b4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft EventLog Remoting Protocol Version 6.0 - IEventService Interface</code></pre></td>
<td>MS Event</td>
<td><pre><code>f6beaff7-1e19-4fbb-9f8f-b89e2018337c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - MSMQCollection</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>f72b9031-2f0c-43e8-924e-e6052cdc493f</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmCollection Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>f76fbf3b-8ddd-4b42-b05a-cb1c3ff1fee8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmAutoApplyQuota Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>f82e5729-6aba-4740-bfc7-c7f58f75fb7b</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventObjectCollection Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>f89ac270-d4eb-11d1-b682-00805fc79216</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Exchange - Exchange System Attendant Cluster Interface (exchange_sysatt_cluster)</code></pre></td>
<td>MS Exchange</td>
<td><pre><code>f930c514-1215-11d3-99a5-00a0c9b61b04</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Internet Information Services (IIS) - Application Host COM - IAppHostWritableAdminManager Interface</code></pre></td>
<td>MS IIS</td>
<td><pre><code>fa7660f6-7b3f-4237-a8bf-ed0ad0dcbbd9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Shadow Copy Management Protocol - IVssSnapshotMgmt Interface</code></pre></td>
<td>MS Volume Shadow Copy</td>
<td><pre><code>fa7df749-66e7-4986-a27f-e2f04ae53772</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventClass Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>fb2b72a0-7a68-11d1-88f9-0080c7d771bf</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventClass2 Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>fb2b72a1-7a68-11d1-88f9-0080c7d771bf</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Component Object Model Plus (COM+) Event System Protocol - IEventSubscription3 Interface</code></pre></td>
<td>MS COM+ Event System</td>
<td><pre><code>fbc1d17d-c498-43a0-81af-423ddd530af6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Management Service</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>fc13257d-5567-4dea-898d-c6f9c48415a0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Virtual Disk Service (VDS) Protocol - IVdsServiceSAN Interface</code></pre></td>
<td>MS Virtual Disk</td>
<td><pre><code>fc5d23e8-a88b-41a5-8de0-2d2f73c5a630</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Windows System Resource Manager (WSRM) Protocol - IWRMRemoteSessionMgmt Interface</code></pre></td>
<td>MS System Resource</td>
<td><pre><code>fc910418-55ca-45ef-b264-83d4ce7d30e0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - ActiveX Client - IMSMQQueueInfo2 Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>fd174a80-89cf-11d2-b0f2-00e02c074f6b</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft Message Queuing - Queue Manager Client Protocol - qmcomm Interface</code></pre></td>
<td>MS Message Queuing</td>
<td><pre><code>fdb3a030-065f-11d1-bb9b-00a024ea5525</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Trusted Platform Module Virtual Smart Card Management Protocol - ITpmVirtualSmartCardManager2 Interface</code></pre></td>
<td>MS TPM Smart Card Mgt</td>
<td><pre><code>fdf8a2b9-02de-47f4-bc26-aa85ab5e5267</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft iSCSI Software Target Management Protocol - IHost3 Interface</code></pre></td>
<td>MS ISTM iSCSI</td>
<td><pre><code>fe7f99f9-1dfb-4afb-9d00-6a8dd0aabf2c</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Telnet Server Remote Administration Protocol (MS-TSRAP) - CLSID_EnumTelnetClientsSvr Interface</code></pre></td>
<td>MS Telnet Server</td>
<td><pre><code>fe9e48a4-a014-11d1-855c-00a0c944138c</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Microsoft File Server Resource Manager Protocol - IFsrmFileScreenManager Interface</code></pre></td>
<td>MS File Server</td>
<td><pre><code>ff4fa04e-5a94-4bda-a3a0-d5b4d3c52eba</code></pre></td>
</tr>
</tbody>
</table>

### Type [dnsclass](#type-dnsclass)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IN</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
<td>Internet</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CS</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
<td>CSNET class (Obsolete - used only for examples)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CH</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
<td>CHAOS class</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HS</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
<td>Hesiod</td>
</tr>
</tbody>
</table>

### Type [dnscode](#type-dnscode)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>No DNS Response</code></pre></td>
<td><pre><code>-1 - 0x-1</code></pre></td>
<td>No DNS Response</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NoError</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
<td>No Error</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FormErr</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
<td>Format Error</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ServFail</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
<td>Server Failure</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NXDomain</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
<td>Non-Existent Domain</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NotImp</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
<td>Not Implemented</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Refused</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
<td>Query Refused</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>YXDomain</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
<td>Name Exists when it should not</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>YXRRSet</code></pre></td>
<td><pre><code>7 - 0x7</code></pre></td>
<td>RR Set Exists when it should not</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NXRRSet</code></pre></td>
<td><pre><code>8 - 0x8</code></pre></td>
<td>RR Set that should exist does not</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NotAuth</code></pre></td>
<td><pre><code>9 - 0x9</code></pre></td>
<td>Server Not Authoritative for zone</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NotZone</code></pre></td>
<td><pre><code>10 - 0xA</code></pre></td>
<td>Name not contained in zone</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BadSig/BadVers</code></pre></td>
<td><pre><code>16 - 0x10</code></pre></td>
<td>TSIG Signature Failure OR Bad OPT version</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BadKey</code></pre></td>
<td><pre><code>17 - 0x11</code></pre></td>
<td>Key not recognized</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BadTime</code></pre></td>
<td><pre><code>18 - 0x12</code></pre></td>
<td>Signature out of time window</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BadMode</code></pre></td>
<td><pre><code>19 - 0x13</code></pre></td>
<td>Bad TKEY Mode</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BadName</code></pre></td>
<td><pre><code>20 - 0x14</code></pre></td>
<td>Duplicate key name</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BadAlg</code></pre></td>
<td><pre><code>21 - 0x15</code></pre></td>
<td>Algorithm not supported</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BadTrunc</code></pre></td>
<td><pre><code>22 - 0x16</code></pre></td>
<td>Bad Truncation</td>
</tr>
</tbody>
</table>

### Type [dnstype](#type-dnstype)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RESERVED</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
<td>reserved type, sometimes mistakenly used by Microsoft protocols</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>A</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
<td>a host address</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NS</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
<td>an authoritative name server</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MD</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
<td>a mail destination (Obsolete - use MX)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MF</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
<td>a mail forwarder (Obsolete - use MX)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CNAME</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
<td>the canonical name for an alias</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SOA</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
<td>marks the start of a zone of authority</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MB</code></pre></td>
<td><pre><code>7 - 0x7</code></pre></td>
<td>a mailbox domain name (EXPERIMENTAL)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MG</code></pre></td>
<td><pre><code>8 - 0x8</code></pre></td>
<td>a mail group member (EXPERIMENTAL)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MR</code></pre></td>
<td><pre><code>9 - 0x9</code></pre></td>
<td>a mail rename domain name (EXPERIMENTAL)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NULL</code></pre></td>
<td><pre><code>10 - 0xA</code></pre></td>
<td>a null RR (EXPERIMENTAL)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>WKS</code></pre></td>
<td><pre><code>11 - 0xB</code></pre></td>
<td>a well known service description</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PTR</code></pre></td>
<td><pre><code>12 - 0xC</code></pre></td>
<td>a domain name pointer</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HINFO</code></pre></td>
<td><pre><code>13 - 0xD</code></pre></td>
<td>host information</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MINFO</code></pre></td>
<td><pre><code>14 - 0xE</code></pre></td>
<td>mailbox or mail list information</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MX</code></pre></td>
<td><pre><code>15 - 0xF</code></pre></td>
<td>mail exchange</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TXT</code></pre></td>
<td><pre><code>16 - 0x10</code></pre></td>
<td>text strings</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RP</code></pre></td>
<td><pre><code>17 - 0x11</code></pre></td>
<td>for Responsible Person</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AFSDB</code></pre></td>
<td><pre><code>18 - 0x12</code></pre></td>
<td>for AFS Data Base location</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>X25</code></pre></td>
<td><pre><code>19 - 0x13</code></pre></td>
<td>for X.25 PSDN address</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISDN</code></pre></td>
<td><pre><code>20 - 0x14</code></pre></td>
<td>for ISDN address</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RT</code></pre></td>
<td><pre><code>21 - 0x15</code></pre></td>
<td>for Route Through</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NSAP</code></pre></td>
<td><pre><code>22 - 0x16</code></pre></td>
<td>for NSAP address, NSAP style A record</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NSAP-PTR</code></pre></td>
<td><pre><code>23 - 0x17</code></pre></td>
<td>for domain name pointer, NSAP style</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SIG</code></pre></td>
<td><pre><code>24 - 0x18</code></pre></td>
<td>for security signature</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KEY</code></pre></td>
<td><pre><code>25 - 0x19</code></pre></td>
<td>for security key</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PX</code></pre></td>
<td><pre><code>26 - 0x1A</code></pre></td>
<td>X.400 mail mapping information</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>GPOS</code></pre></td>
<td><pre><code>27 - 0x1B</code></pre></td>
<td>Geographical Position</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AAAA</code></pre></td>
<td><pre><code>28 - 0x1C</code></pre></td>
<td>a IP6 host address</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>LOC</code></pre></td>
<td><pre><code>29 - 0x1D</code></pre></td>
<td>Location Information</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NXT</code></pre></td>
<td><pre><code>30 - 0x1E</code></pre></td>
<td>Next Domain - OBSOLETE</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EID</code></pre></td>
<td><pre><code>31 - 0x1F</code></pre></td>
<td>Endpoint Identifier</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NIMLOC/NB</code></pre></td>
<td><pre><code>32 - 0x20</code></pre></td>
<td>Nimrod Locator OR Netbios</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SRV/NBSTAT</code></pre></td>
<td><pre><code>33 - 0x21</code></pre></td>
<td>Server Selection OR Netbios Stats</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ATMA</code></pre></td>
<td><pre><code>34 - 0x22</code></pre></td>
<td>ATM Address</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NAPTR</code></pre></td>
<td><pre><code>35 - 0x23</code></pre></td>
<td>Naming Authority Pointer</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KX</code></pre></td>
<td><pre><code>36 - 0x24</code></pre></td>
<td>Key Exchanger</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CERT</code></pre></td>
<td><pre><code>37 - 0x25</code></pre></td>
<td>CERT</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>A6</code></pre></td>
<td><pre><code>38 - 0x26</code></pre></td>
<td>A6 (Experimental)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DNAME</code></pre></td>
<td><pre><code>39 - 0x27</code></pre></td>
<td>DNAME</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SINK</code></pre></td>
<td><pre><code>40 - 0x28</code></pre></td>
<td>SINK</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OPT</code></pre></td>
<td><pre><code>41 - 0x29</code></pre></td>
<td>OPT</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>APL</code></pre></td>
<td><pre><code>42 - 0x2A</code></pre></td>
<td>APL</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DS</code></pre></td>
<td><pre><code>43 - 0x2B</code></pre></td>
<td>Delegation Signer</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SSHFP</code></pre></td>
<td><pre><code>44 - 0x2C</code></pre></td>
<td>SSH Key Fingerprint</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPSECKEY</code></pre></td>
<td><pre><code>45 - 0x2D</code></pre></td>
<td>IPSECKEY</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RRSIG</code></pre></td>
<td><pre><code>46 - 0x2E</code></pre></td>
<td>RRSIG</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NSEC</code></pre></td>
<td><pre><code>47 - 0x2F</code></pre></td>
<td>NSEC</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DNSKEY</code></pre></td>
<td><pre><code>48 - 0x30</code></pre></td>
<td>DNSKEY</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DHCID</code></pre></td>
<td><pre><code>49 - 0x31</code></pre></td>
<td>DHCID</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NSEC3</code></pre></td>
<td><pre><code>50 - 0x32</code></pre></td>
<td>NSEC3</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NSEC3PARAM</code></pre></td>
<td><pre><code>51 - 0x33</code></pre></td>
<td>NSEC3PARAM</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HIP</code></pre></td>
<td><pre><code>55 - 0x37</code></pre></td>
<td>Host Identity Protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NINFO</code></pre></td>
<td><pre><code>56 - 0x38</code></pre></td>
<td>NINFO</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RKEY</code></pre></td>
<td><pre><code>57 - 0x39</code></pre></td>
<td>RKEY</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TALINK</code></pre></td>
<td><pre><code>58 - 0x3A</code></pre></td>
<td>Trust Anchor LINK</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CDS</code></pre></td>
<td><pre><code>59 - 0x3B</code></pre></td>
<td>Child DS</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SPF</code></pre></td>
<td><pre><code>99 - 0x63</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>UINFO</code></pre></td>
<td><pre><code>100 - 0x64</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>UID</code></pre></td>
<td><pre><code>101 - 0x65</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>GID</code></pre></td>
<td><pre><code>102 - 0x66</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>UNSPEC</code></pre></td>
<td><pre><code>103 - 0x67</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TKEY</code></pre></td>
<td><pre><code>249 - 0xF9</code></pre></td>
<td>Transaction Key</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TSIG</code></pre></td>
<td><pre><code>250 - 0xFA</code></pre></td>
<td>Transaction Signature</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IXFR</code></pre></td>
<td><pre><code>251 - 0xFB</code></pre></td>
<td>incremental transfer</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AXFR</code></pre></td>
<td><pre><code>252 - 0xFC</code></pre></td>
<td>transfer of an entire zone</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MAILB</code></pre></td>
<td><pre><code>253 - 0xFD</code></pre></td>
<td>mailbox-related RRs (MB, MG or MR)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>MAILA</code></pre></td>
<td><pre><code>254 - 0xFE</code></pre></td>
<td>mail agent RRs (Obsolete - see MX)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>*</code></pre></td>
<td><pre><code>255 - 0xFF</code></pre></td>
<td>A request for all records</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>URI</code></pre></td>
<td><pre><code>256 - 0x100</code></pre></td>
<td>URI</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>CAA</code></pre></td>
<td><pre><code>257 - 0x101</code></pre></td>
<td>Certification Authority Authorization</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TA</code></pre></td>
<td><pre><code>32768 - 0x8000</code></pre></td>
<td>DNSSEC Trust Authorities</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DLV</code></pre></td>
<td><pre><code>32769 - 0x8001</code></pre></td>
<td>DNSSEC Lookaside Validation</td>
</tr>
</tbody>
</table>

### Type [encryption](#type-encryption)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Off</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Off stream</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Basic</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Basic stream</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Rc5</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
</tbody>
</table>

### Type [ethernetprotocol](#type-ethernetprotocol)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>XEROX PUP</code></pre></td>
<td><pre><code>512 - 0x200</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PUP Addr Trans</code></pre></td>
<td><pre><code>513 - 0x201</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Nixdorf (conflicts with 802.3 Length Field)</code></pre></td>
<td><pre><code>1024 - 0x400</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ethernet II</code></pre></td>
<td><pre><code>1528 - 0x5F8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>XEROX NS IDP</code></pre></td>
<td><pre><code>1536 - 0x600</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>XNS Address Translation</code></pre></td>
<td><pre><code>1537 - 0x601</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DLog</code></pre></td>
<td><pre><code>1632 - 0x660</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DLog</code></pre></td>
<td><pre><code>1633 - 0x661</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv4</code></pre></td>
<td><pre><code>2048 - 0x800</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Valid Systems</code></pre></td>
<td><pre><code>2049 - 0x801</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NBS Internet</code></pre></td>
<td><pre><code>2050 - 0x802</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ECMA Internet</code></pre></td>
<td><pre><code>2051 - 0x803</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Chaosnet</code></pre></td>
<td><pre><code>2052 - 0x804</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>X.25 Level 3</code></pre></td>
<td><pre><code>2053 - 0x805</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ARP</code></pre></td>
<td><pre><code>2054 - 0x806</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>XNS Compatability</code></pre></td>
<td><pre><code>2055 - 0x807</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Frame Relay ARP</code></pre></td>
<td><pre><code>2056 - 0x808</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Symbolics Private</code></pre></td>
<td><pre><code>2076 - 0x81C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wake-on-LAN (WOL)</code></pre></td>
<td><pre><code>2114 - 0x842</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>2184 - 0x888</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>2185 - 0x889</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>2186 - 0x88A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>WiMax Mac to Mac Packet</code></pre></td>
<td><pre><code>2288 - 0x8F0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>G8BPQ AX.25 over Ethernet</code></pre></td>
<td><pre><code>2303 - 0x8FF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass net debugr</code></pre></td>
<td><pre><code>2304 - 0x900</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Xerox IEEE802.3 PUP</code></pre></td>
<td><pre><code>2560 - 0xA00</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PUP Addr Trans</code></pre></td>
<td><pre><code>2561 - 0xA01</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Banyan VINES</code></pre></td>
<td><pre><code>2989 - 0xBAD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>VINES Loopback</code></pre></td>
<td><pre><code>2990 - 0xBAE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>VINES Echo</code></pre></td>
<td><pre><code>2991 - 0xBAF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Berkeley Trailer nego</code></pre></td>
<td><pre><code>4096 - 0x1000</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Berkeley Trailer encap/IP</code></pre></td>
<td><pre><code>4097 - 0x1001</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DCA - Multicast</code></pre></td>
<td><pre><code>4660 - 0x1234</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Valid Systems</code></pre></td>
<td><pre><code>5632 - 0x1600</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TRAIL - MS Network Monitor Summary Packet</code></pre></td>
<td><pre><code>6532 - 0x1984</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Artificial Horizons</code></pre></td>
<td><pre><code>6537 - 0x1989</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datapoint Corporation</code></pre></td>
<td><pre><code>6549 - 0x1995</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Cisco Group Multicast Protocol (CGMP)</code></pre></td>
<td><pre><code>8193 - 0x2001</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>GigaSMART Headers</code></pre></td>
<td><pre><code>8933 - 0x22E5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multiple Stream Reservation Protocol (MSRP)</code></pre></td>
<td><pre><code>8938 - 0x22EA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Audio Video Bridging Transport Protocol (AVBTP)</code></pre></td>
<td><pre><code>8944 - 0x22F0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Robust Header Compression (ROHC)</code></pre></td>
<td><pre><code>8945 - 0x22F1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Transparent Interconnection of Lots of Links (TRILL)</code></pre></td>
<td><pre><code>8947 - 0x22F3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Intermediate System to Intermediate System</code></pre></td>
<td><pre><code>8948 - 0x22F4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Intel Centrino Promiscuous Packets</code></pre></td>
<td><pre><code>9298 - 0x2452</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Virtual Circuit Datagram</code></pre></td>
<td><pre><code>15360 - 0x3C00</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP System Control Datagram</code></pre></td>
<td><pre><code>15361 - 0x3C01</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Connect Request (Virtual CCT)</code></pre></td>
<td><pre><code>15362 - 0x3C02</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Connect Response</code></pre></td>
<td><pre><code>15363 - 0x3C03</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Connect Complete</code></pre></td>
<td><pre><code>15364 - 0x3C04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Close Request (Virtual CCT)</code></pre></td>
<td><pre><code>15365 - 0x3C05</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Close Response</code></pre></td>
<td><pre><code>15366 - 0x3C06</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Datagram</code></pre></td>
<td><pre><code>15367 - 0x3C07</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Datagram Broadcast</code></pre></td>
<td><pre><code>15368 - 0x3C08</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Claim NetBIOS Name</code></pre></td>
<td><pre><code>15369 - 0x3C09</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Delete Netbios Name</code></pre></td>
<td><pre><code>15370 - 0x3C0A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Remote Adaptor Status Request</code></pre></td>
<td><pre><code>15371 - 0x3C0B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Remote Adaptor Response</code></pre></td>
<td><pre><code>15372 - 0x3C0C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com NBP Reset</code></pre></td>
<td><pre><code>15373 - 0x3C0D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ethernet Powerlink (EPL v1)</code></pre></td>
<td><pre><code>15935 - 0x3E3F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PCS Basic Block Protocol</code></pre></td>
<td><pre><code>16962 - 0x4242</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Information Modes Little Big LAN Diagnostic</code></pre></td>
<td><pre><code>16972 - 0x424C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>THD - Diddle</code></pre></td>
<td><pre><code>17185 - 0x4321</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Information Modes Little Big LAN</code></pre></td>
<td><pre><code>19522 - 0x4C42</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BBN Simnet</code></pre></td>
<td><pre><code>21000 - 0x5208</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Unassigned</code></pre></td>
<td><pre><code>24576 - 0x6000</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Maintenance Operation Protocol (MOP)</code></pre></td>
<td><pre><code>24577 - 0x6001</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Maintenance Operation Protocol (MOP)</code></pre></td>
<td><pre><code>24578 - 0x6002</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DECNET Phase IV</code></pre></td>
<td><pre><code>24579 - 0x6003</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Local Area Transport (LAT)</code></pre></td>
<td><pre><code>24580 - 0x6004</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Diagnostic Protocol</code></pre></td>
<td><pre><code>24581 - 0x6005</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Customer Protocol</code></pre></td>
<td><pre><code>24582 - 0x6006</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Local Area VAX Cluster (LAVC)</code></pre></td>
<td><pre><code>24583 - 0x6007</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC AMBER</code></pre></td>
<td><pre><code>24584 - 0x6008</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC MUMPS</code></pre></td>
<td><pre><code>24585 - 0x6009</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com Corporation</code></pre></td>
<td><pre><code>24592 - 0x6010</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com Corporation</code></pre></td>
<td><pre><code>24593 - 0x6011</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com Corporation</code></pre></td>
<td><pre><code>24594 - 0x6012</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com Corporation</code></pre></td>
<td><pre><code>24595 - 0x6013</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com Corporation</code></pre></td>
<td><pre><code>24596 - 0x6014</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Trans Ether Bridging</code></pre></td>
<td><pre><code>25944 - 0x6558</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Raw Frame Relay</code></pre></td>
<td><pre><code>25945 - 0x6559</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass download</code></pre></td>
<td><pre><code>28672 - 0x7000</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass NIUs</code></pre></td>
<td><pre><code>28673 - 0x7001</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass dia/loop</code></pre></td>
<td><pre><code>28674 - 0x7002</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass (NMC to/from UB Bridge)</code></pre></td>
<td><pre><code>28675 - 0x7003</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ungermann-Bass Bridge Spanning Tree</code></pre></td>
<td><pre><code>28676 - 0x7004</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OS/9 Microware</code></pre></td>
<td><pre><code>28679 - 0x7007</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>OS/9 Net</code></pre></td>
<td><pre><code>28681 - 0x7009</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28704 - 0x7020</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28705 - 0x7021</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28706 - 0x7022</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28707 - 0x7023</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28708 - 0x7024</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28709 - 0x7025</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28710 - 0x7026</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28711 - 0x7027</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28712 - 0x7028</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Sintrom (was LRT - England)</code></pre></td>
<td><pre><code>28713 - 0x7029</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Proteon</code></pre></td>
<td><pre><code>28720 - 0x7030</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Prime NTS (Network Terminal Service)</code></pre></td>
<td><pre><code>28721 - 0x7031</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Cabletron</code></pre></td>
<td><pre><code>28724 - 0x7034</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Cronus VLN</code></pre></td>
<td><pre><code>32771 - 0x8003</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Cronus Direct</code></pre></td>
<td><pre><code>32772 - 0x8004</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HP Probe</code></pre></td>
<td><pre><code>32773 - 0x8005</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Nestar</code></pre></td>
<td><pre><code>32774 - 0x8006</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AT&amp;T</code></pre></td>
<td><pre><code>32776 - 0x8008</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Excelan</code></pre></td>
<td><pre><code>32784 - 0x8010</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SGI diagnostics</code></pre></td>
<td><pre><code>32787 - 0x8013</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SGI network games</code></pre></td>
<td><pre><code>32788 - 0x8014</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SGI reserved</code></pre></td>
<td><pre><code>32789 - 0x8015</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SGI bounce server</code></pre></td>
<td><pre><code>32790 - 0x8016</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apollo Domain</code></pre></td>
<td><pre><code>32793 - 0x8019</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Tymshare</code></pre></td>
<td><pre><code>32815 - 0x802F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Tigan, Inc.</code></pre></td>
<td><pre><code>32816 - 0x8030</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reverse ARP</code></pre></td>
<td><pre><code>32821 - 0x8035</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Aeonic Systems</code></pre></td>
<td><pre><code>32822 - 0x8036</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPX (Novell Netware)</code></pre></td>
<td><pre><code>32823 - 0x8037</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC LANBridge Management</code></pre></td>
<td><pre><code>32824 - 0x8038</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC DSM/DDP</code></pre></td>
<td><pre><code>32825 - 0x8039</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Argonaut Console</code></pre></td>
<td><pre><code>32826 - 0x803A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC VAXELN</code></pre></td>
<td><pre><code>32827 - 0x803B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC DNS Naming Service</code></pre></td>
<td><pre><code>32828 - 0x803C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Ethernet CSMA/CD Encryption Protocol</code></pre></td>
<td><pre><code>32829 - 0x803D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Distributed Time Service</code></pre></td>
<td><pre><code>32830 - 0x803E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC LAN Traffic Monitor Protocol</code></pre></td>
<td><pre><code>32831 - 0x803F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC PATHWORKS DECnet NETBIOS Emulation</code></pre></td>
<td><pre><code>32832 - 0x8040</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DEC Local Area System Transport</code></pre></td>
<td><pre><code>32833 - 0x8041</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC unassigned</code></pre></td>
<td><pre><code>32834 - 0x8042</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Planning Research Corp.</code></pre></td>
<td><pre><code>32836 - 0x8044</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AT&amp;T</code></pre></td>
<td><pre><code>32838 - 0x8046</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AT&amp;T</code></pre></td>
<td><pre><code>32839 - 0x8047</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DEC Availability Manager</code></pre></td>
<td><pre><code>32840 - 0x8048</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ExperData</code></pre></td>
<td><pre><code>32841 - 0x8049</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>VMTP (Versatile Message Transaction Protocol)</code></pre></td>
<td><pre><code>32859 - 0x805B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Stanford V Kernel prod.</code></pre></td>
<td><pre><code>32860 - 0x805C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Evans &amp; Sutherland</code></pre></td>
<td><pre><code>32861 - 0x805D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Little Machines</code></pre></td>
<td><pre><code>32864 - 0x8060</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Counterpoint Computers</code></pre></td>
<td><pre><code>32866 - 0x8062</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Univ. of Mass. @ Amherst</code></pre></td>
<td><pre><code>32869 - 0x8065</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Univ. of Mass. @ Amherst</code></pre></td>
<td><pre><code>32870 - 0x8066</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Veeco Integrated Auto.</code></pre></td>
<td><pre><code>32871 - 0x8067</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>General Dynamics</code></pre></td>
<td><pre><code>32872 - 0x8068</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>AT&amp;T</code></pre></td>
<td><pre><code>32873 - 0x8069</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Autophon</code></pre></td>
<td><pre><code>32874 - 0x806A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ComDesign</code></pre></td>
<td><pre><code>32876 - 0x806C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computgraphic Corp.</code></pre></td>
<td><pre><code>32877 - 0x806D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32878 - 0x806E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32879 - 0x806F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32880 - 0x8070</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32881 - 0x8071</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32882 - 0x8072</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32883 - 0x8073</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32884 - 0x8074</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32885 - 0x8075</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32886 - 0x8076</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landmark Graphics Corporation</code></pre></td>
<td><pre><code>32887 - 0x8077</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Matra</code></pre></td>
<td><pre><code>32890 - 0x807A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Dansk Data Elektronik</code></pre></td>
<td><pre><code>32891 - 0x807B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Merit Internodal</code></pre></td>
<td><pre><code>32892 - 0x807C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Vitalink Communications</code></pre></td>
<td><pre><code>32893 - 0x807D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Vitalink Communications</code></pre></td>
<td><pre><code>32894 - 0x807E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Vitalink Communications</code></pre></td>
<td><pre><code>32895 - 0x807F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Vitalink TransLAN III</code></pre></td>
<td><pre><code>32896 - 0x8080</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Counterpoint Computers</code></pre></td>
<td><pre><code>32897 - 0x8081</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Counterpoint Computers</code></pre></td>
<td><pre><code>32898 - 0x8082</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Counterpoint Computers</code></pre></td>
<td><pre><code>32899 - 0x8083</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>32904 - 0x8088</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>32906 - 0x808A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ethertalk (AppleTalk over Ethernet)</code></pre></td>
<td><pre><code>32923 - 0x809B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32924 - 0x809C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32925 - 0x809D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32926 - 0x809E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Spider Systems Ltd.</code></pre></td>
<td><pre><code>32927 - 0x809F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Nixdorf Computers</code></pre></td>
<td><pre><code>32931 - 0x80A3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32932 - 0x80A4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32933 - 0x80A5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32934 - 0x80A6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32935 - 0x80A7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32936 - 0x80A8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32937 - 0x80A9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32938 - 0x80AA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32939 - 0x80AB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32940 - 0x80AC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32941 - 0x80AD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32942 - 0x80AE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32943 - 0x80AF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32944 - 0x80B0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32945 - 0x80B1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32946 - 0x80B2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Siemens Gammasonics Inc.</code></pre></td>
<td><pre><code>32947 - 0x80B3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DCA Data Exchange Cluster</code></pre></td>
<td><pre><code>32960 - 0x80C0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DCA Data Exchange Cluster</code></pre></td>
<td><pre><code>32961 - 0x80C1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DCA Data Exchange Cluster</code></pre></td>
<td><pre><code>32962 - 0x80C2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DCA Data Exchange Cluster</code></pre></td>
<td><pre><code>32963 - 0x80C3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Banyan Systems</code></pre></td>
<td><pre><code>32964 - 0x80C4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Banyan Systems</code></pre></td>
<td><pre><code>32965 - 0x80C5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Pacer Software</code></pre></td>
<td><pre><code>32966 - 0x80C6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Applitek Corporation</code></pre></td>
<td><pre><code>32967 - 0x80C7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Intergraph Corporation</code></pre></td>
<td><pre><code>32968 - 0x80C8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Intergraph Corporation</code></pre></td>
<td><pre><code>32969 - 0x80C9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Intergraph Corporation</code></pre></td>
<td><pre><code>32970 - 0x80CA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Intergraph Corporation</code></pre></td>
<td><pre><code>32971 - 0x80CB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Intergraph Corporation</code></pre></td>
<td><pre><code>32972 - 0x80CC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Harris Corporation</code></pre></td>
<td><pre><code>32973 - 0x80CD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Harris Corporation</code></pre></td>
<td><pre><code>32974 - 0x80CE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taylor Instrument</code></pre></td>
<td><pre><code>32975 - 0x80CF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taylor Instrument</code></pre></td>
<td><pre><code>32976 - 0x80D0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taylor Instrument</code></pre></td>
<td><pre><code>32977 - 0x80D1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taylor Instrument</code></pre></td>
<td><pre><code>32978 - 0x80D2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Rosemount Corporation</code></pre></td>
<td><pre><code>32979 - 0x80D3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Rosemount Corporation</code></pre></td>
<td><pre><code>32980 - 0x80D4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IBM SNA Service on Ether</code></pre></td>
<td><pre><code>32981 - 0x80D5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Varian Associates</code></pre></td>
<td><pre><code>32989 - 0x80DD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Transparent Remote File System (TRFS)</code></pre></td>
<td><pre><code>32990 - 0x80DE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Transparent Remote File System (TRFS)</code></pre></td>
<td><pre><code>32991 - 0x80DF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Allen-Bradley</code></pre></td>
<td><pre><code>32992 - 0x80E0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Allen-Bradley</code></pre></td>
<td><pre><code>32993 - 0x80E1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Allen-Bradley</code></pre></td>
<td><pre><code>32994 - 0x80E2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Allen-Bradley</code></pre></td>
<td><pre><code>32995 - 0x80E3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32996 - 0x80E4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32997 - 0x80E5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32998 - 0x80E6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>32999 - 0x80E7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33000 - 0x80E8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33001 - 0x80E9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33002 - 0x80EA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33003 - 0x80EB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33004 - 0x80EC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33005 - 0x80ED</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33006 - 0x80EE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33007 - 0x80EF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datability</code></pre></td>
<td><pre><code>33008 - 0x80F0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Retix</code></pre></td>
<td><pre><code>33010 - 0x80F2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>AppleTalk AARP (Kinetics)</code></pre></td>
<td><pre><code>33011 - 0x80F3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Kinetics</code></pre></td>
<td><pre><code>33012 - 0x80F4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Kinetics</code></pre></td>
<td><pre><code>33013 - 0x80F5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apollo Computer</code></pre></td>
<td><pre><code>33015 - 0x80F7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wellfleet Communications</code></pre></td>
<td><pre><code>33023 - 0x80FF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IEEE 802.1Q VLAN-tagged</code></pre></td>
<td><pre><code>33024 - 0x8100</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wellfleet Communications</code></pre></td>
<td><pre><code>33025 - 0x8101</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Wellfleet - BOFL (Breath Of Life)</code></pre></td>
<td><pre><code>33026 - 0x8102</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wellfleet Communications</code></pre></td>
<td><pre><code>33027 - 0x8103</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Symbolics Private</code></pre></td>
<td><pre><code>33031 - 0x8107</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Symbolics Private</code></pre></td>
<td><pre><code>33032 - 0x8108</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Symbolics Private</code></pre></td>
<td><pre><code>33033 - 0x8109</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Talaris</code></pre></td>
<td><pre><code>33067 - 0x812B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Hayes Microcomputers</code></pre></td>
<td><pre><code>33072 - 0x8130</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>VG Laboratory Systems</code></pre></td>
<td><pre><code>33073 - 0x8131</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Bridge Communications</code></pre></td>
<td><pre><code>33074 - 0x8132</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Juniper NetScreen Redundancy Protocol (NSRP v2)</code></pre></td>
<td><pre><code>33075 - 0x8133</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Bridge Communications</code></pre></td>
<td><pre><code>33076 - 0x8134</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bridge Communications</code></pre></td>
<td><pre><code>33077 - 0x8135</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Bridge Communications</code></pre></td>
<td><pre><code>33078 - 0x8136</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPX - NetWare</code></pre></td>
<td><pre><code>33079 - 0x8137</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPX - Novell</code></pre></td>
<td><pre><code>33080 - 0x8138</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KTI</code></pre></td>
<td><pre><code>33081 - 0x8139</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KTI</code></pre></td>
<td><pre><code>33082 - 0x813A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KTI</code></pre></td>
<td><pre><code>33083 - 0x813B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>KTI</code></pre></td>
<td><pre><code>33084 - 0x813C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>KTI</code></pre></td>
<td><pre><code>33085 - 0x813D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>M/MUMPS Data Sharing</code></pre></td>
<td><pre><code>33087 - 0x813F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Amoeba 4 RPC - Vrije Universiteit (NL)</code></pre></td>
<td><pre><code>33093 - 0x8145</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Fast Local Internet Protocol (FLIP)</code></pre></td>
<td><pre><code>33094 - 0x8146</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Vrije Universiteit (NL)</code></pre></td>
<td><pre><code>33095 - 0x8147</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Logicraft</code></pre></td>
<td><pre><code>33096 - 0x8148</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Network Computing Devices</code></pre></td>
<td><pre><code>33097 - 0x8149</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Alpha Micro</code></pre></td>
<td><pre><code>33098 - 0x814A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SNMP over Eth.</code></pre></td>
<td><pre><code>33100 - 0x814C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BIIN</code></pre></td>
<td><pre><code>33101 - 0x814D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>BIIN 814F Technically Elite Concepts</code></pre></td>
<td><pre><code>33102 - 0x814E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Technically Elite Concepts</code></pre></td>
<td><pre><code>33103 - 0x814F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Rational Corp</code></pre></td>
<td><pre><code>33104 - 0x8150</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33105 - 0x8151</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33106 - 0x8152</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33107 - 0x8153</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computer Protocol Pty Ltd</code></pre></td>
<td><pre><code>33116 - 0x815C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Protocol Pty Ltd</code></pre></td>
<td><pre><code>33117 - 0x815D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computer Protocol Pty Ltd</code></pre></td>
<td><pre><code>33118 - 0x815E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33124 - 0x8164</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33125 - 0x8165</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33126 - 0x8166</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>XTP</code></pre></td>
<td><pre><code>33149 - 0x817D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SGI/Time Warner Proprietary</code></pre></td>
<td><pre><code>33150 - 0x817E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>High-Performance Parallel Interface-Framing (HIPPI-FP)</code></pre></td>
<td><pre><code>33152 - 0x8180</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>High-Performance Parallel Interface-Scheduled Transfer (HIPPI-STP)</code></pre></td>
<td><pre><code>33153 - 0x8181</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved for HIPPI-6400</code></pre></td>
<td><pre><code>33154 - 0x8182</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved for HIPPI-6400</code></pre></td>
<td><pre><code>33155 - 0x8183</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33156 - 0x8184</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33157 - 0x8185</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33158 - 0x8186</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33159 - 0x8187</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33160 - 0x8188</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33161 - 0x8189</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33162 - 0x818A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33163 - 0x818B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Silicon Graphics Proprietary</code></pre></td>
<td><pre><code>33164 - 0x818C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Motorola Computer</code></pre></td>
<td><pre><code>33165 - 0x818D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PowerLAN / NetBIOS/NetBEUI (PC)</code></pre></td>
<td><pre><code>33169 - 0x8191</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33178 - 0x819A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33179 - 0x819B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33180 - 0x819C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33181 - 0x819D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33182 - 0x819E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33183 - 0x819F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33184 - 0x81A0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33185 - 0x81A1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33186 - 0x81A2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Qualcomm</code></pre></td>
<td><pre><code>33187 - 0x81A3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ARAI Bunkichi</code></pre></td>
<td><pre><code>33188 - 0x81A4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RAD Network Devices</code></pre></td>
<td><pre><code>33189 - 0x81A5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RAD Network Devices</code></pre></td>
<td><pre><code>33198 - 0x81AE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>33207 - 0x81B7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>33208 - 0x81B8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Xyplex</code></pre></td>
<td><pre><code>33209 - 0x81B9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33228 - 0x81CC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33229 - 0x81CD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33230 - 0x81CE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33231 - 0x81CF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33232 - 0x81D0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33233 - 0x81D1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33234 - 0x81D2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33235 - 0x81D3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33236 - 0x81D4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Apricot Computers</code></pre></td>
<td><pre><code>33237 - 0x81D5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33238 - 0x81D6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33239 - 0x81D7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33240 - 0x81D8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33241 - 0x81D9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33242 - 0x81DA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33243 - 0x81DB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33244 - 0x81DC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Artisoft Lantastic</code></pre></td>
<td><pre><code>33245 - 0x81DD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33254 - 0x81E6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33255 - 0x81E7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33256 - 0x81E8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33257 - 0x81E9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33258 - 0x81EA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33259 - 0x81EB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33260 - 0x81EC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33261 - 0x81ED</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33262 - 0x81EE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Polygon</code></pre></td>
<td><pre><code>33263 - 0x81EF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Comsat Labs</code></pre></td>
<td><pre><code>33264 - 0x81F0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Comsat Labs</code></pre></td>
<td><pre><code>33265 - 0x81F1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Comsat Labs</code></pre></td>
<td><pre><code>33266 - 0x81F2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SAIC</code></pre></td>
<td><pre><code>33267 - 0x81F3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SAIC</code></pre></td>
<td><pre><code>33268 - 0x81F4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SAIC</code></pre></td>
<td><pre><code>33269 - 0x81F5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>VG Analytical</code></pre></td>
<td><pre><code>33270 - 0x81F6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>VG Analytical</code></pre></td>
<td><pre><code>33271 - 0x81F7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>VG Analytical</code></pre></td>
<td><pre><code>33272 - 0x81F8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Cabletron InterSwitch Message Protocol</code></pre></td>
<td><pre><code>33277 - 0x81FD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Cabletron InterSwitch Message Protocol</code></pre></td>
<td><pre><code>33279 - 0x81FF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>QNX QNet Software Systems Ltd.</code></pre></td>
<td><pre><code>33283 - 0x8203</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>QNX QNet Software Systems Ltd.</code></pre></td>
<td><pre><code>33284 - 0x8204</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>QNX QNet Software Systems Ltd.</code></pre></td>
<td><pre><code>33285 - 0x8205</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ascom Banking Systems</code></pre></td>
<td><pre><code>33313 - 0x8221</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ascom Banking Systems</code></pre></td>
<td><pre><code>33314 - 0x8222</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Advanced Encryption System</code></pre></td>
<td><pre><code>33342 - 0x823E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Advanced Encryption System</code></pre></td>
<td><pre><code>33343 - 0x823F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Advanced Encryption System</code></pre></td>
<td><pre><code>33344 - 0x8240</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33379 - 0x8263</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33380 - 0x8264</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33381 - 0x8265</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33382 - 0x8266</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33383 - 0x8267</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33384 - 0x8268</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33385 - 0x8269</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Charles River Data System</code></pre></td>
<td><pre><code>33386 - 0x826A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Athena Programming</code></pre></td>
<td><pre><code>33407 - 0x827F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Athena Programming</code></pre></td>
<td><pre><code>33408 - 0x8280</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Athena Programming</code></pre></td>
<td><pre><code>33409 - 0x8281</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Athena Programming</code></pre></td>
<td><pre><code>33410 - 0x8282</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Institute for Industrial Information Tech. Ltd</code></pre></td>
<td><pre><code>33434 - 0x829A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Institute for Industrial Information Tech. Ltd</code></pre></td>
<td><pre><code>33435 - 0x829B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33436 - 0x829C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33437 - 0x829D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33438 - 0x829E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33439 - 0x829F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33440 - 0x82A0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33441 - 0x82A1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33442 - 0x82A2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33443 - 0x82A3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33444 - 0x82A4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33445 - 0x82A5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33446 - 0x82A6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33447 - 0x82A7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33448 - 0x82A8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33449 - 0x82A9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33450 - 0x82AA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Taurus Controls</code></pre></td>
<td><pre><code>33451 - 0x82AB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Accton Technologies</code></pre></td>
<td><pre><code>33680 - 0x8390</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Talaris Multicast</code></pre></td>
<td><pre><code>34091 - 0x852B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Kalpana</code></pre></td>
<td><pre><code>34178 - 0x8582</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34452 - 0x8694</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34453 - 0x8695</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34454 - 0x8696</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34455 - 0x8697</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34456 - 0x8698</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34457 - 0x8699</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34458 - 0x869A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34459 - 0x869B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34460 - 0x869C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Idea Courier</code></pre></td>
<td><pre><code>34461 - 0x869D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Network Tech</code></pre></td>
<td><pre><code>34462 - 0x869E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computer Network Tech</code></pre></td>
<td><pre><code>34463 - 0x869F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Computer Network Tech</code></pre></td>
<td><pre><code>34464 - 0x86A0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Computer Network Tech</code></pre></td>
<td><pre><code>34465 - 0x86A1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34467 - 0x86A3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34468 - 0x86A4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34469 - 0x86A5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34470 - 0x86A6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34471 - 0x86A7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34472 - 0x86A8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34473 - 0x86A9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34474 - 0x86AA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34475 - 0x86AB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Communications</code></pre></td>
<td><pre><code>34476 - 0x86AC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SECTRA</code></pre></td>
<td><pre><code>34523 - 0x86DB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6</code></pre></td>
<td><pre><code>34525 - 0x86DD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Delta Controls</code></pre></td>
<td><pre><code>34526 - 0x86DE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ATOMIC</code></pre></td>
<td><pre><code>34527 - 0x86DF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Landis &amp; Gyr Powers</code></pre></td>
<td><pre><code>34528 - 0x86E0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Landis &amp; Gyr Powers</code></pre></td>
<td><pre><code>34543 - 0x86EF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Motorola</code></pre></td>
<td><pre><code>34560 - 0x8700</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Motorola</code></pre></td>
<td><pre><code>34576 - 0x8710</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Cisco Wireless Lan Context Control Protocol (WLCCP)</code></pre></td>
<td><pre><code>34605 - 0x872D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Control Technology Inc. - RDP Without IP</code></pre></td>
<td><pre><code>34617 - 0x8739</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Control Technology Inc. - Multicast </code></pre></td>
<td><pre><code>34618 - 0x873A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Control Technology Inc. - Proprietary</code></pre></td>
<td><pre><code>34619 - 0x873B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Control Technology Inc. - Proprietary</code></pre></td>
<td><pre><code>34620 - 0x873C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TCP/IP Compression</code></pre></td>
<td><pre><code>34667 - 0x876B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IP Autonomous Systems</code></pre></td>
<td><pre><code>34668 - 0x876C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Secure Data</code></pre></td>
<td><pre><code>34669 - 0x876D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Symbol Technologies</code></pre></td>
<td><pre><code>34688 - 0x8780</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Motorola Protocol, Roaming  Updates between Access Points </code></pre></td>
<td><pre><code>34689 - 0x8781</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Motorola Protocol, Access Point Adoption, extended VLANs and Clustering</code></pre></td>
<td><pre><code>34691 - 0x8783</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ethernet Flow Control / Ethernet Passive Optical Network (EPON)</code></pre></td>
<td><pre><code>34824 - 0x8808</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ethernet OAM Protocol IEEE 802.3ah (a.k.a.: Slow Protocols)</code></pre></td>
<td><pre><code>34825 - 0x8809</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Point-to-Point Protocol (PPP)</code></pre></td>
<td><pre><code>34827 - 0x880B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>General Switch Management Protocol (GSMP)</code></pre></td>
<td><pre><code>34828 - 0x880C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Cirrus CobraNet</code></pre></td>
<td><pre><code>34841 - 0x8819</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Hitachi Cable (Optoelectronic Systems Laboratory)</code></pre></td>
<td><pre><code>34848 - 0x8820</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Web-cache Coordination Protocol</code></pre></td>
<td><pre><code>34878 - 0x883E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multi-Protocol Label Switching (MPLS) Unicast </code></pre></td>
<td><pre><code>34887 - 0x8847</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Multi-Protocol Label Switching (MPLS) Multicast</code></pre></td>
<td><pre><code>34888 - 0x8848</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Axis Communications AB - Proprietary</code></pre></td>
<td><pre><code>34902 - 0x8856</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Foundry Proprietary Protocol</code></pre></td>
<td><pre><code>34906 - 0x885A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multicast Channel Allocation Protocol (MCAP)</code></pre></td>
<td><pre><code>34913 - 0x8861</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PPP Over Ethernet (PPPoE) Discovery Stage</code></pre></td>
<td><pre><code>34915 - 0x8863</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PPP Over Ethernet (PPPoE) Session Stage</code></pre></td>
<td><pre><code>34916 - 0x8864</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Intel ANS (NIC Teaming)</code></pre></td>
<td><pre><code>34925 - 0x886D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Microsoft Network Load Balancing Hearbeat</code></pre></td>
<td><pre><code>34927 - 0x886F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Jumbo Frames</code></pre></td>
<td><pre><code>34928 - 0x8870</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HomePlug 1.0 MME</code></pre></td>
<td><pre><code>34939 - 0x887B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Byte Stream Protocol for IP based micro-mobility bearer interfaces (A10)</code></pre></td>
<td><pre><code>34945 - 0x8881</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Frame-based ATM Transport over Ethernet</code></pre></td>
<td><pre><code>34948 - 0x8884</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HP LanProbe Test</code></pre></td>
<td><pre><code>34952 - 0x8888</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EAP over LAN - Authentication (IEEE 802.1X)</code></pre></td>
<td><pre><code>34958 - 0x888E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PROFIBUS PROFINET Protocol</code></pre></td>
<td><pre><code>34962 - 0x8892</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Realtek Remote Control Protocol (RRCP)</code></pre></td>
<td><pre><code>34969 - 0x8899</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HyperSCSI (SCSI over Ethernet)</code></pre></td>
<td><pre><code>34970 - 0x889A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CSM_ENCAPS Protocol - Mindspeed Technologies</code></pre></td>
<td><pre><code>34971 - 0x889B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Telkonet Powerline Ethernet</code></pre></td>
<td><pre><code>34977 - 0x88A1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ATA over Ethernet (AoE)</code></pre></td>
<td><pre><code>34978 - 0x88A2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>EtherCAT Protocol</code></pre></td>
<td><pre><code>34980 - 0x88A4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Huawei Technologies / Cluster</code></pre></td>
<td><pre><code>34983 - 0x88A7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Provider Bridging (IEEE 802.1ad) &amp; Shortest Path Bridging IEEE 802.1aq</code></pre></td>
<td><pre><code>34984 - 0x88A8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Ethernet Powerlink, Communication Profile for Real-Time Ethernet (RTE)</code></pre></td>
<td><pre><code>34987 - 0x88AB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>XiMeta Technology Americas Inc. Proprietary </code></pre></td>
<td><pre><code>34989 - 0x88AD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Boardwalk</code></pre></td>
<td><pre><code>34990 - 0x88AE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>WLAN Authentication Infrastructure (WAI) Authentication Protocol</code></pre></td>
<td><pre><code>34996 - 0x88B4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IEEE 802a OUI Extended Ethertype</code></pre></td>
<td><pre><code>34999 - 0x88B7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Generic substation Events - International Electrotechnical Commission - Electrical Substation Automation (IEC-61850)</code></pre></td>
<td><pre><code>35000 - 0x88B8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sampled Value Services - International Electrotechnical Commission</code></pre></td>
<td><pre><code>35002 - 0x88BA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Light Weight Access Point Protocol (LWAPP)</code></pre></td>
<td><pre><code>35003 - 0x88BB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Robust Security Network (RSN) Pre-Authentication - 802.11i </code></pre></td>
<td><pre><code>35015 - 0x88C7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Transparent Inter Process Communication Protocol (TIPC)</code></pre></td>
<td><pre><code>35018 - 0x88CA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Link Layer Discovery Protocol (LLDP)</code></pre></td>
<td><pre><code>35020 - 0x88CC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SERCOS III Real-time Protocol for Motion Control</code></pre></td>
<td><pre><code>35021 - 0x88CD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3rd Generation Partnership Project 2 (3GPP2) for CDMA2000 Access Network Interfaces</code></pre></td>
<td><pre><code>35026 - 0x88D2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Circuit Emulation Services over Ethernet (MEF 8)</code></pre></td>
<td><pre><code>35032 - 0x88D8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Link Layer Topology Discovery (LLTD)</code></pre></td>
<td><pre><code>35033 - 0x88D9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wireless Access in a Vehicle Environment - WAVE Short Message Protocol (WSMP)</code></pre></td>
<td><pre><code>35036 - 0x88DC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>VMware LabManager</code></pre></td>
<td><pre><code>35038 - 0x88DE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HomePlug AV</code></pre></td>
<td><pre><code>35041 - 0x88E1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Media Redundancy Protocol (IEC62439-2)</code></pre></td>
<td><pre><code>35043 - 0x88E3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>MAC security (IEEE 802.1AE)</code></pre></td>
<td><pre><code>35045 - 0x88E5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Provider Backbone Bridge Mac-in-Mac - IEEE 802.1ah</code></pre></td>
<td><pre><code>35047 - 0x88E7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ethernet Local Management Interface (E-LMI)</code></pre></td>
<td><pre><code>35054 - 0x88EE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multiple VLAN Registration Protocol (MVRP) - IEEE 802.1ak</code></pre></td>
<td><pre><code>35061 - 0x88F5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Multiple MAC Registration Protocol (MMRP) - IEEE 802.1ak</code></pre></td>
<td><pre><code>35062 - 0x88F6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Precision Time Protocol over Eth. (PTP v2) - IEEE-1588</code></pre></td>
<td><pre><code>35063 - 0x88F7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Network Controller Sideband Interface (NCSI)</code></pre></td>
<td><pre><code>35064 - 0x88F8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Parallel Redundancy Protocol (IEC62439 Part 3)</code></pre></td>
<td><pre><code>35067 - 0x88FB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Nokia Siemens Networks Flow Layer Internal Protocol (FLIP)</code></pre></td>
<td><pre><code>35073 - 0x8901</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)</code></pre></td>
<td><pre><code>35074 - 0x8902</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Cisco FabricPath Switching - Frame Encapsulation - DCE</code></pre></td>
<td><pre><code>35075 - 0x8903</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Fiber Channel over Ethernet (FCoE)</code></pre></td>
<td><pre><code>35078 - 0x8906</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Wireless LAN - Data Encapsulation (IEEE-802.11)</code></pre></td>
<td><pre><code>35085 - 0x890D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ENEA LINX (Inter Process Communication) IPC Protocol over Ethernet</code></pre></td>
<td><pre><code>35089 - 0x8911</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Fiber Channel over Ethernet (FCoE)- Initialization Protocol</code></pre></td>
<td><pre><code>35092 - 0x8914</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Infiniband Remote Direct Memory Access (RDMA) over Converged Ethernet (RoCE)</code></pre></td>
<td><pre><code>35093 - 0x8915</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Media Independent Handover Protocol</code></pre></td>
<td><pre><code>35095 - 0x8917</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TTEthernet Protocol Control Frame</code></pre></td>
<td><pre><code>35101 - 0x891D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>High-availability Seamless Redundancy (IEC-62439)</code></pre></td>
<td><pre><code>35119 - 0x892F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Invisible Software</code></pre></td>
<td><pre><code>35478 - 0x8A96</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Invisible Software</code></pre></td>
<td><pre><code>35479 - 0x8A97</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Loopback (Configuration Layer 2 Test Protocol)</code></pre></td>
<td><pre><code>36864 - 0x9000</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com (Formerly Bridge Communications), XNS Systems Management</code></pre></td>
<td><pre><code>36865 - 0x9001</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3Com (Formerly Bridge Communications), TCP/IP Systems Management</code></pre></td>
<td><pre><code>36866 - 0x9002</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>3Com (Formerly Bridge Communications), Loopback Detection</code></pre></td>
<td><pre><code>36867 - 0x9003</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RTnet: Real-Time Media Access Control (RTMAC)</code></pre></td>
<td><pre><code>36897 - 0x9021</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RTnet: Real-Time Configuration Protocol (RTCFG)</code></pre></td>
<td><pre><code>36898 - 0x9022</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Q-in-Q / VLAN-tagged frame</code></pre></td>
<td><pre><code>37120 - 0x9100</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Q-in-Q / VLAN-tagged frame</code></pre></td>
<td><pre><code>37376 - 0x9200</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DECNET - Used by VAX 6220 DEBNI</code></pre></td>
<td><pre><code>43690 - 0xAAAA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Veritas Low Latency Transport (LLT)</code></pre></td>
<td><pre><code>51966 - 0xCAFE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Digium Time Division Multiplexing (TDM) over Ethernet (TDMoE)</code></pre></td>
<td><pre><code>53261 - 0xD00D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ethertype Distributed Switch Architecture (DSA)</code></pre></td>
<td><pre><code>56026 - 0xDADA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Sonix Arpeggio</code></pre></td>
<td><pre><code>64245 - 0xFAF5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Cisco Multilayer Director Switches (MDS)</code></pre></td>
<td><pre><code>64764 - 0xFCFC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BBN VITAL-LanBridge cache wakeups</code></pre></td>
<td><pre><code>65280 - 0xFF00</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65281 - 0xFF01</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65282 - 0xFF02</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65283 - 0xFF03</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65284 - 0xFF04</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65285 - 0xFF05</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65286 - 0xFF06</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65287 - 0xFF07</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65288 - 0xFF08</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65289 - 0xFF09</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65290 - 0xFF0A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65291 - 0xFF0B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65292 - 0xFF0C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65293 - 0xFF0D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ISC Bunker Ramo</code></pre></td>
<td><pre><code>65294 - 0xFF0E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved</code></pre></td>
<td><pre><code>65535 - 0xFFFF</code></pre></td>
</tr>
</tbody>
</table>

### Type [httpquerymethod](#type-httpquerymethod)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>GET</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HEAD</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>POST</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CONNECT</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>PUT</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OPTIONS</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TRACE</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>DELETE</code></pre></td>
<td><pre><code>7 - 0x7</code></pre></td>
</tr>
</tbody>
</table>

### Type [httpstatus](#type-httpstatus)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>No response</code></pre></td>
<td><pre><code>None</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Continue</code></pre></td>
<td><pre><code>100 - 0x64</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Switching Protocols</code></pre></td>
<td><pre><code>101 - 0x65</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Processing</code></pre></td>
<td><pre><code>102 - 0x66</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Early Hints</code></pre></td>
<td><pre><code>103 - 0x67</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OK</code></pre></td>
<td><pre><code>200 - 0xC8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Created</code></pre></td>
<td><pre><code>201 - 0xC9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Accepted</code></pre></td>
<td><pre><code>202 - 0xCA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Non-Authoritative Information</code></pre></td>
<td><pre><code>203 - 0xCB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>No Content</code></pre></td>
<td><pre><code>204 - 0xCC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reset Content</code></pre></td>
<td><pre><code>205 - 0xCD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Partial Content</code></pre></td>
<td><pre><code>206 - 0xCE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Multi-Status</code></pre></td>
<td><pre><code>207 - 0xCF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Already Reported</code></pre></td>
<td><pre><code>208 - 0xD0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IM Used</code></pre></td>
<td><pre><code>226 - 0xE2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multiple Choices</code></pre></td>
<td><pre><code>300 - 0x12C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Moved Permanently</code></pre></td>
<td><pre><code>301 - 0x12D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Found</code></pre></td>
<td><pre><code>302 - 0x12E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>See Other</code></pre></td>
<td><pre><code>303 - 0x12F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Not Modified</code></pre></td>
<td><pre><code>304 - 0x130</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Use Proxy</code></pre></td>
<td><pre><code>305 - 0x131</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Switch Proxy</code></pre></td>
<td><pre><code>306 - 0x132</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Temporary Redirect</code></pre></td>
<td><pre><code>307 - 0x133</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Permanent Redirect</code></pre></td>
<td><pre><code>308 - 0x134</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bad Request</code></pre></td>
<td><pre><code>400 - 0x190</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unauthorized</code></pre></td>
<td><pre><code>401 - 0x191</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Payment Required</code></pre></td>
<td><pre><code>402 - 0x192</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Forbidden</code></pre></td>
<td><pre><code>403 - 0x193</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Not Found</code></pre></td>
<td><pre><code>404 - 0x194</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Method Not Allowed</code></pre></td>
<td><pre><code>405 - 0x195</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Not Acceptable</code></pre></td>
<td><pre><code>406 - 0x196</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Proxy Authentication Required</code></pre></td>
<td><pre><code>407 - 0x197</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Request Timeout</code></pre></td>
<td><pre><code>408 - 0x198</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Conflict</code></pre></td>
<td><pre><code>409 - 0x199</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gone</code></pre></td>
<td><pre><code>410 - 0x19A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Length Required</code></pre></td>
<td><pre><code>411 - 0x19B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Precondition Failed</code></pre></td>
<td><pre><code>412 - 0x19C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Request Entity Too Large</code></pre></td>
<td><pre><code>413 - 0x19D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Request-URI Too Long</code></pre></td>
<td><pre><code>414 - 0x19E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unsupported Media Type</code></pre></td>
<td><pre><code>415 - 0x19F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Requested Range Not Satisfiable</code></pre></td>
<td><pre><code>416 - 0x1A0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Expectation Failed</code></pre></td>
<td><pre><code>417 - 0x1A1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>I&#39;m a teapot</code></pre></td>
<td><pre><code>418 - 0x1A2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Misdirected Request</code></pre></td>
<td><pre><code>421 - 0x1A5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Unprocessable Entity</code></pre></td>
<td><pre><code>422 - 0x1A6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Locked</code></pre></td>
<td><pre><code>423 - 0x1A7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Failed Dependency</code></pre></td>
<td><pre><code>424 - 0x1A8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Upgrade Required</code></pre></td>
<td><pre><code>426 - 0x1AA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Precondition Required</code></pre></td>
<td><pre><code>428 - 0x1AC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Too Many Requests</code></pre></td>
<td><pre><code>429 - 0x1AD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Request Header Fields Too Large</code></pre></td>
<td><pre><code>431 - 0x1AF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unavailable For Legal Reasons</code></pre></td>
<td><pre><code>451 - 0x1C3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Internal Server Error</code></pre></td>
<td><pre><code>500 - 0x1F4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Not Implemented</code></pre></td>
<td><pre><code>501 - 0x1F5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bad Gateway</code></pre></td>
<td><pre><code>502 - 0x1F6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Service Unavailable</code></pre></td>
<td><pre><code>503 - 0x1F7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Gateway Timeout</code></pre></td>
<td><pre><code>504 - 0x1F8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HTTP Version Not Supported</code></pre></td>
<td><pre><code>505 - 0x1F9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Variant Also Negotiates</code></pre></td>
<td><pre><code>506 - 0x1FA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Insufficient Storage</code></pre></td>
<td><pre><code>507 - 0x1FB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Loop Detected</code></pre></td>
<td><pre><code>508 - 0x1FC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Not Extended</code></pre></td>
<td><pre><code>510 - 0x1FE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Network Authentication Required</code></pre></td>
<td><pre><code>511 - 0x1FF</code></pre></td>
</tr>
</tbody>
</table>

### Type [httpstatuscategory](#type-httpstatuscategory)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>No response</code></pre></td>
<td><pre><code>None</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Informational (1xx)</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>OK (2xx)</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Multiple Choices (3xx)</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Bad Request (4xx)</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Internal Server Error (5xx)</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
</tbody>
</table>

### Type [icmpmessage](#type-icmpmessage)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Echo Reply</code></pre></td>
<td><pre><code>0:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Network Unreachable</code></pre></td>
<td><pre><code>3:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Host Unreachable</code></pre></td>
<td><pre><code>3:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Protocol Unreachable</code></pre></td>
<td><pre><code>3:2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Port Unreachable</code></pre></td>
<td><pre><code>3:3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Fragmentation Needed and Don&#39;t Fragment was Set</code></pre></td>
<td><pre><code>3:4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Source Route Failed</code></pre></td>
<td><pre><code>3:5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Destination Network Unknown</code></pre></td>
<td><pre><code>3:6</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Destination Host Unknown</code></pre></td>
<td><pre><code>3:7</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Source Host Isolated</code></pre></td>
<td><pre><code>3:8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Communication with Destination Network is Administratively Prohibited</code></pre></td>
<td><pre><code>3:9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Communication with Destination Host is Administratively Prohibited</code></pre></td>
<td><pre><code>3:10</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Destination Network Unreachable for Type of Service</code></pre></td>
<td><pre><code>3:11</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Destination Host Unreachable for Type of Service</code></pre></td>
<td><pre><code>3:12</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Communication Administratively Prohibited</code></pre></td>
<td><pre><code>3:13</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Host Precedence Violation</code></pre></td>
<td><pre><code>3:14</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Precedence cutoff in effect</code></pre></td>
<td><pre><code>3:15</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Source Quench</code></pre></td>
<td><pre><code>4:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Redirect Datagram for the Network (or subnet)</code></pre></td>
<td><pre><code>5:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Redirect Datagram for the Host</code></pre></td>
<td><pre><code>5:1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Redirect Datagram for the Type of Service and Network</code></pre></td>
<td><pre><code>5:2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Redirect Datagram for the Type of Service and Host</code></pre></td>
<td><pre><code>5:3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Alternate Address for Host</code></pre></td>
<td><pre><code>6:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Echo</code></pre></td>
<td><pre><code>8:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Normal router advertisement</code></pre></td>
<td><pre><code>9:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Does not route common traffic</code></pre></td>
<td><pre><code>9:16</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Router Selection</code></pre></td>
<td><pre><code>10:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Time to Live exceeded in Transit</code></pre></td>
<td><pre><code>11:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Fragment Reassembly Time Exceeded</code></pre></td>
<td><pre><code>11:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Pointer indicates the error</code></pre></td>
<td><pre><code>12:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Missing a Required Option</code></pre></td>
<td><pre><code>12:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Bad Length</code></pre></td>
<td><pre><code>12:2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Timestamp</code></pre></td>
<td><pre><code>13:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Timestamp Reply</code></pre></td>
<td><pre><code>14:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Information Request</code></pre></td>
<td><pre><code>15:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Information Reply</code></pre></td>
<td><pre><code>16:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Address Mask Request</code></pre></td>
<td><pre><code>17:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Address Mask Reply</code></pre></td>
<td><pre><code>18:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Security)</code></pre></td>
<td><pre><code>19:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>20:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>21:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>22:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>23:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>24:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>25:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>26:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>27:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>28:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td><pre><code>29:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Traceroute</code></pre></td>
<td><pre><code>30:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datagram Conversion Error</code></pre></td>
<td><pre><code>31:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mobile Host Redirect</code></pre></td>
<td><pre><code>32:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Where-Are-You</code></pre></td>
<td><pre><code>33:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 I-Am-Here</code></pre></td>
<td><pre><code>34:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Mobile Registration Request</code></pre></td>
<td><pre><code>35:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mobile Registration Reply</code></pre></td>
<td><pre><code>36:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SKIP</code></pre></td>
<td><pre><code>39:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Bad SPI</code></pre></td>
<td><pre><code>40:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Authentication Failed</code></pre></td>
<td><pre><code>40:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Decompression Failed</code></pre></td>
<td><pre><code>40:2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Decryption Failed</code></pre></td>
<td><pre><code>40:3</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Need Authentication</code></pre></td>
<td><pre><code>40:4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Need Authorization</code></pre></td>
<td><pre><code>40:5</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Echo Request</code></pre></td>
<td><pre><code>128:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Echo Reply</code></pre></td>
<td><pre><code>129:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Query</code></pre></td>
<td><pre><code>130:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Report</code></pre></td>
<td><pre><code>131:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Done</code></pre></td>
<td><pre><code>132:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Router Solicitation</code></pre></td>
<td><pre><code>133:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Router Advertisement</code></pre></td>
<td><pre><code>134:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Neighbor Solicitation</code></pre></td>
<td><pre><code>135:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Neighbor Advertisement</code></pre></td>
<td><pre><code>136:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Redirect Message</code></pre></td>
<td><pre><code>137:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Command</code></pre></td>
<td><pre><code>138:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Result</code></pre></td>
<td><pre><code>138:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reset</code></pre></td>
<td><pre><code>138:255</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Subject</code></pre></td>
<td><pre><code>139:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Subject or Empty</code></pre></td>
<td><pre><code>139:1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Ipv4 Subject</code></pre></td>
<td><pre><code>139:2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Successful</code></pre></td>
<td><pre><code>140:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Refused</code></pre></td>
<td><pre><code>140:1</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Unknown</code></pre></td>
<td><pre><code>140:2</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Inverse Neighbor Discovery Solicitation Message</code></pre></td>
<td><pre><code>141:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Inverse Neighbor Discovery Advertisement Message</code></pre></td>
<td><pre><code>142:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Home Agent Address Discovery Request Message</code></pre></td>
<td><pre><code>144:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Home Agent Address Discovery Reply Message</code></pre></td>
<td><pre><code>145:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Mobile Prefix Solicitation</code></pre></td>
<td><pre><code>146:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Mobile Prefix Advertisement</code></pre></td>
<td><pre><code>147:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Certification Path Solicitation Message</code></pre></td>
<td><pre><code>148:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Certification Path Advertisement Message</code></pre></td>
<td><pre><code>149:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Advertisement</code></pre></td>
<td><pre><code>151:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Solicitation</code></pre></td>
<td><pre><code>152:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Termination</code></pre></td>
<td><pre><code>153:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>FMIPv6 Messages</code></pre></td>
<td><pre><code>154:0</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RFC3692-style Experiment 1</code></pre></td>
<td><pre><code>253:0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RFC3692-style Experiment 2</code></pre></td>
<td><pre><code>254:0</code></pre></td>
</tr>
</tbody>
</table>

### Type [icmptype](#type-icmptype)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Category</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Echo Reply</code></pre></td>
<td>Message</td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Destination Unreachable</code></pre></td>
<td>Error</td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Source Quench</code></pre></td>
<td>Error</td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Redirect</code></pre></td>
<td>Message</td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Alternate Host Address</code></pre></td>
<td>Message</td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Echo</code></pre></td>
<td>Message</td>
<td><pre><code>8 - 0x8</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Router Advertisement</code></pre></td>
<td>Error</td>
<td><pre><code>9 - 0x9</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Router Selection</code></pre></td>
<td>Error</td>
<td><pre><code>10 - 0xA</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Time Exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>11 - 0xB</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Parameter Problem</code></pre></td>
<td>Error</td>
<td><pre><code>12 - 0xC</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Timestamp</code></pre></td>
<td>Message</td>
<td><pre><code>13 - 0xD</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Timestamp Reply</code></pre></td>
<td>Message</td>
<td><pre><code>14 - 0xE</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Information Request</code></pre></td>
<td>Message</td>
<td><pre><code>15 - 0xF</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Information Reply</code></pre></td>
<td>Message</td>
<td><pre><code>16 - 0x10</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Address Mask Request</code></pre></td>
<td>Message</td>
<td><pre><code>17 - 0x11</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Address Mask Reply</code></pre></td>
<td>Message</td>
<td><pre><code>18 - 0x12</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Security)</code></pre></td>
<td>Error</td>
<td><pre><code>19 - 0x13</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>20 - 0x14</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>21 - 0x15</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>22 - 0x16</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>23 - 0x17</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>24 - 0x18</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>25 - 0x19</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>26 - 0x1A</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>27 - 0x1B</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>28 - 0x1C</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Reserved (for Robustness Experiment)</code></pre></td>
<td>Error</td>
<td><pre><code>29 - 0x1D</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Traceroute</code></pre></td>
<td>Error</td>
<td><pre><code>30 - 0x1E</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Datagram Conversion Error</code></pre></td>
<td>Error</td>
<td><pre><code>31 - 0x1F</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mobile Host Redirect</code></pre></td>
<td>Error</td>
<td><pre><code>32 - 0x20</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Where-Are-You</code></pre></td>
<td>Error</td>
<td><pre><code>33 - 0x21</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 I-Am-Here</code></pre></td>
<td>Error</td>
<td><pre><code>34 - 0x22</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Mobile Registration Request</code></pre></td>
<td>Message</td>
<td><pre><code>35 - 0x23</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mobile Registration Reply</code></pre></td>
<td>Message</td>
<td><pre><code>36 - 0x24</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Skip</code></pre></td>
<td>Error</td>
<td><pre><code>39 - 0x27</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Photuris</code></pre></td>
<td>Error</td>
<td><pre><code>40 - 0x28</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Echo Request</code></pre></td>
<td>Message</td>
<td><pre><code>128 - 0x80</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Echo Reply</code></pre></td>
<td>Message</td>
<td><pre><code>129 - 0x81</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Query</code></pre></td>
<td>Message</td>
<td><pre><code>130 - 0x82</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Report</code></pre></td>
<td>Message</td>
<td><pre><code>131 - 0x83</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Listener Done</code></pre></td>
<td>Message</td>
<td><pre><code>132 - 0x84</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Router Solicitation</code></pre></td>
<td>Message</td>
<td><pre><code>133 - 0x85</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Router Advertisement</code></pre></td>
<td>Message</td>
<td><pre><code>134 - 0x86</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Neighbor Solicitation</code></pre></td>
<td>Message</td>
<td><pre><code>135 - 0x87</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Neighbor Advertisement</code></pre></td>
<td>Message</td>
<td><pre><code>136 - 0x88</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Redirect Message</code></pre></td>
<td>Message</td>
<td><pre><code>137 - 0x89</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Router Renumbering</code></pre></td>
<td>Message</td>
<td><pre><code>138 - 0x8A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ICMPv6 Node Information Query</code></pre></td>
<td>Message</td>
<td><pre><code>139 - 0x8B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ICMPv6 Node Information Response</code></pre></td>
<td>Message</td>
<td><pre><code>140 - 0x8C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Inverse Neighbor Discovery Solicitation Message</code></pre></td>
<td>Message</td>
<td><pre><code>141 - 0x8D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Inverse Neighbor Discovery Advertisement Message</code></pre></td>
<td>Message</td>
<td><pre><code>142 - 0x8E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Home Agent Address Discovery Request Message</code></pre></td>
<td>Message</td>
<td><pre><code>144 - 0x90</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Home Agent Address Discovery Reply Message</code></pre></td>
<td>Message</td>
<td><pre><code>145 - 0x91</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Mobile Prefix Solicitation</code></pre></td>
<td>Message</td>
<td><pre><code>146 - 0x92</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Mobile Prefix Advertisement</code></pre></td>
<td>Message</td>
<td><pre><code>147 - 0x93</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Certification Path Solicitation Message</code></pre></td>
<td>Message</td>
<td><pre><code>148 - 0x94</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Certification Path Advertisement Message</code></pre></td>
<td>Message</td>
<td><pre><code>149 - 0x95</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Advertisement</code></pre></td>
<td>Message</td>
<td><pre><code>151 - 0x97</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Solicitation</code></pre></td>
<td>Message</td>
<td><pre><code>152 - 0x98</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv6 Multicast Router Termination</code></pre></td>
<td>Message</td>
<td><pre><code>153 - 0x99</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FMIPv6 Messages</code></pre></td>
<td>Message</td>
<td><pre><code>154 - 0x9A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RFC3692-style Experiment 1</code></pre></td>
<td>Error</td>
<td><pre><code>253 - 0xFD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RFC3692-style Experiment 2</code></pre></td>
<td>Error</td>
<td><pre><code>254 - 0xFE</code></pre></td>
</tr>
</tbody>
</table>

### Type [ipfamily](#type-ipfamily)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>No IP Address</code></pre></td>
<td><pre><code>None</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>IPv4</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>IPv6</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
</tbody>
</table>

### Type [ipprotocol](#type-ipprotocol)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>icmp</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
<td>Internet control message protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>igmp</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
<td>Internet group management</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ggp</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
<td>Gateway-gateway protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipencap</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
<td>Ip encapsulated in ip</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>st</code></pre></td>
<td><pre><code>5 - 0x5</code></pre></td>
<td>St datagram mode</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>tcp</code></pre></td>
<td><pre><code>6 - 0x6</code></pre></td>
<td>Transmission control protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>cbt</code></pre></td>
<td><pre><code>7 - 0x7</code></pre></td>
<td>Cbt</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>egp</code></pre></td>
<td><pre><code>8 - 0x8</code></pre></td>
<td>Exterior gateway protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>igp</code></pre></td>
<td><pre><code>9 - 0x9</code></pre></td>
<td>Any private interior gateway (used by cisco for igrp)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>bbn-rcc-mon</code></pre></td>
<td><pre><code>10 - 0xA</code></pre></td>
<td>Bbn rcc monitoring</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>nvp-ii</code></pre></td>
<td><pre><code>11 - 0xB</code></pre></td>
<td>Network voice protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>pup</code></pre></td>
<td><pre><code>12 - 0xC</code></pre></td>
<td>Parc universal packet protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>argus</code></pre></td>
<td><pre><code>13 - 0xD</code></pre></td>
<td>Argus</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>emcom</code></pre></td>
<td><pre><code>14 - 0xE</code></pre></td>
<td>Emcon</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>xnet</code></pre></td>
<td><pre><code>15 - 0xF</code></pre></td>
<td>Cross net debugger</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>chaos</code></pre></td>
<td><pre><code>16 - 0x10</code></pre></td>
<td>Chaos</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>udp</code></pre></td>
<td><pre><code>17 - 0x11</code></pre></td>
<td>User datagram protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>mux</code></pre></td>
<td><pre><code>18 - 0x12</code></pre></td>
<td>Multiplexing</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>dcn-meas</code></pre></td>
<td><pre><code>19 - 0x13</code></pre></td>
<td>Dcn measurement subsystems</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>hmp</code></pre></td>
<td><pre><code>20 - 0x14</code></pre></td>
<td>Host monitoring protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>prm</code></pre></td>
<td><pre><code>21 - 0x15</code></pre></td>
<td>Packet radio measurement</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>xns-idp</code></pre></td>
<td><pre><code>22 - 0x16</code></pre></td>
<td>Xerox ns idp</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>trunk-1</code></pre></td>
<td><pre><code>23 - 0x17</code></pre></td>
<td>Trunk-1</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>trunk-2</code></pre></td>
<td><pre><code>24 - 0x18</code></pre></td>
<td>Trunk-2</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>leaf-1</code></pre></td>
<td><pre><code>25 - 0x19</code></pre></td>
<td>Leaf-1</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>leaf-2</code></pre></td>
<td><pre><code>26 - 0x1A</code></pre></td>
<td>Leaf-2</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>rdp</code></pre></td>
<td><pre><code>27 - 0x1B</code></pre></td>
<td>Reliable data protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>irtp</code></pre></td>
<td><pre><code>28 - 0x1C</code></pre></td>
<td>Internet reliable transaction</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>iso-tp4</code></pre></td>
<td><pre><code>29 - 0x1D</code></pre></td>
<td>Iso transport protocol class 4</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>netblt</code></pre></td>
<td><pre><code>30 - 0x1E</code></pre></td>
<td>Bulk data transfer protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>mfe-nsp</code></pre></td>
<td><pre><code>31 - 0x1F</code></pre></td>
<td>Mfe network services protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>merit-inp</code></pre></td>
<td><pre><code>32 - 0x20</code></pre></td>
<td>Merit internodal protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>dccp</code></pre></td>
<td><pre><code>33 - 0x21</code></pre></td>
<td>Datagram congestion control protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>3pc</code></pre></td>
<td><pre><code>34 - 0x22</code></pre></td>
<td>Third party connect protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>idpr</code></pre></td>
<td><pre><code>35 - 0x23</code></pre></td>
<td>Inter-domain policy routing protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>xtp</code></pre></td>
<td><pre><code>36 - 0x24</code></pre></td>
<td>Xpress transfer protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ddp</code></pre></td>
<td><pre><code>37 - 0x25</code></pre></td>
<td>Datagram delivery protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>idpr-cmtp</code></pre></td>
<td><pre><code>38 - 0x26</code></pre></td>
<td>Idpr control message transport</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>tp++</code></pre></td>
<td><pre><code>39 - 0x27</code></pre></td>
<td>Tp++ transport protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>il</code></pre></td>
<td><pre><code>40 - 0x28</code></pre></td>
<td>Il transport protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ipv6</code></pre></td>
<td><pre><code>41 - 0x29</code></pre></td>
<td>Ipv6</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>sdrp</code></pre></td>
<td><pre><code>42 - 0x2A</code></pre></td>
<td>Source demand routing protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ipv6-route</code></pre></td>
<td><pre><code>43 - 0x2B</code></pre></td>
<td>Routing header for ipv6</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipv6-frag</code></pre></td>
<td><pre><code>44 - 0x2C</code></pre></td>
<td>Fragment header for ipv6</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>idrp</code></pre></td>
<td><pre><code>45 - 0x2D</code></pre></td>
<td>Inter-domain routing protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>rsvp</code></pre></td>
<td><pre><code>46 - 0x2E</code></pre></td>
<td>Reservation protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>gre</code></pre></td>
<td><pre><code>47 - 0x2F</code></pre></td>
<td>General routing encapsulation</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>dsr</code></pre></td>
<td><pre><code>48 - 0x30</code></pre></td>
<td>Dynamic source routing protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>bna</code></pre></td>
<td><pre><code>49 - 0x31</code></pre></td>
<td>Bna</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>esp</code></pre></td>
<td><pre><code>50 - 0x32</code></pre></td>
<td>Encap security payload</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ah</code></pre></td>
<td><pre><code>51 - 0x33</code></pre></td>
<td>Authentication header</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>i-nlsp</code></pre></td>
<td><pre><code>52 - 0x34</code></pre></td>
<td>Integrated net layer security tuba</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>swipe</code></pre></td>
<td><pre><code>53 - 0x35</code></pre></td>
<td>Ip with encryption</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>narp</code></pre></td>
<td><pre><code>54 - 0x36</code></pre></td>
<td>Nbma address resolution protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>mobile</code></pre></td>
<td><pre><code>55 - 0x37</code></pre></td>
<td>Ip mobility</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>tlsp</code></pre></td>
<td><pre><code>56 - 0x38</code></pre></td>
<td>Transport layer security protocol using kryptonet key management</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>skip</code></pre></td>
<td><pre><code>57 - 0x39</code></pre></td>
<td>Skip</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipv6-icmp</code></pre></td>
<td><pre><code>58 - 0x3A</code></pre></td>
<td>Icmp for ipv6</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ipv6-nonxt</code></pre></td>
<td><pre><code>59 - 0x3B</code></pre></td>
<td>No next header for ipv6</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipv6-opts</code></pre></td>
<td><pre><code>60 - 0x3C</code></pre></td>
<td>Destination options for ipv6</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>anyhost</code></pre></td>
<td><pre><code>61 - 0x3D</code></pre></td>
<td>Any host internal protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>cftp</code></pre></td>
<td><pre><code>62 - 0x3E</code></pre></td>
<td>Cftp</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>anylan</code></pre></td>
<td><pre><code>63 - 0x3F</code></pre></td>
<td>Any local network</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>sat-expak</code></pre></td>
<td><pre><code>64 - 0x40</code></pre></td>
<td>Satnet and backroom expak</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>kryptolan</code></pre></td>
<td><pre><code>65 - 0x41</code></pre></td>
<td>Kryptolan</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>rvd</code></pre></td>
<td><pre><code>66 - 0x42</code></pre></td>
<td>Mit remote virtual disk protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ippc internet</code></pre></td>
<td><pre><code>67 - 0x43</code></pre></td>
<td>Internet pluribus packet core</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>anydfs</code></pre></td>
<td><pre><code>68 - 0x44</code></pre></td>
<td>Any distributed file system</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sat-mon</code></pre></td>
<td><pre><code>69 - 0x45</code></pre></td>
<td>Satnet monitoring</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>visa</code></pre></td>
<td><pre><code>70 - 0x46</code></pre></td>
<td>Visa protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ipcv</code></pre></td>
<td><pre><code>71 - 0x47</code></pre></td>
<td>Internet packet core utility</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>cpnx</code></pre></td>
<td><pre><code>72 - 0x48</code></pre></td>
<td>Computer protocol network executive</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>rspf</code></pre></td>
<td><pre><code>73 - 0x49</code></pre></td>
<td>Radio shortest path first (officially cphb, computer protocol heart beat</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>br-sat-mon</code></pre></td>
<td><pre><code>76 - 0x4C</code></pre></td>
<td>Backroom satnet monitoring</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sun-nd</code></pre></td>
<td><pre><code>77 - 0x4D</code></pre></td>
<td>Sun nd protocol-temporary</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>wb-mon</code></pre></td>
<td><pre><code>78 - 0x4E</code></pre></td>
<td>Wideband monitoring</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>wb-expak</code></pre></td>
<td><pre><code>79 - 0x4F</code></pre></td>
<td>Wideband expak</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>iso-ip</code></pre></td>
<td><pre><code>80 - 0x50</code></pre></td>
<td>Iso internet protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>vmtp</code></pre></td>
<td><pre><code>81 - 0x51</code></pre></td>
<td>Versatile message transport</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>secure-vmtp</code></pre></td>
<td><pre><code>82 - 0x52</code></pre></td>
<td>Versatile message transport</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>vines</code></pre></td>
<td><pre><code>83 - 0x53</code></pre></td>
<td>Vines</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ttp</code></pre></td>
<td><pre><code>84 - 0x54</code></pre></td>
<td>Ttp</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>msfnet-igp</code></pre></td>
<td><pre><code>85 - 0x55</code></pre></td>
<td>Msfnet-igp</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>dgp</code></pre></td>
<td><pre><code>86 - 0x56</code></pre></td>
<td>Dissimilar gateway protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>tcf</code></pre></td>
<td><pre><code>87 - 0x57</code></pre></td>
<td>Tcf</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>eigrp</code></pre></td>
<td><pre><code>88 - 0x58</code></pre></td>
<td>Enhanced interior routing protocol (cisco)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ospf</code></pre></td>
<td><pre><code>89 - 0x59</code></pre></td>
<td>Open shortest path first igp</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>sprite-rpc</code></pre></td>
<td><pre><code>90 - 0x5A</code></pre></td>
<td>Sprite rpc protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>larp</code></pre></td>
<td><pre><code>91 - 0x5B</code></pre></td>
<td>Locus address resolution protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>mtp</code></pre></td>
<td><pre><code>92 - 0x5C</code></pre></td>
<td>Multicast transport protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ax.25</code></pre></td>
<td><pre><code>93 - 0x5D</code></pre></td>
<td>Ax.25 frames</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipip</code></pre></td>
<td><pre><code>94 - 0x5E</code></pre></td>
<td>Ip-within-ip encapsulation protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>micp</code></pre></td>
<td><pre><code>95 - 0x5F</code></pre></td>
<td>Mobile internetworking control pro.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>scc-sp</code></pre></td>
<td><pre><code>96 - 0x60</code></pre></td>
<td>Semaphore communications sec. pro.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>etherip</code></pre></td>
<td><pre><code>97 - 0x61</code></pre></td>
<td>Ethernet-within-ip encapsulation</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>anyprivenc</code></pre></td>
<td><pre><code>98 - 0x62</code></pre></td>
<td>Any private encryption scheme</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>gmtp</code></pre></td>
<td><pre><code>100 - 0x64</code></pre></td>
<td>Gmtp</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ifmp</code></pre></td>
<td><pre><code>101 - 0x65</code></pre></td>
<td>Ipsilon flow management protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>pnni</code></pre></td>
<td><pre><code>102 - 0x66</code></pre></td>
<td>Pnni over ip</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>pim</code></pre></td>
<td><pre><code>103 - 0x67</code></pre></td>
<td>Protocol independent multicast</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>aris</code></pre></td>
<td><pre><code>104 - 0x68</code></pre></td>
<td>Aris</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>scps</code></pre></td>
<td><pre><code>105 - 0x69</code></pre></td>
<td>Scps</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>qnx</code></pre></td>
<td><pre><code>106 - 0x6A</code></pre></td>
<td>Qnx</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>a/n</code></pre></td>
<td><pre><code>107 - 0x6B</code></pre></td>
<td>Active networks</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ipcomp</code></pre></td>
<td><pre><code>108 - 0x6C</code></pre></td>
<td>Ip payload compression protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>snp</code></pre></td>
<td><pre><code>109 - 0x6D</code></pre></td>
<td>Sitara networks protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>compaq-peer</code></pre></td>
<td><pre><code>110 - 0x6E</code></pre></td>
<td>Compaq peer protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ipx-in-ip</code></pre></td>
<td><pre><code>111 - 0x6F</code></pre></td>
<td>Ipx in ip</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>vrrp</code></pre></td>
<td><pre><code>112 - 0x70</code></pre></td>
<td>Virtual router redundancy protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>pgm</code></pre></td>
<td><pre><code>113 - 0x71</code></pre></td>
<td>Pgm reliable transport protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>any0hop</code></pre></td>
<td><pre><code>114 - 0x72</code></pre></td>
<td>Any 0-hop protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>l2tp</code></pre></td>
<td><pre><code>115 - 0x73</code></pre></td>
<td>Layer two tunneling protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ddx</code></pre></td>
<td><pre><code>116 - 0x74</code></pre></td>
<td>D-ii data exchange (ddx)</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>iatp</code></pre></td>
<td><pre><code>117 - 0x75</code></pre></td>
<td>Interactive agent transfer protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>stp</code></pre></td>
<td><pre><code>118 - 0x76</code></pre></td>
<td>Schedule transfer protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>srp</code></pre></td>
<td><pre><code>119 - 0x77</code></pre></td>
<td>Spectralink radio protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>uti</code></pre></td>
<td><pre><code>120 - 0x78</code></pre></td>
<td>Uti</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>smp</code></pre></td>
<td><pre><code>121 - 0x79</code></pre></td>
<td>Simple message protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sm</code></pre></td>
<td><pre><code>122 - 0x7A</code></pre></td>
<td>Sm</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>ptp</code></pre></td>
<td><pre><code>123 - 0x7B</code></pre></td>
<td>Performance transparency protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>isis</code></pre></td>
<td><pre><code>124 - 0x7C</code></pre></td>
<td>Isis over ipv4</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>fire</code></pre></td>
<td><pre><code>125 - 0x7D</code></pre></td>
<td>Fire</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>crtp</code></pre></td>
<td><pre><code>126 - 0x7E</code></pre></td>
<td>Combat radio transport protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>crudp</code></pre></td>
<td><pre><code>127 - 0x7F</code></pre></td>
<td>Combat radio user datagram</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sscopmce</code></pre></td>
<td><pre><code>128 - 0x80</code></pre></td>
<td>Sscopmce</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>iplt</code></pre></td>
<td><pre><code>129 - 0x81</code></pre></td>
<td>Iplt</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sps</code></pre></td>
<td><pre><code>130 - 0x82</code></pre></td>
<td>Secure packet shield</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>pipe</code></pre></td>
<td><pre><code>131 - 0x83</code></pre></td>
<td>Private ip encapsulation within ip</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>sctp</code></pre></td>
<td><pre><code>132 - 0x84</code></pre></td>
<td>Stream control transmission protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>fc</code></pre></td>
<td><pre><code>133 - 0x85</code></pre></td>
<td>Fibre channel</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>rsvp-e2e-ignore</code></pre></td>
<td><pre><code>134 - 0x86</code></pre></td>
<td>Rsvp-e2e-ignore</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>mobilityheader</code></pre></td>
<td><pre><code>135 - 0x87</code></pre></td>
<td>Mobility header</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>udplite</code></pre></td>
<td><pre><code>136 - 0x88</code></pre></td>
<td>Udp-lite</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>mpls-in-ip</code></pre></td>
<td><pre><code>137 - 0x89</code></pre></td>
<td>Mpls-in-ip</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>manet</code></pre></td>
<td><pre><code>138 - 0x8A</code></pre></td>
<td>Manet protocols</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>hip</code></pre></td>
<td><pre><code>139 - 0x8B</code></pre></td>
<td>Host identity protocol</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>shim6</code></pre></td>
<td><pre><code>140 - 0x8C</code></pre></td>
<td>Shim6 protocol</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>testing1</code></pre></td>
<td><pre><code>253 - 0xFD</code></pre></td>
<td>Use for experimentation and testing</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>testing2</code></pre></td>
<td><pre><code>254 - 0xFE</code></pre></td>
<td>Use for experimentation and testing</td>
</tr>
</tbody>
</table>

### Type [keytype](#type-keytype)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RSA</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EC</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
</tbody>
</table>

### Type [layer](#type-layer)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Citrix</code></pre></td>
<td><pre><code>citrix</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Citrix Channels</code></pre></td>
<td><pre><code>citrix_channels</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>DNS</code></pre></td>
<td><pre><code>dns</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>HTTP</code></pre></td>
<td><pre><code>http</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>ICMP</code></pre></td>
<td><pre><code>icmp</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Non IP</code></pre></td>
<td><pre><code>non_ip</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Other IP</code></pre></td>
<td><pre><code>other_ip</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>CIFS</code></pre></td>
<td><pre><code>smb</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Databases</code></pre></td>
<td><pre><code>databases</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TCP</code></pre></td>
<td><pre><code>tcp</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>UDP</code></pre></td>
<td><pre><code>udp</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>VoIP</code></pre></td>
<td><pre><code>voip</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TLS</code></pre></td>
<td><pre><code>tls</code></pre></td>
</tr>
</tbody>
</table>

### Type [os](#type-os)

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Category</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Unknown</code></pre></td>
<td>Unknown</td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:3.x</code></pre></td>
<td>linux</td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.6.x</code></pre></td>
<td>linux</td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.4.x</code></pre></td>
<td>linux</td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.2.x</code></pre></td>
<td>linux</td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.0</code></pre></td>
<td>linux</td>
<td><pre><code>5 - 0x5</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:3.x (loopback)</code></pre></td>
<td>linux</td>
<td><pre><code>6 - 0x6</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.6.x (loopback)</code></pre></td>
<td>linux</td>
<td><pre><code>7 - 0x7</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.4.x (loopback)</code></pre></td>
<td>linux</td>
<td><pre><code>8 - 0x8</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.2.x (loopback)</code></pre></td>
<td>linux</td>
<td><pre><code>9 - 0x9</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.6.x (google crawler)</code></pre></td>
<td>linux</td>
<td><pre><code>10 - 0xA</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:Android</code></pre></td>
<td>mobile</td>
<td><pre><code>11 - 0xB</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:3.x (generic)</code></pre></td>
<td>linux</td>
<td><pre><code>12 - 0xC</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.4.x-2.6.x (generic)</code></pre></td>
<td>linux</td>
<td><pre><code>13 - 0xD</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.2.x-3.x (generic)</code></pre></td>
<td>linux</td>
<td><pre><code>14 - 0xE</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.2.x-3.x (generic, no ts)</code></pre></td>
<td>linux</td>
<td><pre><code>15 - 0xF</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.2.x-3.x (generic, barebone)</code></pre></td>
<td>linux</td>
<td><pre><code>16 - 0x10</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Windows:XP</code></pre></td>
<td>windows</td>
<td><pre><code>17 - 0x11</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Windows:7 or 8</code></pre></td>
<td>windows</td>
<td><pre><code>18 - 0x12</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Windows:7 (Websense crawler)</code></pre></td>
<td>windows</td>
<td><pre><code>19 - 0x13</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Windows:NT kernel 5.x (generic)</code></pre></td>
<td>windows</td>
<td><pre><code>20 - 0x14</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Windows:NT kernel 6.x (generic)</code></pre></td>
<td>windows</td>
<td><pre><code>21 - 0x15</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Windows:NT kernel (generic)</code></pre></td>
<td>windows</td>
<td><pre><code>22 - 0x16</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mac OS X:10.x</code></pre></td>
<td>macos</td>
<td><pre><code>23 - 0x17</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>iOS:iPhone or iPad</code></pre></td>
<td>mobile</td>
<td><pre><code>24 - 0x18</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Mac OS X (generic)</code></pre></td>
<td>macos</td>
<td><pre><code>25 - 0x19</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FreeBSD:9.x</code></pre></td>
<td>bsd</td>
<td><pre><code>26 - 0x1A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>FreeBSD:8.x</code></pre></td>
<td>bsd</td>
<td><pre><code>27 - 0x1B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FreeBSD (generic)</code></pre></td>
<td>bsd</td>
<td><pre><code>28 - 0x1C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OpenBSD:3.x</code></pre></td>
<td>bsd</td>
<td><pre><code>29 - 0x1D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>OpenBSD:4.x-5.x</code></pre></td>
<td>bsd</td>
<td><pre><code>30 - 0x1E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Solaris:8</code></pre></td>
<td>solaris</td>
<td><pre><code>31 - 0x1F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Solaris:10</code></pre></td>
<td>solaris</td>
<td><pre><code>32 - 0x20</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OpenVMS:8.x</code></pre></td>
<td>other</td>
<td><pre><code>33 - 0x21</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>OpenVMS:7.x</code></pre></td>
<td>other</td>
<td><pre><code>34 - 0x22</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NeXTSTEP</code></pre></td>
<td>other</td>
<td><pre><code>35 - 0x23</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Tru64:4.x</code></pre></td>
<td>other</td>
<td><pre><code>36 - 0x24</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NMap:SYN scan</code></pre></td>
<td>Unknown</td>
<td><pre><code>37 - 0x25</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NMap:OS detection</code></pre></td>
<td>Unknown</td>
<td><pre><code>38 - 0x26</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>p0f:sendsyn utility</code></pre></td>
<td>Unknown</td>
<td><pre><code>39 - 0x27</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Blackberry</code></pre></td>
<td>mobile</td>
<td><pre><code>40 - 0x28</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Nintendo:3DS</code></pre></td>
<td>other</td>
<td><pre><code>41 - 0x29</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Nintendo:Wii</code></pre></td>
<td>other</td>
<td><pre><code>42 - 0x2A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>BaiduSpider</code></pre></td>
<td>other</td>
<td><pre><code>43 - 0x2B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:3.x (syn+ack)</code></pre></td>
<td>linux</td>
<td><pre><code>44 - 0x2C</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.4-2.6 (syn+ack)</code></pre></td>
<td>linux</td>
<td><pre><code>45 - 0x2D</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Linux:2.4.x (syn+ack)</code></pre></td>
<td>linux</td>
<td><pre><code>46 - 0x2E</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Linux:2.6.x (syn+ack)</code></pre></td>
<td>linux</td>
<td><pre><code>47 - 0x2F</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Windows:XP (syn+ack)</code></pre></td>
<td>windows</td>
<td><pre><code>48 - 0x30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Windows:7 or 8 (syn+ack)</code></pre></td>
<td>windows</td>
<td><pre><code>49 - 0x31</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FreeBSD:9.x (syn+ack)</code></pre></td>
<td>bsd</td>
<td><pre><code>50 - 0x32</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>FreeBSD:8.x (syn+ack)</code></pre></td>
<td>bsd</td>
<td><pre><code>51 - 0x33</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>FreeBSD:8.x-9.x (syn+ack)</code></pre></td>
<td>bsd</td>
<td><pre><code>52 - 0x34</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OpenBSD:5.x (syn+ack)</code></pre></td>
<td>bsd</td>
<td><pre><code>53 - 0x35</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Mac OS X:10.x (syn+ack)</code></pre></td>
<td>macos</td>
<td><pre><code>54 - 0x36</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Solaris:6 (syn+ack)</code></pre></td>
<td>solaris</td>
<td><pre><code>55 - 0x37</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Solaris:8 (syn+ack)</code></pre></td>
<td>solaris</td>
<td><pre><code>56 - 0x38</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Solaris:10 (syn+ack)</code></pre></td>
<td>solaris</td>
<td><pre><code>57 - 0x39</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>HP-UX:11.x (syn+ack)</code></pre></td>
<td>other</td>
<td><pre><code>58 - 0x3A</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>OpenVMS:7.x (syn+ack)</code></pre></td>
<td>other</td>
<td><pre><code>59 - 0x3B</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Tru64:4.x (syn+ack)</code></pre></td>
<td>other</td>
<td><pre><code>60 - 0x3C</code></pre></td>
</tr>
</tbody>
</table>

### Type [pktsourcekind](#type-pktsourcekind)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>Missing</code></pre></td>
<td><pre><code>0 - 0x0</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>Network Interface</code></pre></td>
<td><pre><code>1 - 0x1</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPCAPD Remote Capture</code></pre></td>
<td><pre><code>2 - 0x2</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>PCAP File</code></pre></td>
<td><pre><code>3 - 0x3</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NetFlow</code></pre></td>
<td><pre><code>4 - 0x4</code></pre></td>
</tr>
</tbody>
</table>

### Type [smbcommand](#type-smbcommand)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_create_directory</code></pre></td>
<td><pre><code>1:0</code></pre></td>
<td>Create a new directory on the server, relative to a connected share.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_delete_directory</code></pre></td>
<td><pre><code>1:1</code></pre></td>
<td>Delete an empty directory.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_open</code></pre></td>
<td><pre><code>1:2</code></pre></td>
<td>Open an existing regular file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_create</code></pre></td>
<td><pre><code>1:3</code></pre></td>
<td>Create and open a new file or open and truncate an existing file to zero length.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_close</code></pre></td>
<td><pre><code>1:4</code></pre></td>
<td>Close an instance of an object associated with a valid FID.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_flush</code></pre></td>
<td><pre><code>1:5</code></pre></td>
<td>Request that the server flush data and allocation information for a specified file or for all open files under the session.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_delete</code></pre></td>
<td><pre><code>1:6</code></pre></td>
<td>Delete one or more regular files.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_rename</code></pre></td>
<td><pre><code>1:7</code></pre></td>
<td>Change the name of one or more files or directories</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_query_information</code></pre></td>
<td><pre><code>1:8</code></pre></td>
<td>Obtain attribute information about a file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_set_information</code></pre></td>
<td><pre><code>1:9</code></pre></td>
<td>Change the attribute information of a regular file or directory.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read</code></pre></td>
<td><pre><code>1:10</code></pre></td>
<td>Read bytes from a regular file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write</code></pre></td>
<td><pre><code>1:11</code></pre></td>
<td>Write bytes to a regular file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_lock_byte_range</code></pre></td>
<td><pre><code>1:12</code></pre></td>
<td>Explicitly lock a contiguous range of bytes in an open regular file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_unlock_byte_range</code></pre></td>
<td><pre><code>1:13</code></pre></td>
<td>Explicitly unlock a contiguous range of bytes in an open regular file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_create_temporary</code></pre></td>
<td><pre><code>1:14</code></pre></td>
<td>Create a file for temporary use by the client.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_create_new</code></pre></td>
<td><pre><code>1:15</code></pre></td>
<td>Create a new file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_check_directory</code></pre></td>
<td><pre><code>1:16</code></pre></td>
<td>Verify that a specified path resolves to a valid directory on the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_process_exit</code></pre></td>
<td><pre><code>1:17</code></pre></td>
<td>Sent by the client to indicate the catastrophic failure of a client process.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_seek</code></pre></td>
<td><pre><code>1:18</code></pre></td>
<td>Position a file pointer within a regular file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_lock_and_read</code></pre></td>
<td><pre><code>1:19</code></pre></td>
<td>Explicitly lock and read bytes from a regular file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_and_unlock</code></pre></td>
<td><pre><code>1:20</code></pre></td>
<td>Write to a range of bytes and then unlock them.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read_raw</code></pre></td>
<td><pre><code>1:26</code></pre></td>
<td>Request raw data from the file or named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read_mpx</code></pre></td>
<td><pre><code>1:27</code></pre></td>
<td>This is a specialized read command intended to maximize the performance of reading large blocks of data from a regular file while allowing for other operations to take place between the client and the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read_mpx_secondary</code></pre></td>
<td><pre><code>1:28</code></pre></td>
<td>This command is no longer used in conjunction with the SMB_COM_READ_MPX command.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_raw</code></pre></td>
<td><pre><code>1:29</code></pre></td>
<td>This is a specialized write command intended to maximize performance when writing large blocks of data to an open regular file, a named pipe, a device, or spooled output.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_mpx</code></pre></td>
<td><pre><code>1:30</code></pre></td>
<td>SMB_COM_WRITE_MPX is used to maximize performance when writing a large block of data from the client to the server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_mpx_secondary</code></pre></td>
<td><pre><code>1:31</code></pre></td>
<td>This command is no longer used in conjunction with the SMB_COM_WRITE_MPX command.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_complete</code></pre></td>
<td><pre><code>1:32</code></pre></td>
<td>This command is sent by the server as the final response of an SMB_COM_WRITE_RAW command sequence.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_query_server</code></pre></td>
<td><pre><code>1:33</code></pre></td>
<td>This command was introduced in the NT LAN Manager dialect, and was reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_set_information2</code></pre></td>
<td><pre><code>1:34</code></pre></td>
<td>Set attribute information about an open file. This command allows the client to set more attribute information for the file than the SMB_COM_SET_INFORMATION command.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_query_information2</code></pre></td>
<td><pre><code>1:35</code></pre></td>
<td>Obtain attribute information about an open file. This command provides more information about the file than the SMB_COM_QUERY_INFORMATION command.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_locking_andx</code></pre></td>
<td><pre><code>1:36</code></pre></td>
<td>Explicitly lock and/or unlock a contiguous range of bytes in a regular file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_transaction</code></pre></td>
<td><pre><code>1:37</code></pre></td>
<td>This command serves as the transport for the Transaction Subprotocol Commands. These commands operate on mailslots and named pipes, which are interprocess communication endpoints within the CIFS file system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_transaction_secondary</code></pre></td>
<td><pre><code>1:38</code></pre></td>
<td>The SMB_COM_TRANSACTION_SECONDARY command is used to complete a data transfer initiated by an SMB_COM_TRANSACTION Request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_ioctl</code></pre></td>
<td><pre><code>1:39</code></pre></td>
<td>This command delivers a device- or file-specific IOCTL request to a server, and a device- or file-specific IOCTL response to the requester.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_ioctl_secondary</code></pre></td>
<td><pre><code>1:40</code></pre></td>
<td>This command is a companion to SMB_COM_IOCTL.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_copy</code></pre></td>
<td><pre><code>1:41</code></pre></td>
<td>Perform server-side file copies</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_move</code></pre></td>
<td><pre><code>1:42</code></pre></td>
<td>Move files on the server</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_echo</code></pre></td>
<td><pre><code>1:43</code></pre></td>
<td>Sent by the client to test the transport layer connection with the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_and_close</code></pre></td>
<td><pre><code>1:44</code></pre></td>
<td>Write to a range of bytes and then close the file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_open_andx</code></pre></td>
<td><pre><code>1:45</code></pre></td>
<td>Open a new file or open an existing regular file and chain additional messages along with the request.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read_andx</code></pre></td>
<td><pre><code>1:46</code></pre></td>
<td>Read bytes from a regular file, a named pipe, or a directly accessible device such as a serial port (COM) or printer port (LPT).</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_andx</code></pre></td>
<td><pre><code>1:47</code></pre></td>
<td>Write bytes to a regular file, a named pipe, or a directly accessible I/O device such as a serial port (COM) or printer port (LPT).</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_new_file_size</code></pre></td>
<td><pre><code>1:48</code></pre></td>
<td>This command was reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_close_and_tree_disc</code></pre></td>
<td><pre><code>1:49</code></pre></td>
<td>This command was reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_transaction2</code></pre></td>
<td><pre><code>1:50</code></pre></td>
<td>Provide support for a richer set of server-side file system semantics. The "Trans2 subcommands", as they are called, allow clients to set and retrieve Extended Attribute key/value pairs, make use of long file names, and perform directory searches, among other tasks.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_transaction2_secondary</code></pre></td>
<td><pre><code>1:51</code></pre></td>
<td>The SMB_COM_TRANSACTION2_SECONDARY command is used to complete a data transfer initiated by an SMB_COM_TRANSACTION2 request.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_find_close2</code></pre></td>
<td><pre><code>1:52</code></pre></td>
<td>Close a search handle that was created by a TRANS2_FIND_FIRST2 subcommand.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_find_notify_close</code></pre></td>
<td><pre><code>1:53</code></pre></td>
<td>Close a directory search handle that was created by a TRANS2_FIND_NOTIFY_FIRST subcommand request to the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_tree_connect</code></pre></td>
<td><pre><code>1:112</code></pre></td>
<td>Establish a client connection to a server share.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_tree_disconnect</code></pre></td>
<td><pre><code>1:113</code></pre></td>
<td>Disconnect client access to a server resource.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_negociate</code></pre></td>
<td><pre><code>1:114</code></pre></td>
<td>Initiate an SMB connection between the client and the server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_session_setup_andx</code></pre></td>
<td><pre><code>1:115</code></pre></td>
<td>Configure an SMB session.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_logoff_andx</code></pre></td>
<td><pre><code>1:116</code></pre></td>
<td>Log off the user connection.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_tree_connect_andx</code></pre></td>
<td><pre><code>1:117</code></pre></td>
<td>Establish a client connection to a server share.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_security_package_andx</code></pre></td>
<td><pre><code>1:126</code></pre></td>
<td>Negotiate security packages and related information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_query_information_disk</code></pre></td>
<td><pre><code>1:128</code></pre></td>
<td>Obtain the capacity and remaining free space on the volume hosting the subtree indicated by the tree_id.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_search</code></pre></td>
<td><pre><code>1:129</code></pre></td>
<td>Search a directory for files or other objects that have names matching a given wildcard template.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_find</code></pre></td>
<td><pre><code>1:130</code></pre></td>
<td>This command is identical in structure and purpose to SMB_COM_SEARCH. The only difference is that SMB_COM_FIND is paired with the SMB_COM_FIND_CLOSE command, which allows the client to explicitly close a search operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_find_unique</code></pre></td>
<td><pre><code>1:131</code></pre></td>
<td>The use of this command, as opposed to SMB_COM_SEARCH or SMB_COM_FIND, indicates to the server that it need not maintain a search context or any other state. The SMB_COM_FIND_UNIQUE command is single-use. No follow-up commands are permitted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_find_close</code></pre></td>
<td><pre><code>1:132</code></pre></td>
<td>This command is used to close a directory search opened by SMB_COM_FIND.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_nt_transact</code></pre></td>
<td><pre><code>1:160</code></pre></td>
<td>SMB_COM_NT_TRANSACT subcommands extend the file system feature access offered by SMB_COM_TRANSACTION2, and also allow for the transfer of very large parameter and data blocks.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_nt_transact_secondary</code></pre></td>
<td><pre><code>1:161</code></pre></td>
<td>The SMB_COM_NT_TRANSACT_SECONDARY command is used to complete a data transfer initiated by an SMB_COM_NT_TRANSACT request.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_nt_create_andx</code></pre></td>
<td><pre><code>1:162</code></pre></td>
<td>This command is used to create and open a new file, or to open an existing file, or to open and truncate an existing file to zero length, or to create a directory, or to create a connection to a named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_nt_cancel</code></pre></td>
<td><pre><code>1:164</code></pre></td>
<td>Request that a currently pending request be canceled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_nt_rename</code></pre></td>
<td><pre><code>1:165</code></pre></td>
<td>Create hard links on the remote server, to perform an in-place file rename, and to move a file within its existing path hierarchy.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_open_print_file</code></pre></td>
<td><pre><code>1:192</code></pre></td>
<td>Create a print queue spool file. The file will be queued to the printer when closed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_print_file</code></pre></td>
<td><pre><code>1:193</code></pre></td>
<td>Write data to an open print queue spool file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_close_print_file</code></pre></td>
<td><pre><code>1:194</code></pre></td>
<td>Closes the specified print queue spool file, causing the server to queue the file for printing.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_get_print_file</code></pre></td>
<td><pre><code>1:195</code></pre></td>
<td>Generate a list of items currently in a print queue associated with the specified tree_id.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_read_bulk</code></pre></td>
<td><pre><code>1:216</code></pre></td>
<td>This command was reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_bulk</code></pre></td>
<td><pre><code>1:217</code></pre></td>
<td>This command was reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_write_bulk_data</code></pre></td>
<td><pre><code>1:218</code></pre></td>
<td>This command was reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_com_invalid</code></pre></td>
<td><pre><code>1:254</code></pre></td>
<td>Reserved value that specifically indicates an invalid command.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_com_no_andx_command</code></pre></td>
<td><pre><code>1:255</code></pre></td>
<td>In the earliest SMB Protocol specifications (see [IBM-SMB]), this command code was reserved for proprietary protocol extensions.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_negotiate</code></pre></td>
<td><pre><code>2:0</code></pre></td>
<td>Notify the server what dialects of the SMB 2 Protocol the client understands.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_session_setup</code></pre></td>
<td><pre><code>2:1</code></pre></td>
<td>Request a new authenticated session within a new or existing SMB 2 Protocol transport connection to the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_logoff</code></pre></td>
<td><pre><code>2:2</code></pre></td>
<td>Request termination of a particular session.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_tree_connect</code></pre></td>
<td><pre><code>2:3</code></pre></td>
<td>Request access to a particular share on the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_tree_disconnect</code></pre></td>
<td><pre><code>2:4</code></pre></td>
<td>Request that the tree connect that is specified be disconnected.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_create</code></pre></td>
<td><pre><code>2:5</code></pre></td>
<td>Request either creation of or access to a file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_close</code></pre></td>
<td><pre><code>2:6</code></pre></td>
<td>Close an instance of a file that was opened previously with a successful SMB2 CREATE Request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_flush</code></pre></td>
<td><pre><code>2:7</code></pre></td>
<td>Request that a server flush all cached file information for a specified open of a file to the persistent store that backs the file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_read</code></pre></td>
<td><pre><code>2:8</code></pre></td>
<td>Request a read operation on the file that is specified by the FileId.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_write</code></pre></td>
<td><pre><code>2:9</code></pre></td>
<td>Write data to the file or named pipe on the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_lock</code></pre></td>
<td><pre><code>2:10</code></pre></td>
<td>Either lock or unlock portions of a file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_ioctl</code></pre></td>
<td><pre><code>2:11</code></pre></td>
<td>Issue an implementation-specific file system control or device control (FSCTL/IOCTL) command across the network.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_cancel</code></pre></td>
<td><pre><code>2:12</code></pre></td>
<td>Cancel a previously sent message on the same SMB2 transport connection.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_echo</code></pre></td>
<td><pre><code>2:13</code></pre></td>
<td>Determine whether a server is processing requests.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_query_directory</code></pre></td>
<td><pre><code>2:14</code></pre></td>
<td>Obtain a directory enumeration on a directory open.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_change_notify</code></pre></td>
<td><pre><code>2:15</code></pre></td>
<td>request change notifications on a directory.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_query_info</code></pre></td>
<td><pre><code>2:16</code></pre></td>
<td>Request information on a file, named pipe, or underlying volume.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_set_info</code></pre></td>
<td><pre><code>2:17</code></pre></td>
<td>Set information on a file or underlying object store.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB2_com_oplock_break</code></pre></td>
<td><pre><code>2:18</code></pre></td>
<td>Sent by the server when the underlying object store indicates that an opportunistic lock (oplock) is being broken, representing a change in the oplock level.</td>
</tr>
</tbody>
</table>

### Type [smbstatus](#type-smbstatus)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Category</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_ok</code></pre></td>
<td>Success</td>
<td><pre><code>0 - 0x0</code></pre></td>
<td>The operation completed successfully.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_abandoned</code></pre></td>
<td>Success</td>
<td><pre><code>128 - 0x80</code></pre></td>
<td>The caller attempted to wait for a mutex that has been abandoned.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_user_apc</code></pre></td>
<td>Success</td>
<td><pre><code>192 - 0xC0</code></pre></td>
<td>A user-mode APC was delivered before the given Interval expired.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_kernel_apc</code></pre></td>
<td>Success</td>
<td><pre><code>256 - 0x100</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_alerted</code></pre></td>
<td>Success</td>
<td><pre><code>257 - 0x101</code></pre></td>
<td>The delay completed because the thread was alerted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_timeout</code></pre></td>
<td>Success</td>
<td><pre><code>258 - 0x102</code></pre></td>
<td>The given Timeout interval expired.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pending</code></pre></td>
<td>Success</td>
<td><pre><code>259 - 0x103</code></pre></td>
<td>The operation that was requested is pending completion.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_reparse</code></pre></td>
<td>Success</td>
<td><pre><code>260 - 0x104</code></pre></td>
<td>A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_more_entries</code></pre></td>
<td>Success</td>
<td><pre><code>261 - 0x105</code></pre></td>
<td>Returned by enumeration APIs to indicate more information is available to successive calls.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_all_assigned</code></pre></td>
<td>Success</td>
<td><pre><code>262 - 0x106</code></pre></td>
<td>Indicates not all privileges or groups that are referenced are assigned to the caller. This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_some_not_mapped</code></pre></td>
<td>Success</td>
<td><pre><code>263 - 0x107</code></pre></td>
<td>Some of the information to be translated has not been translated.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_oplock_break_in_progress</code></pre></td>
<td>Success</td>
<td><pre><code>264 - 0x108</code></pre></td>
<td>An open/create operation completed while an opportunistic lock (oplock) break is underway.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_volume_mounted</code></pre></td>
<td>Success</td>
<td><pre><code>265 - 0x109</code></pre></td>
<td>A new volume has been mounted by a file system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_rxact_committed</code></pre></td>
<td>Success</td>
<td><pre><code>266 - 0x10A</code></pre></td>
<td>This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_notify_cleanup</code></pre></td>
<td>Success</td>
<td><pre><code>267 - 0x10B</code></pre></td>
<td>Indicates that a notify change request has been completed due to closing the handle that made the notify change request.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_notify_enum_dir</code></pre></td>
<td>Warning</td>
<td><pre><code>268 - 0x10C</code></pre></td>
<td>Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_quotas_for_account</code></pre></td>
<td>Success</td>
<td><pre><code>269 - 0x10D</code></pre></td>
<td>{No Quotas} No system quota limits are specifically set for this account.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_primary_transport_connect_failed</code></pre></td>
<td>Success</td>
<td><pre><code>270 - 0x10E</code></pre></td>
<td>{Connect Failure on Primary Transport} An attempt was made to connect to the remote server on the primary transport, but the connection failed. The computer WAS able to connect on a secondary transport.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_page_fault_transition</code></pre></td>
<td>Success</td>
<td><pre><code>272 - 0x110</code></pre></td>
<td>The page fault was a transition fault.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_page_fault_demand_zero</code></pre></td>
<td>Success</td>
<td><pre><code>273 - 0x111</code></pre></td>
<td>The page fault was a demand zero fault.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_page_fault_copy_on_write</code></pre></td>
<td>Success</td>
<td><pre><code>274 - 0x112</code></pre></td>
<td>The page fault was a demand zero fault.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_page_fault_guard_page</code></pre></td>
<td>Success</td>
<td><pre><code>275 - 0x113</code></pre></td>
<td>The page fault was a demand zero fault.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_page_fault_paging_file</code></pre></td>
<td>Success</td>
<td><pre><code>276 - 0x114</code></pre></td>
<td>The page fault was satisfied by reading from a secondary storage device.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_cache_page_locked</code></pre></td>
<td>Success</td>
<td><pre><code>277 - 0x115</code></pre></td>
<td>The cached page was locked during operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_crash_dump</code></pre></td>
<td>Success</td>
<td><pre><code>278 - 0x116</code></pre></td>
<td>The crash dump exists in a paging file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_buffer_all_zeros</code></pre></td>
<td>Success</td>
<td><pre><code>279 - 0x117</code></pre></td>
<td>The specified buffer contains all zeros.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_reparse_object</code></pre></td>
<td>Success</td>
<td><pre><code>280 - 0x118</code></pre></td>
<td>A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_requirements_changed</code></pre></td>
<td>Success</td>
<td><pre><code>281 - 0x119</code></pre></td>
<td>The device has succeeded a query-stop and its resource requirements have changed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_translation_complete</code></pre></td>
<td>Success</td>
<td><pre><code>288 - 0x120</code></pre></td>
<td>The translator has translated these resources into the global space and no additional translations should be performed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_membership_evaluated_locally</code></pre></td>
<td>Success</td>
<td><pre><code>289 - 0x121</code></pre></td>
<td>The directory service evaluated group memberships locally, because it was unable to contact a global catalog server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_nothing_to_terminate</code></pre></td>
<td>Success</td>
<td><pre><code>290 - 0x122</code></pre></td>
<td>A process being terminated has no threads to terminate.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_process_not_in_job</code></pre></td>
<td>Success</td>
<td><pre><code>291 - 0x123</code></pre></td>
<td>The specified process is not part of a job.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_process_in_job</code></pre></td>
<td>Success</td>
<td><pre><code>292 - 0x124</code></pre></td>
<td>The specified process is part of a job.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wait_for_oplock</code></pre></td>
<td>Success</td>
<td><pre><code>871 - 0x367</code></pre></td>
<td>An operation is blocked and waiting for an oplock.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_smb</code></pre></td>
<td>Error</td>
<td><pre><code>65538 - 0x10002</code></pre></td>
<td>The debugger continued.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_bad_tid</code></pre></td>
<td>Error</td>
<td><pre><code>327682 - 0x50002</code></pre></td>
<td>The TID is no longer valid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_bad_fid</code></pre></td>
<td>Warning</td>
<td><pre><code>393217 - 0x60001</code></pre></td>
<td>Invalid FID.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_invalid_access</code></pre></td>
<td>Warning</td>
<td><pre><code>786433 - 0xC0001</code></pre></td>
<td>Invalid open mode.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_bad_command</code></pre></td>
<td>Error</td>
<td><pre><code>1441794 - 0x160002</code></pre></td>
<td>An unknown SMB command code was received by the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_bad_uid</code></pre></td>
<td>Error</td>
<td><pre><code>5963778 - 0x5B0002</code></pre></td>
<td>The UID specified is not known as a valid ID on this server session.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_no_more_sids</code></pre></td>
<td>Warning</td>
<td><pre><code>7405569 - 0x710001</code></pre></td>
<td>Maximum number of searches has been exhausted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_invalid_level</code></pre></td>
<td>Warning</td>
<td><pre><code>8126465 - 0x7C0001</code></pre></td>
<td>The InformationLevel supplied is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_negative_seek</code></pre></td>
<td>Warning</td>
<td><pre><code>8585217 - 0x830001</code></pre></td>
<td>An attempt was made to seek to a negative absolute offset within a file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_cancel_violation</code></pre></td>
<td>Warning</td>
<td><pre><code>11337729 - 0xAD0001</code></pre></td>
<td>No lock request was outstanding for the supplied cancel region.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_atomic_locks_not_supported</code></pre></td>
<td>Warning</td>
<td><pre><code>11403265 - 0xAE0001</code></pre></td>
<td>The file system does not support atomic changes to the lock type.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_use_mpx</code></pre></td>
<td>Error</td>
<td><pre><code>16384002 - 0xFA0002</code></pre></td>
<td>Temporarily unable to support RAW mode transfers. Use MPX mode.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_use_standard</code></pre></td>
<td>Error</td>
<td><pre><code>16449538 - 0xFB0002</code></pre></td>
<td>Temporarily unable to support RAW or MPX mode transfers. Use standard read/write.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_smb_continue_mpx</code></pre></td>
<td>Error</td>
<td><pre><code>16515074 - 0xFC0002</code></pre></td>
<td>Continue in MPX mode. This error code is reserved for future use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_cannot_copy</code></pre></td>
<td>Warning</td>
<td><pre><code>17432577 - 0x10A0001</code></pre></td>
<td>The copy functions cannot be used.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_eas_didnt_fit</code></pre></td>
<td>Warning</td>
<td><pre><code>18022401 - 0x1130001</code></pre></td>
<td>Either there are no extended attributes, or the available extended attributes did not fit into the response.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_os2_ea_access_denied</code></pre></td>
<td>Warning</td>
<td><pre><code>65142785 - 0x3E20001</code></pre></td>
<td>Access to the extended attribute was denied.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_object_name_exists</code></pre></td>
<td>Success</td>
<td><pre><code>1073741824 - 0x40000000</code></pre></td>
<td>{Object Exists} An attempt was made to create an object but the object name already exists.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_thread_was_suspended</code></pre></td>
<td>Success</td>
<td><pre><code>1073741825 - 0x40000001</code></pre></td>
<td>{Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_working_set_limit_range</code></pre></td>
<td>Success</td>
<td><pre><code>1073741826 - 0x40000002</code></pre></td>
<td>{Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_not_at_base</code></pre></td>
<td>Success</td>
<td><pre><code>1073741827 - 0x40000003</code></pre></td>
<td>{Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_rxact_state_created</code></pre></td>
<td>Success</td>
<td><pre><code>1073741828 - 0x40000004</code></pre></td>
<td>This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_segment_notification</code></pre></td>
<td>Success</td>
<td><pre><code>1073741829 - 0x40000005</code></pre></td>
<td>{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_local_user_session_key</code></pre></td>
<td>Success</td>
<td><pre><code>1073741830 - 0x40000006</code></pre></td>
<td>{Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection. The session key that is returned is a constant value and not unique to this connection.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_current_directory</code></pre></td>
<td>Success</td>
<td><pre><code>1073741831 - 0x40000007</code></pre></td>
<td>{Invalid Current Directory} The process cannot switch to the startup current directory. Select OK to set the current directory, or select CANCEL to exit.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_serial_more_writes</code></pre></td>
<td>Success</td>
<td><pre><code>1073741832 - 0x40000008</code></pre></td>
<td>{Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_registry_recovered</code></pre></td>
<td>Success</td>
<td><pre><code>1073741833 - 0x40000009</code></pre></td>
<td>{Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ft_read_recovery_from_backup</code></pre></td>
<td>Success</td>
<td><pre><code>1073741834 - 0x4000000A</code></pre></td>
<td>{Redundant Read} To satisfy a read request, the Windows&amp;nbsp;NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ft_write_recovery</code></pre></td>
<td>Success</td>
<td><pre><code>1073741835 - 0x4000000B</code></pre></td>
<td>{Redundant Write} To satisfy a write request, the Windows&amp;nbsp;NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_serial_counter_timeout</code></pre></td>
<td>Success</td>
<td><pre><code>1073741836 - 0x4000000C</code></pre></td>
<td>{Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_null_lm_password</code></pre></td>
<td>Success</td>
<td><pre><code>1073741837 - 0x4000000D</code></pre></td>
<td>{Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password. The LAN Manager password that returned is a NULL string.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_machine_type_mismatch</code></pre></td>
<td>Success</td>
<td><pre><code>1073741838 - 0x4000000E</code></pre></td>
<td>{Machine Type Mismatch} The image file is valid but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_receive_partial</code></pre></td>
<td>Success</td>
<td><pre><code>1073741839 - 0x4000000F</code></pre></td>
<td>{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_receive_expedited</code></pre></td>
<td>Success</td>
<td><pre><code>1073741840 - 0x40000010</code></pre></td>
<td>{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_receive_partial_expedited</code></pre></td>
<td>Success</td>
<td><pre><code>1073741841 - 0x40000011</code></pre></td>
<td>{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_event_done</code></pre></td>
<td>Success</td>
<td><pre><code>1073741842 - 0x40000012</code></pre></td>
<td>{TDI Event Done} The TDI indication has completed successfully.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_event_pending</code></pre></td>
<td>Success</td>
<td><pre><code>1073741843 - 0x40000013</code></pre></td>
<td>{TDI Event Pending} The TDI indication has entered the pending state.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_checking_file_system</code></pre></td>
<td>Success</td>
<td><pre><code>1073741844 - 0x40000014</code></pre></td>
<td>Checking file system.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_fatal_app_exit</code></pre></td>
<td>Success</td>
<td><pre><code>1073741845 - 0x40000015</code></pre></td>
<td>{Fatal Application Exit}</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_predefined_handle</code></pre></td>
<td>Success</td>
<td><pre><code>1073741846 - 0x40000016</code></pre></td>
<td>The specified registry key is referenced by a predefined handle.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_was_unlocked</code></pre></td>
<td>Success</td>
<td><pre><code>1073741847 - 0x40000017</code></pre></td>
<td>{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_service_notification</code></pre></td>
<td>Success</td>
<td><pre><code>1073741848 - 0x40000018</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_was_locked</code></pre></td>
<td>Success</td>
<td><pre><code>1073741849 - 0x40000019</code></pre></td>
<td>{Page Locked} One of the pages to lock was already locked.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_log_hard_error</code></pre></td>
<td>Success</td>
<td><pre><code>1073741850 - 0x4000001A</code></pre></td>
<td>Application popup</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_already_win32</code></pre></td>
<td>Success</td>
<td><pre><code>1073741851 - 0x4000001B</code></pre></td>
<td>A Win32 process already exists.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_unsimulate</code></pre></td>
<td>Success</td>
<td><pre><code>1073741852 - 0x4000001C</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_continue</code></pre></td>
<td>Success</td>
<td><pre><code>1073741853 - 0x4000001D</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_single_step</code></pre></td>
<td>Success</td>
<td><pre><code>1073741854 - 0x4000001E</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_breakpoint</code></pre></td>
<td>Success</td>
<td><pre><code>1073741855 - 0x4000001F</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_exception_continue</code></pre></td>
<td>Success</td>
<td><pre><code>1073741856 - 0x40000020</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_exception_lastchance</code></pre></td>
<td>Success</td>
<td><pre><code>1073741857 - 0x40000021</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_exception_chain</code></pre></td>
<td>Success</td>
<td><pre><code>1073741858 - 0x40000022</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_machine_type_mismatch_exe</code></pre></td>
<td>Success</td>
<td><pre><code>1073741859 - 0x40000023</code></pre></td>
<td>{Machine Type Mismatch} The image file is valid but is for a machine type other than the current machine.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_yield_performed</code></pre></td>
<td>Success</td>
<td><pre><code>1073741860 - 0x40000024</code></pre></td>
<td>A yield execution was performed and no thread was available to run.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_timer_resume_ignored</code></pre></td>
<td>Success</td>
<td><pre><code>1073741861 - 0x40000025</code></pre></td>
<td>The resume flag to a timer API was ignored.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_arbitration_unhandled</code></pre></td>
<td>Success</td>
<td><pre><code>1073741862 - 0x40000026</code></pre></td>
<td>The arbiter has deferred arbitration of these resources to its parent.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cardbus_not_supported</code></pre></td>
<td>Success</td>
<td><pre><code>1073741863 - 0x40000027</code></pre></td>
<td>The device has detected a CardBus card in its slot.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_createwx86tib</code></pre></td>
<td>Success</td>
<td><pre><code>1073741864 - 0x40000028</code></pre></td>
<td>An exception status code that is used by the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_mp_processor_mismatch</code></pre></td>
<td>Success</td>
<td><pre><code>1073741865 - 0x40000029</code></pre></td>
<td>The CPUs in this multiprocessor system are not all the same revision level. To use all processors, the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_hibernated</code></pre></td>
<td>Success</td>
<td><pre><code>1073741866 - 0x4000002A</code></pre></td>
<td>The system was put into hibernation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_resume_hibernation</code></pre></td>
<td>Success</td>
<td><pre><code>1073741867 - 0x4000002B</code></pre></td>
<td>The system was resumed from hibernation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wake_system</code></pre></td>
<td>Success</td>
<td><pre><code>1073742484 - 0x40000294</code></pre></td>
<td>The system has awoken.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_shutting_down</code></pre></td>
<td>Success</td>
<td><pre><code>1073742704 - 0x40000370</code></pre></td>
<td>The directory service is shutting down.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_uuid_local_only</code></pre></td>
<td>Success</td>
<td><pre><code>1073872982 - 0x40020056</code></pre></td>
<td>A UUID that is valid only on this computer has been allocated.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_send_incomplete</code></pre></td>
<td>Success</td>
<td><pre><code>1073873071 - 0x400200AF</code></pre></td>
<td>Some data remains to be sent in the request buffer.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_guard_page_violation</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483649 - 0x80000001</code></pre></td>
<td>{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_datatype_misalignment</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483650 - 0x80000002</code></pre></td>
<td>{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_breakpoint</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483651 - 0x80000003</code></pre></td>
<td>{EXCEPTION} Breakpoint A breakpoint has been reached.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_single_step</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483652 - 0x80000004</code></pre></td>
<td>{EXCEPTION} Single Step A single step or trace operation has just been completed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_buffer_overflow</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483653 - 0x80000005</code></pre></td>
<td>{Buffer Overflow} The data was too large to fit into the specified buffer.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_no_more_files</code></pre></td>
<td>Success</td>
<td><pre><code>2147483654 - 0x80000006</code></pre></td>
<td>{No More Files} No more files were found which match the file specification. This is a warning status in specification but since it is used to end a query directory request, we consider it as an ok status.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wake_system_debugger</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483655 - 0x80000007</code></pre></td>
<td>{Kernel Debugger Awakened} The system debugger was awakened by an interrupt.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_handles_closed</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483658 - 0x8000000A</code></pre></td>
<td>{Handles Closed} Handles to objects have been automatically closed because of the requested operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_inheritance</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483659 - 0x8000000B</code></pre></td>
<td>{Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_guid_substitution_made</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483660 - 0x8000000C</code></pre></td>
<td>{GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide a more restrictive access than intended.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_partial_copy</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483661 - 0x8000000D</code></pre></td>
<td>Because of protection conflicts, not all the requested bytes could be copied.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_device_paper_empty</code></pre></td>
<td>Error</td>
<td><pre><code>2147483662 - 0x8000000E</code></pre></td>
<td>{Out of Paper} The printer is out of paper.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_powered_off</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483663 - 0x8000000F</code></pre></td>
<td>{Device Power Is Off} The printer power has been turned off.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_off_line</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483664 - 0x80000010</code></pre></td>
<td>{Device Offline} The printer has been taken offline.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_busy</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483665 - 0x80000011</code></pre></td>
<td>{Device Busy} The device is currently busy.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_more_eas</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483666 - 0x80000012</code></pre></td>
<td>{No More EAs} No more extended attributes (EAs) were found for the file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_ea_name</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483667 - 0x80000013</code></pre></td>
<td>{Illegal EA} The specified extended attribute (EA) name contains at least one illegal character.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ea_list_inconsistent</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483668 - 0x80000014</code></pre></td>
<td>{Inconsistent EA List} The extended attribute (EA) list is inconsistent.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_ea_flag</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483669 - 0x80000015</code></pre></td>
<td>{Invalid EA Flag} An invalid extended attribute (EA) flag was set.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_verify_required</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483670 - 0x80000016</code></pre></td>
<td>{Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes may be performed to the device, except those that are used in the verify operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_extraneous_information</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483671 - 0x80000017</code></pre></td>
<td>{Too Much Information} The specified access control list (ACL) contained more information than was expected.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_rxact_commit_necessary</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483672 - 0x80000018</code></pre></td>
<td>This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed but has not been rolled back either; therefore, it may still be committed, if needed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_more_entries</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483674 - 0x8000001A</code></pre></td>
<td>{No More Entries} No more entries are available from an enumeration operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_filemark_detected</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483675 - 0x8000001B</code></pre></td>
<td>{Filemark Found} A filemark was detected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_media_changed</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483676 - 0x8000001C</code></pre></td>
<td>{Media Changed} The media may have changed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bus_reset</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483677 - 0x8000001D</code></pre></td>
<td>{I/O Bus Reset} An I/O bus reset was detected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_end_of_media</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483678 - 0x8000001E</code></pre></td>
<td>{End of Media} The end of the media was encountered.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_beginning_of_media</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483679 - 0x8000001F</code></pre></td>
<td>The beginning of a tape or partition has been detected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_media_check</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483680 - 0x80000020</code></pre></td>
<td>{Media Changed} The media may have changed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_setmark_detected</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483681 - 0x80000021</code></pre></td>
<td>A tape access reached a set mark.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_data_detected</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483682 - 0x80000022</code></pre></td>
<td>During a tape access, the end of the data written is reached.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_redirector_has_open_handles</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483683 - 0x80000023</code></pre></td>
<td>The redirector is in use and cannot be unloaded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_server_has_open_handles</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483684 - 0x80000024</code></pre></td>
<td>The server is in use and cannot be unloaded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_already_disconnected</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483685 - 0x80000025</code></pre></td>
<td>The specified connection has already been disconnected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_longjump</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483686 - 0x80000026</code></pre></td>
<td>A long jump has been executed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cleaner_cartridge_installed</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483687 - 0x80000027</code></pre></td>
<td>A cleaner cartridge is present in the tape library.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_plugplay_query_vetoed</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483688 - 0x80000028</code></pre></td>
<td>The Plug and Play query operation was not successful.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unwind_consolidate</code></pre></td>
<td>Warning</td>
<td><pre><code>2147483689 - 0x80000029</code></pre></td>
<td>A frame consolidation has been executed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_requires_cleaning</code></pre></td>
<td>Warning</td>
<td><pre><code>2147484296 - 0x80000288</code></pre></td>
<td>The device has indicated that cleaning is necessary.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_door_open</code></pre></td>
<td>Warning</td>
<td><pre><code>2147484297 - 0x80000289</code></pre></td>
<td>The device has indicated that its door is open. Further operations require it closed and secured.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_unsuccessful</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225473 - 0xC0000001</code></pre></td>
<td>{Operation Failed} The requested operation was unsuccessful.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_not_implemented</code></pre></td>
<td>Error</td>
<td><pre><code>3221225474 - 0xC0000002</code></pre></td>
<td>{Not Implemented} The requested operation is not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_info_class</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225475 - 0xC0000003</code></pre></td>
<td>{Invalid Parameter} The specified information class is not a valid information class for the specified object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_info_length_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221225476 - 0xC0000004</code></pre></td>
<td>The specified information record length does not match the length that is required for the specified information class.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_access_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221225477 - 0xC0000005</code></pre></td>
<td>The instruction caused a memory access violation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_in_page_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225478 - 0xC0000006</code></pre></td>
<td>The required data was not placed into memory because of an I/O error.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pagefile_quota</code></pre></td>
<td>Error</td>
<td><pre><code>3221225479 - 0xC0000007</code></pre></td>
<td>The page file quota for the process has been exhausted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_handle</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225480 - 0xC0000008</code></pre></td>
<td>An invalid HANDLE was specified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_initial_stack</code></pre></td>
<td>Error</td>
<td><pre><code>3221225481 - 0xC0000009</code></pre></td>
<td>An invalid initial stack was specified in a call to NtCreateThread.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_initial_pc</code></pre></td>
<td>Error</td>
<td><pre><code>3221225482 - 0xC000000A</code></pre></td>
<td>An invalid initial start address was specified in a call to NtCreateThread.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_cid</code></pre></td>
<td>Error</td>
<td><pre><code>3221225483 - 0xC000000B</code></pre></td>
<td>An invalid client ID was specified.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_timer_not_canceled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225484 - 0xC000000C</code></pre></td>
<td>An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_parameter</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225485 - 0xC000000D</code></pre></td>
<td>An invalid parameter was passed to a service or function.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_no_such_device</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225486 - 0xC000000E</code></pre></td>
<td>A device that does not exist was specified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_no_such_file</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225487 - 0xC000000F</code></pre></td>
<td>{File Not Found} The file does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_device_request</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225488 - 0xC0000010</code></pre></td>
<td>The specified request is not a valid operation for the target device.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_end_of_file</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225489 - 0xC0000011</code></pre></td>
<td>The end-of-file marker has been reached. There is no valid data in the file beyond this marker.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_wrong_volume</code></pre></td>
<td>Error</td>
<td><pre><code>3221225490 - 0xC0000012</code></pre></td>
<td>{Wrong Volume} The wrong volume is in the drive. Insert volume into drive.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_no_media_in_device</code></pre></td>
<td>Error</td>
<td><pre><code>3221225491 - 0xC0000013</code></pre></td>
<td>{No Disk} There is no disk in the drive. Insert a disk into drive.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unrecognized_media</code></pre></td>
<td>Error</td>
<td><pre><code>3221225492 - 0xC0000014</code></pre></td>
<td>{Unknown Disk Format} The disk in drive is not formatted properly. Check the disk, and reformat it, if needed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_nonexistent_sector</code></pre></td>
<td>Error</td>
<td><pre><code>3221225493 - 0xC0000015</code></pre></td>
<td>{Sector Not Found} The specified sector does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_more_processing_required</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225494 - 0xC0000016</code></pre></td>
<td>{Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_memory</code></pre></td>
<td>Error</td>
<td><pre><code>3221225495 - 0xC0000017</code></pre></td>
<td>{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_conflicting_addresses</code></pre></td>
<td>Error</td>
<td><pre><code>3221225496 - 0xC0000018</code></pre></td>
<td>{Conflicting Address Range} The specified address range conflicts with the address space.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_mapped_view</code></pre></td>
<td>Error</td>
<td><pre><code>3221225497 - 0xC0000019</code></pre></td>
<td>The address range to unmap is not a mapped view.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unable_to_free_vm</code></pre></td>
<td>Error</td>
<td><pre><code>3221225498 - 0xC000001A</code></pre></td>
<td>The virtual memory cannot be freed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unable_to_delete_section</code></pre></td>
<td>Error</td>
<td><pre><code>3221225499 - 0xC000001B</code></pre></td>
<td>The specified section cannot be deleted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_system_service</code></pre></td>
<td>Error</td>
<td><pre><code>3221225500 - 0xC000001C</code></pre></td>
<td>An invalid system service was specified in a system service call.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_illegal_instruction</code></pre></td>
<td>Error</td>
<td><pre><code>3221225501 - 0xC000001D</code></pre></td>
<td>{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_lock_sequence</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225502 - 0xC000001E</code></pre></td>
<td>{Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_view_size</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225503 - 0xC000001F</code></pre></td>
<td>{Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_file_for_section</code></pre></td>
<td>Error</td>
<td><pre><code>3221225504 - 0xC0000020</code></pre></td>
<td>{Bad File} The attributes of the specified mapping file for a section of memory cannot be read.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_already_committed</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225505 - 0xC0000021</code></pre></td>
<td>{Already Committed} The specified address range is already committed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_access_denied</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225506 - 0xC0000022</code></pre></td>
<td>{Access Denied} A process has requested access to an object but has not been granted those access rights.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_buffer_too_small</code></pre></td>
<td>Error</td>
<td><pre><code>3221225507 - 0xC0000023</code></pre></td>
<td>{Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_type_mismatch</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225508 - 0xC0000024</code></pre></td>
<td>{Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_noncontinuable_exception</code></pre></td>
<td>Error</td>
<td><pre><code>3221225509 - 0xC0000025</code></pre></td>
<td>{EXCEPTION} Cannot Continue Windows cannot continue from this exception.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_disposition</code></pre></td>
<td>Error</td>
<td><pre><code>3221225510 - 0xC0000026</code></pre></td>
<td>An invalid exception disposition was returned by an exception handler.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unwind</code></pre></td>
<td>Error</td>
<td><pre><code>3221225511 - 0xC0000027</code></pre></td>
<td>Unwind exception code.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_stack</code></pre></td>
<td>Error</td>
<td><pre><code>3221225512 - 0xC0000028</code></pre></td>
<td>An invalid or unaligned stack was encountered during an unwind operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_unwind_target</code></pre></td>
<td>Error</td>
<td><pre><code>3221225513 - 0xC0000029</code></pre></td>
<td>An invalid unwind target was encountered during an unwind operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_locked</code></pre></td>
<td>Error</td>
<td><pre><code>3221225514 - 0xC000002A</code></pre></td>
<td>An attempt was made to unlock a page of memory that was not locked.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_parity_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225515 - 0xC000002B</code></pre></td>
<td>A device parity error on an I/O operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unable_to_decommit_vm</code></pre></td>
<td>Error</td>
<td><pre><code>3221225516 - 0xC000002C</code></pre></td>
<td>An attempt was made to decommit uncommitted virtual memory.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_committed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225517 - 0xC000002D</code></pre></td>
<td>An attempt was made to change the attributes on memory that has not been committed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_port_attributes</code></pre></td>
<td>Error</td>
<td><pre><code>3221225518 - 0xC000002E</code></pre></td>
<td>Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_port_message_too_long</code></pre></td>
<td>Error</td>
<td><pre><code>3221225519 - 0xC000002F</code></pre></td>
<td>The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_mix</code></pre></td>
<td>Error</td>
<td><pre><code>3221225520 - 0xC0000030</code></pre></td>
<td>An invalid combination of parameters was specified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_quota_lower</code></pre></td>
<td>Error</td>
<td><pre><code>3221225521 - 0xC0000031</code></pre></td>
<td>An attempt was made to lower a quota limit below the current usage.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_disk_corrupt_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225522 - 0xC0000032</code></pre></td>
<td>{Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_object_name_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221225523 - 0xC0000033</code></pre></td>
<td>The object name is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_name_not_found</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225524 - 0xC0000034</code></pre></td>
<td>The object name is not found.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_name_collision</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225525 - 0xC0000035</code></pre></td>
<td>The object name already exists.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_port_disconnected</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225527 - 0xC0000037</code></pre></td>
<td>An attempt was made to send a message to a disconnected communication port.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_already_attached</code></pre></td>
<td>Error</td>
<td><pre><code>3221225528 - 0xC0000038</code></pre></td>
<td>An attempt was made to attach to a device that was already attached to another device.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_path_invalid</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225529 - 0xC0000039</code></pre></td>
<td>The object path component was not a directory object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_path_not_found</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225530 - 0xC000003A</code></pre></td>
<td>{Path Not Found} The path does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_object_path_syntax_bad</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225531 - 0xC000003B</code></pre></td>
<td>The object path component was not a directory object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_data_overrun</code></pre></td>
<td>Error</td>
<td><pre><code>3221225532 - 0xC000003C</code></pre></td>
<td>{Data Overrun} A data overrun error occurred.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_data_late_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225533 - 0xC000003D</code></pre></td>
<td>{Data Late} A data late error occurred.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_data_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225534 - 0xC000003E</code></pre></td>
<td>{Data Error} An error occurred in reading or writing data.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_crc_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225535 - 0xC000003F</code></pre></td>
<td>{Bad CRC} A cyclic redundancy check (CRC) checksum error occurred.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_section_too_big</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225536 - 0xC0000040</code></pre></td>
<td>{Section Too Large} The specified section is too big to map the file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_port_connection_refused</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225537 - 0xC0000041</code></pre></td>
<td>The NtConnectPort request is refused.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_port_handle</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225538 - 0xC0000042</code></pre></td>
<td>The type of port handle is invalid for the operation that is requested.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_sharing_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221225539 - 0xC0000043</code></pre></td>
<td>A file cannot be opened because the share access flags are incompatible.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_quota_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225540 - 0xC0000044</code></pre></td>
<td>Insufficient quota exists to complete the operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_page_protection</code></pre></td>
<td>Error</td>
<td><pre><code>3221225541 - 0xC0000045</code></pre></td>
<td>The specified page protection was not valid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_mutant_not_owned</code></pre></td>
<td>Error</td>
<td><pre><code>3221225542 - 0xC0000046</code></pre></td>
<td>An attempt to release a mutant object was made by a thread that was not the owner of the mutant object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_semaphore_limit_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225543 - 0xC0000047</code></pre></td>
<td>An attempt was made to release a semaphore such that its maximum count would have been exceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_port_already_set</code></pre></td>
<td>Error</td>
<td><pre><code>3221225544 - 0xC0000048</code></pre></td>
<td>An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_section_not_image</code></pre></td>
<td>Error</td>
<td><pre><code>3221225545 - 0xC0000049</code></pre></td>
<td>An attempt was made to query image information on a section that does not map an image.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_suspend_count_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225546 - 0xC000004A</code></pre></td>
<td>An attempt was made to suspend a thread whose suspend count was at its maximum.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_thread_is_terminating</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225547 - 0xC000004B</code></pre></td>
<td>An attempt was made to suspend a thread that has begun termination.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_working_set_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221225548 - 0xC000004C</code></pre></td>
<td>An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum).</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_incompatible_file_map</code></pre></td>
<td>Error</td>
<td><pre><code>3221225549 - 0xC000004D</code></pre></td>
<td>A section was created to map a file that is not compatible with an already existing section that maps the same file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_section_protection</code></pre></td>
<td>Error</td>
<td><pre><code>3221225550 - 0xC000004E</code></pre></td>
<td>A view to a section specifies a protection that is incompatible with the protection of the initial view.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_eas_not_supported</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225551 - 0xC000004F</code></pre></td>
<td>An operation involving EAs failed because the file system does not support EAs.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_ea_too_large</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225552 - 0xC0000050</code></pre></td>
<td>An EA operation failed because the EA set is too large.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_nonexistent_ea_entry</code></pre></td>
<td>Error</td>
<td><pre><code>3221225553 - 0xC0000051</code></pre></td>
<td>An EA operation failed because the name or EA index is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_eas_on_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221225554 - 0xC0000052</code></pre></td>
<td>The file for which EAs were requested has no EAs.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ea_corrupt_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225555 - 0xC0000053</code></pre></td>
<td>The EA is corrupt and cannot be read.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_file_lock_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221225556 - 0xC0000054</code></pre></td>
<td>A requested read/write cannot be granted due to a conflicting file lock.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_lock_not_granted</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225557 - 0xC0000055</code></pre></td>
<td>A requested file lock cannot be granted due to other existing locks.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_delete_pending</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225558 - 0xC0000056</code></pre></td>
<td>A non-close operation has been requested of a file object that has a delete pending.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ctl_file_not_supported</code></pre></td>
<td>Error</td>
<td><pre><code>3221225559 - 0xC0000057</code></pre></td>
<td>An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unknown_revision</code></pre></td>
<td>Error</td>
<td><pre><code>3221225560 - 0xC0000058</code></pre></td>
<td>Indicates a revision number that was encountered or specified is not one that is known by the service. It may be a more recent revision than the service is aware of.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_revision_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221225561 - 0xC0000059</code></pre></td>
<td>Indicates that two revision levels are incompatible.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_owner</code></pre></td>
<td>Error</td>
<td><pre><code>3221225562 - 0xC000005A</code></pre></td>
<td>Indicates a particular security ID may not be assigned as the owner of an object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_primary_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225563 - 0xC000005B</code></pre></td>
<td>Indicates a particular security ID may not be assigned as the primary group of an object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_impersonation_token</code></pre></td>
<td>Error</td>
<td><pre><code>3221225564 - 0xC000005C</code></pre></td>
<td>An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_disable_mandatory</code></pre></td>
<td>Error</td>
<td><pre><code>3221225565 - 0xC000005D</code></pre></td>
<td>A mandatory group may not be disabled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_logon_servers</code></pre></td>
<td>Error</td>
<td><pre><code>3221225566 - 0xC000005E</code></pre></td>
<td>No logon servers are currently available to service the logon request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_logon_session</code></pre></td>
<td>Error</td>
<td><pre><code>3221225567 - 0xC000005F</code></pre></td>
<td>A specified logon session does not exist. It may already have been terminated.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_privilege</code></pre></td>
<td>Error</td>
<td><pre><code>3221225568 - 0xC0000060</code></pre></td>
<td>A specified privilege does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_privilege_not_held</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225569 - 0xC0000061</code></pre></td>
<td>A required privilege is not held by the client.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_account_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221225570 - 0xC0000062</code></pre></td>
<td>The name provided is not a properly formed account name.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_user_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225571 - 0xC0000063</code></pre></td>
<td>The specified account already exists.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_user</code></pre></td>
<td>Error</td>
<td><pre><code>3221225572 - 0xC0000064</code></pre></td>
<td>The specified account does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_group_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225573 - 0xC0000065</code></pre></td>
<td>The specified group already exists.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225574 - 0xC0000066</code></pre></td>
<td>The specified group does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_member_in_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225575 - 0xC0000067</code></pre></td>
<td>The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_member_not_in_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225576 - 0xC0000068</code></pre></td>
<td>The specified user account is not a member of the specified group account.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_last_admin</code></pre></td>
<td>Error</td>
<td><pre><code>3221225577 - 0xC0000069</code></pre></td>
<td>Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_wrong_password</code></pre></td>
<td>Error</td>
<td><pre><code>3221225578 - 0xC000006A</code></pre></td>
<td>When trying to update a password, this return status indicates that the value provided as the current password is not correct.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ill_formed_password</code></pre></td>
<td>Error</td>
<td><pre><code>3221225579 - 0xC000006B</code></pre></td>
<td>When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_password_restriction</code></pre></td>
<td>Error</td>
<td><pre><code>3221225580 - 0xC000006C</code></pre></td>
<td>When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_logon_failure</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225581 - 0xC000006D</code></pre></td>
<td>The attempted logon is invalid. This is either due to a bad username or authentication information.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_account_restriction</code></pre></td>
<td>Error</td>
<td><pre><code>3221225582 - 0xC000006E</code></pre></td>
<td>Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_logon_hours</code></pre></td>
<td>Error</td>
<td><pre><code>3221225583 - 0xC000006F</code></pre></td>
<td>The user account has time restrictions and may not be logged onto at this time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_workstation</code></pre></td>
<td>Error</td>
<td><pre><code>3221225584 - 0xC0000070</code></pre></td>
<td>The user account is restricted so that it may not be used to log on from the source workstation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_password_expired</code></pre></td>
<td>Error</td>
<td><pre><code>3221225585 - 0xC0000071</code></pre></td>
<td>The user account password has expired.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_account_disabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225586 - 0xC0000072</code></pre></td>
<td>The referenced account is currently disabled and may not be logged on to.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_luids_requested</code></pre></td>
<td>Error</td>
<td><pre><code>3221225588 - 0xC0000074</code></pre></td>
<td>The number of LUIDs requested may not be allocated with a single allocation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_luids_exhausted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225589 - 0xC0000075</code></pre></td>
<td>Indicates there are no more LUIDs to allocate.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_sub_authority</code></pre></td>
<td>Error</td>
<td><pre><code>3221225590 - 0xC0000076</code></pre></td>
<td>Indicates the sub-authority value is invalid for the particular use.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_acl</code></pre></td>
<td>Error</td>
<td><pre><code>3221225591 - 0xC0000077</code></pre></td>
<td>Indicates the ACL structure is not valid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_sid</code></pre></td>
<td>Error</td>
<td><pre><code>3221225592 - 0xC0000078</code></pre></td>
<td>Indicates the SID structure is not valid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_security_descr</code></pre></td>
<td>Error</td>
<td><pre><code>3221225593 - 0xC0000079</code></pre></td>
<td>Indicates the SECURITY_DESCRIPTOR structure is not valid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_procedure_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225594 - 0xC000007A</code></pre></td>
<td>Indicates the specified procedure address cannot be found in the DLL.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221225595 - 0xC000007B</code></pre></td>
<td>{Bad Image} The image is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_token</code></pre></td>
<td>Error</td>
<td><pre><code>3221225596 - 0xC000007C</code></pre></td>
<td>An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_inheritance_acl</code></pre></td>
<td>Error</td>
<td><pre><code>3221225597 - 0xC000007D</code></pre></td>
<td>Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_range_not_locked</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225598 - 0xC000007E</code></pre></td>
<td>The range specified in NtUnlockFile was not locked.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_disk_full</code></pre></td>
<td>Error</td>
<td><pre><code>3221225599 - 0xC000007F</code></pre></td>
<td>An operation failed because the disk was full.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_server_disabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225600 - 0xC0000080</code></pre></td>
<td>The GUID allocation server is disabled at the moment.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_server_not_disabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225601 - 0xC0000081</code></pre></td>
<td>The GUID allocation server is enabled at the moment.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_guids_requested</code></pre></td>
<td>Error</td>
<td><pre><code>3221225602 - 0xC0000082</code></pre></td>
<td>Too many GUIDs were requested from the allocation server at once.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_guids_exhausted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225603 - 0xC0000083</code></pre></td>
<td>The GUIDs could not be allocated because the Authority Agent was exhausted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_id_authority</code></pre></td>
<td>Error</td>
<td><pre><code>3221225604 - 0xC0000084</code></pre></td>
<td>The value provided was an invalid value for an identifier authority.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_agents_exhausted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225605 - 0xC0000085</code></pre></td>
<td>No more authority agent values are available for the particular identifier authority value.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_volume_label</code></pre></td>
<td>Error</td>
<td><pre><code>3221225606 - 0xC0000086</code></pre></td>
<td>An invalid volume label has been specified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_section_not_extended</code></pre></td>
<td>Error</td>
<td><pre><code>3221225607 - 0xC0000087</code></pre></td>
<td>A mapped section could not be extended.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_mapped_data</code></pre></td>
<td>Error</td>
<td><pre><code>3221225608 - 0xC0000088</code></pre></td>
<td>Specified section to flush does not map a data file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_data_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225609 - 0xC0000089</code></pre></td>
<td>Indicates the specified image file did not contain a resource section.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_type_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225610 - 0xC000008A</code></pre></td>
<td>Indicates the specified resource type cannot be found in the image file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_name_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225611 - 0xC000008B</code></pre></td>
<td>Indicates the specified resource name cannot be found in the image file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_array_bounds_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225612 - 0xC000008C</code></pre></td>
<td>{EXCEPTION} Array bounds exceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_denormal_operand</code></pre></td>
<td>Error</td>
<td><pre><code>3221225613 - 0xC000008D</code></pre></td>
<td>{EXCEPTION} Floating-point denormal operand.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_divide_by_zero</code></pre></td>
<td>Error</td>
<td><pre><code>3221225614 - 0xC000008E</code></pre></td>
<td>{EXCEPTION} Floating-point division by zero.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_inexact_result</code></pre></td>
<td>Error</td>
<td><pre><code>3221225615 - 0xC000008F</code></pre></td>
<td>{EXCEPTION} Floating-point inexact result.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_invalid_operation</code></pre></td>
<td>Error</td>
<td><pre><code>3221225616 - 0xC0000090</code></pre></td>
<td>{EXCEPTION} Floating-point invalid operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221225617 - 0xC0000091</code></pre></td>
<td>{EXCEPTION} Floating-point overflow.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_stack_check</code></pre></td>
<td>Error</td>
<td><pre><code>3221225618 - 0xC0000092</code></pre></td>
<td>{EXCEPTION} Floating-point stack check.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_underflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221225619 - 0xC0000093</code></pre></td>
<td>{EXCEPTION} Floating-point underflow.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_integer_divide_by_zero</code></pre></td>
<td>Error</td>
<td><pre><code>3221225620 - 0xC0000094</code></pre></td>
<td>{EXCEPTION} Integer division by zero.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_integer_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221225621 - 0xC0000095</code></pre></td>
<td>{EXCEPTION} Integer overflow.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_privileged_instruction</code></pre></td>
<td>Error</td>
<td><pre><code>3221225622 - 0xC0000096</code></pre></td>
<td>{EXCEPTION} Privileged instruction.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_too_many_paging_files</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225623 - 0xC0000097</code></pre></td>
<td>An attempt was made to install more paging files than the system supports.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221225624 - 0xC0000098</code></pre></td>
<td>The volume for a file has been externally altered such that the opened file is no longer valid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_allotted_space_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225625 - 0xC0000099</code></pre></td>
<td>When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates may exceed the amount of memory originally allotted. Because a quota may already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory. Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_insufficient_resources</code></pre></td>
<td>Error</td>
<td><pre><code>3221225626 - 0xC000009A</code></pre></td>
<td>Insufficient system resources exist to complete the API.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_dfs_exit_path_found</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225627 - 0xC000009B</code></pre></td>
<td>An attempt has been made to open a DFS exit path control file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_data_error_unused</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225628 - 0xC000009C</code></pre></td>
<td>There are bad blocks (sectors) on the hard disk.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_not_connected</code></pre></td>
<td>Error</td>
<td><pre><code>3221225629 - 0xC000009D</code></pre></td>
<td>There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_power_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225630 - 0xC000009E</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_free_vm_not_at_base</code></pre></td>
<td>Error</td>
<td><pre><code>3221225631 - 0xC000009F</code></pre></td>
<td>Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_memory_not_allocated</code></pre></td>
<td>Error</td>
<td><pre><code>3221225632 - 0xC00000A0</code></pre></td>
<td>An attempt was made to free virtual memory that is not allocated.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_working_set_quota</code></pre></td>
<td>Error</td>
<td><pre><code>3221225633 - 0xC00000A1</code></pre></td>
<td>The working set is not big enough to allow the requested pages to be locked.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_media_write_protected</code></pre></td>
<td>Error</td>
<td><pre><code>3221225634 - 0xC00000A2</code></pre></td>
<td>{Write Protect Error} The disk cannot be written to because it is write-protected. Remove the write protection from the volume in drive.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_not_ready</code></pre></td>
<td>Error</td>
<td><pre><code>3221225635 - 0xC00000A3</code></pre></td>
<td>{Drive Not Ready} The drive is not ready for use; its door may be open. Check drive and make sure that a disk is inserted and that the drive door is closed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_group_attributes</code></pre></td>
<td>Error</td>
<td><pre><code>3221225636 - 0xC00000A4</code></pre></td>
<td>The specified attributes are invalid or are incompatible with the attributes for the group as a whole.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_impersonation_level</code></pre></td>
<td>Error</td>
<td><pre><code>3221225637 - 0xC00000A5</code></pre></td>
<td>A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_open_anonymous</code></pre></td>
<td>Error</td>
<td><pre><code>3221225638 - 0xC00000A6</code></pre></td>
<td>An attempt was made to open an anonymous-level token. Anonymous tokens may not be opened.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_validation_class</code></pre></td>
<td>Error</td>
<td><pre><code>3221225639 - 0xC00000A7</code></pre></td>
<td>The validation information class requested was invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_token_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221225640 - 0xC00000A8</code></pre></td>
<td>The type of a token object is inappropriate for its attempted use.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_master_boot_record</code></pre></td>
<td>Error</td>
<td><pre><code>3221225641 - 0xC00000A9</code></pre></td>
<td>The type of a token object is inappropriate for its attempted use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_instruction_misalignment</code></pre></td>
<td>Error</td>
<td><pre><code>3221225642 - 0xC00000AA</code></pre></td>
<td>An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_instance_not_available</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225643 - 0xC00000AB</code></pre></td>
<td>The maximum named pipe instance count has been reached.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_pipe_not_available</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225644 - 0xC00000AC</code></pre></td>
<td>An instance of a named pipe cannot be found in the listening state.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_pipe_state</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225645 - 0xC00000AD</code></pre></td>
<td>The named pipe is not in the connected or closing state.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_pipe_busy</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225646 - 0xC00000AE</code></pre></td>
<td>The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_illegal_function</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225647 - 0xC00000AF</code></pre></td>
<td>The specified handle is not open to the server end of the named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_pipe_disconnected</code></pre></td>
<td>Error</td>
<td><pre><code>3221225648 - 0xC00000B0</code></pre></td>
<td>The specified named pipe is in the disconnected state.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_pipe_closing</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225649 - 0xC00000B1</code></pre></td>
<td>The specified named pipe is in the closing state.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pipe_connected</code></pre></td>
<td>Error</td>
<td><pre><code>3221225650 - 0xC00000B2</code></pre></td>
<td>The specified named pipe is in the connected state.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pipe_listening</code></pre></td>
<td>Error</td>
<td><pre><code>3221225651 - 0xC00000B3</code></pre></td>
<td>The specified named pipe is in the listening state.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_read_mode</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225652 - 0xC00000B4</code></pre></td>
<td>The specified named pipe is not in message mode.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_io_timeout</code></pre></td>
<td>Error</td>
<td><pre><code>3221225653 - 0xC00000B5</code></pre></td>
<td>{Device Timeout} The specified I/O operation was not completed before the time-out period expired.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_forced_closed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225654 - 0xC00000B6</code></pre></td>
<td>The specified file has been closed by another process.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_profiling_not_started</code></pre></td>
<td>Error</td>
<td><pre><code>3221225655 - 0xC00000B7</code></pre></td>
<td>Profiling is not started.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_profiling_not_stopped</code></pre></td>
<td>Error</td>
<td><pre><code>3221225656 - 0xC00000B8</code></pre></td>
<td>Profiling is not stopped.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_could_not_interpret</code></pre></td>
<td>Error</td>
<td><pre><code>3221225657 - 0xC00000B9</code></pre></td>
<td>The passed ACL did not contain the minimum required information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_file_is_a_directory</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225658 - 0xC00000BA</code></pre></td>
<td>The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_not_listening</code></pre></td>
<td>Error</td>
<td><pre><code>3221225660 - 0xC00000BC</code></pre></td>
<td>This remote computer is not listening.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_duplicate_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221225661 - 0xC00000BD</code></pre></td>
<td>A duplicate name exists on the network.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_network_path</code></pre></td>
<td>Error</td>
<td><pre><code>3221225662 - 0xC00000BE</code></pre></td>
<td>The network path cannot be located.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_network_busy</code></pre></td>
<td>Error</td>
<td><pre><code>3221225663 - 0xC00000BF</code></pre></td>
<td>The network is busy.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_does_not_exist</code></pre></td>
<td>Error</td>
<td><pre><code>3221225664 - 0xC00000C0</code></pre></td>
<td>This device does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_commands</code></pre></td>
<td>Error</td>
<td><pre><code>3221225665 - 0xC00000C1</code></pre></td>
<td>The network BIOS command limit has been reached.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_adapter_hardware_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225666 - 0xC00000C2</code></pre></td>
<td>An I/O adapter hardware error has occurred.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_network_response</code></pre></td>
<td>Error</td>
<td><pre><code>3221225667 - 0xC00000C3</code></pre></td>
<td>The network responded incorrectly.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_unexpected_network_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225668 - 0xC00000C4</code></pre></td>
<td>An unexpected network error occurred.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_remote_adapter</code></pre></td>
<td>Error</td>
<td><pre><code>3221225669 - 0xC00000C5</code></pre></td>
<td>The remote adapter is not compatible.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_print_queue_full</code></pre></td>
<td>Error</td>
<td><pre><code>3221225670 - 0xC00000C6</code></pre></td>
<td>The print queue is full.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_no_spool_space</code></pre></td>
<td>Error</td>
<td><pre><code>3221225671 - 0xC00000C7</code></pre></td>
<td>Space to store the file that is waiting to be printed is not available on the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_print_cancelled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225672 - 0xC00000C8</code></pre></td>
<td>The requested print file has been canceled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_network_name_deleted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225673 - 0xC00000C9</code></pre></td>
<td>The network name was deleted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_network_access_denied</code></pre></td>
<td>Error</td>
<td><pre><code>3221225674 - 0xC00000CA</code></pre></td>
<td>Network access is denied.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_bad_device_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221225675 - 0xC00000CB</code></pre></td>
<td>{Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_bad_network_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221225676 - 0xC00000CC</code></pre></td>
<td>{Network Name Not Found} The specified share name cannot be found on the remote server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_names</code></pre></td>
<td>Error</td>
<td><pre><code>3221225677 - 0xC00000CD</code></pre></td>
<td>The name limit for the network adapter card of the local computer was exceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_too_many_sessions</code></pre></td>
<td>Error</td>
<td><pre><code>3221225678 - 0xC00000CE</code></pre></td>
<td>The network BIOS session limit was exceeded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_sharing_paused</code></pre></td>
<td>Error</td>
<td><pre><code>3221225679 - 0xC00000CF</code></pre></td>
<td>File sharing has been temporarily paused.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_request_not_accepted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225680 - 0xC00000D0</code></pre></td>
<td>No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_redirector_paused</code></pre></td>
<td>Error</td>
<td><pre><code>3221225681 - 0xC00000D1</code></pre></td>
<td>Print or disk redirection is temporarily paused.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_net_write_fault</code></pre></td>
<td>Error</td>
<td><pre><code>3221225682 - 0xC00000D2</code></pre></td>
<td>A network data fault occurred.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_profiling_at_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221225683 - 0xC00000D3</code></pre></td>
<td>The number of active profiling objects is at the maximum and no more may be started.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_not_same_device</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225684 - 0xC00000D4</code></pre></td>
<td>{Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_file_renamed</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225685 - 0xC00000D5</code></pre></td>
<td>The specified file has been renamed and thus cannot be modified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_virtual_circuit_closed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225686 - 0xC00000D6</code></pre></td>
<td>{Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_security_on_object</code></pre></td>
<td>Error</td>
<td><pre><code>3221225687 - 0xC00000D7</code></pre></td>
<td>Indicates an attempt was made to operate on the security of an object that does not have security associated with it.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_wait</code></pre></td>
<td>Error</td>
<td><pre><code>3221225688 - 0xC00000D8</code></pre></td>
<td>Used to indicate that an operation cannot continue without blocking for I/O.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_pipe_empty</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225689 - 0xC00000D9</code></pre></td>
<td>Used to indicate that a read operation was done on an empty pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_access_domain_info</code></pre></td>
<td>Error</td>
<td><pre><code>3221225690 - 0xC00000DA</code></pre></td>
<td>Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_terminate_self</code></pre></td>
<td>Error</td>
<td><pre><code>3221225691 - 0xC00000DB</code></pre></td>
<td>Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_server_state</code></pre></td>
<td>Error</td>
<td><pre><code>3221225692 - 0xC00000DC</code></pre></td>
<td>Indicates the Sam Server was in the wrong state to perform the desired operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_domain_state</code></pre></td>
<td>Error</td>
<td><pre><code>3221225693 - 0xC00000DD</code></pre></td>
<td>Indicates the domain was in the wrong state to perform the desired operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_domain_role</code></pre></td>
<td>Error</td>
<td><pre><code>3221225694 - 0xC00000DE</code></pre></td>
<td>This operation is only allowed for the primary domain controller of the domain.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_domain</code></pre></td>
<td>Error</td>
<td><pre><code>3221225695 - 0xC00000DF</code></pre></td>
<td>The specified domain did not exist.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_domain_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225696 - 0xC00000E0</code></pre></td>
<td>The specified domain already exists.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_domain_limit_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225697 - 0xC00000E1</code></pre></td>
<td>An attempt was made to exceed the limit on the number of domains per server for this release.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_oplock_not_granted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225698 - 0xC00000E2</code></pre></td>
<td>An error status returned when the opportunistic lock (oplock) request is denied.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_oplock_protocol</code></pre></td>
<td>Error</td>
<td><pre><code>3221225699 - 0xC00000E3</code></pre></td>
<td>An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_internal_db_corruption</code></pre></td>
<td>Error</td>
<td><pre><code>3221225700 - 0xC00000E4</code></pre></td>
<td>This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_internal_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225701 - 0xC00000E5</code></pre></td>
<td>An internal error occurred.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_generic_not_mapped</code></pre></td>
<td>Error</td>
<td><pre><code>3221225702 - 0xC00000E6</code></pre></td>
<td>Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_descriptor_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221225703 - 0xC00000E7</code></pre></td>
<td>Indicates a security descriptor is not in the necessary format (absolute or self-relative).</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_user_buffer</code></pre></td>
<td>Error</td>
<td><pre><code>3221225704 - 0xC00000E8</code></pre></td>
<td>An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unexpected_io_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225705 - 0xC00000E9</code></pre></td>
<td>If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unexpected_mm_create_err</code></pre></td>
<td>Error</td>
<td><pre><code>3221225706 - 0xC00000EA</code></pre></td>
<td>If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unexpected_mm_map_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225707 - 0xC00000EB</code></pre></td>
<td>If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unexpected_mm_extend_err</code></pre></td>
<td>Error</td>
<td><pre><code>3221225708 - 0xC00000EC</code></pre></td>
<td>If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_logon_process</code></pre></td>
<td>Error</td>
<td><pre><code>3221225709 - 0xC00000ED</code></pre></td>
<td>The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_logon_session_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225710 - 0xC00000EE</code></pre></td>
<td>An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_1</code></pre></td>
<td>Error</td>
<td><pre><code>3221225711 - 0xC00000EF</code></pre></td>
<td>An invalid parameter was passed to a service or function as the first argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_2</code></pre></td>
<td>Error</td>
<td><pre><code>3221225712 - 0xC00000F0</code></pre></td>
<td>An invalid parameter was passed to a service or function as the second argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_3</code></pre></td>
<td>Error</td>
<td><pre><code>3221225713 - 0xC00000F1</code></pre></td>
<td>An invalid parameter was passed to a service or function as the third argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_4</code></pre></td>
<td>Error</td>
<td><pre><code>3221225714 - 0xC00000F2</code></pre></td>
<td>An invalid parameter was passed to a service or function as the fourth argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_5</code></pre></td>
<td>Error</td>
<td><pre><code>3221225715 - 0xC00000F3</code></pre></td>
<td>An invalid parameter was passed to a service or function as the fifth argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_6</code></pre></td>
<td>Error</td>
<td><pre><code>3221225716 - 0xC00000F4</code></pre></td>
<td>An invalid parameter was passed to a service or function as the sixth argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_7</code></pre></td>
<td>Error</td>
<td><pre><code>3221225717 - 0xC00000F5</code></pre></td>
<td>An invalid parameter was passed to a service or function as the seventh argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_8</code></pre></td>
<td>Error</td>
<td><pre><code>3221225718 - 0xC00000F6</code></pre></td>
<td>An invalid parameter was passed to a service or function as the eighth argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_9</code></pre></td>
<td>Error</td>
<td><pre><code>3221225719 - 0xC00000F7</code></pre></td>
<td>An invalid parameter was passed to a service or function as the ninth argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_10</code></pre></td>
<td>Error</td>
<td><pre><code>3221225720 - 0xC00000F8</code></pre></td>
<td>An invalid parameter was passed to a service or function as the tenth argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_11</code></pre></td>
<td>Error</td>
<td><pre><code>3221225721 - 0xC00000F9</code></pre></td>
<td>An invalid parameter was passed to a service or function as the eleventh argument.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_parameter_12</code></pre></td>
<td>Error</td>
<td><pre><code>3221225722 - 0xC00000FA</code></pre></td>
<td>An invalid parameter was passed to a service or function as the twelfth argument.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_redirector_not_started</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225723 - 0xC00000FB</code></pre></td>
<td>An attempt was made to access a network file, but the network software was not yet started.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_redirector_started</code></pre></td>
<td>Error</td>
<td><pre><code>3221225724 - 0xC00000FC</code></pre></td>
<td>An attempt was made to start the redirector, but the redirector has already been started.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_stack_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221225725 - 0xC00000FD</code></pre></td>
<td>A new guard page for the stack cannot be created.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_package</code></pre></td>
<td>Error</td>
<td><pre><code>3221225726 - 0xC00000FE</code></pre></td>
<td>A specified authentication package is unknown.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_function_table</code></pre></td>
<td>Error</td>
<td><pre><code>3221225727 - 0xC00000FF</code></pre></td>
<td>A malformed function table was encountered during an unwind operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_variable_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225728 - 0xC0000100</code></pre></td>
<td>Indicates the specified environment variable name was not found in the specified environment block.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_directory_not_empty</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225729 - 0xC0000101</code></pre></td>
<td>Indicates that the directory trying to be deleted is not empty.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_corrupt_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225730 - 0xC0000102</code></pre></td>
<td>{Corrupt File} The file or directory is corrupt and unreadable. Run the Chkdsk utility.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_a_directory</code></pre></td>
<td>Error</td>
<td><pre><code>3221225731 - 0xC0000103</code></pre></td>
<td>A requested opened file is not a directory.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_logon_session_state</code></pre></td>
<td>Error</td>
<td><pre><code>3221225732 - 0xC0000104</code></pre></td>
<td>The logon session is not in a state that is consistent with the requested operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_logon_session_collision</code></pre></td>
<td>Error</td>
<td><pre><code>3221225733 - 0xC0000105</code></pre></td>
<td>An internal LSA error has occurred. An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_name_too_long</code></pre></td>
<td>Error</td>
<td><pre><code>3221225734 - 0xC0000106</code></pre></td>
<td>A specified name string is too long for its intended use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_files_open</code></pre></td>
<td>Error</td>
<td><pre><code>3221225735 - 0xC0000107</code></pre></td>
<td>The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_in_use</code></pre></td>
<td>Error</td>
<td><pre><code>3221225736 - 0xC0000108</code></pre></td>
<td>The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_message_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225737 - 0xC0000109</code></pre></td>
<td>RtlFindMessage could not locate the requested message ID in the message table resource.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_process_is_terminating</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225738 - 0xC000010A</code></pre></td>
<td>An attempt was made to duplicate an object handle into or out of an exiting process.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_logon_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221225739 - 0xC000010B</code></pre></td>
<td>Indicates an invalid value has been provided for the LogonType requested.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_guid_translation</code></pre></td>
<td>Error</td>
<td><pre><code>3221225740 - 0xC000010C</code></pre></td>
<td>Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cannot_impersonate</code></pre></td>
<td>Error</td>
<td><pre><code>3221225741 - 0xC000010D</code></pre></td>
<td>Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_already_loaded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225742 - 0xC000010E</code></pre></td>
<td>Indicates that the specified image is already loaded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_not_present</code></pre></td>
<td>Error</td>
<td><pre><code>3221225743 - 0xC000010F</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_lid_not_exist</code></pre></td>
<td>Error</td>
<td><pre><code>3221225744 - 0xC0000110</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_lid_already_owned</code></pre></td>
<td>Error</td>
<td><pre><code>3221225745 - 0xC0000111</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_not_lid_owner</code></pre></td>
<td>Error</td>
<td><pre><code>3221225746 - 0xC0000112</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_invalid_command</code></pre></td>
<td>Error</td>
<td><pre><code>3221225747 - 0xC0000113</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_invalid_lid</code></pre></td>
<td>Error</td>
<td><pre><code>3221225748 - 0xC0000114</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_selector_not_available</code></pre></td>
<td>Error</td>
<td><pre><code>3221225749 - 0xC0000115</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_abios_invalid_selector</code></pre></td>
<td>Error</td>
<td><pre><code>3221225750 - 0xC0000116</code></pre></td>
<td></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_ldt</code></pre></td>
<td>Error</td>
<td><pre><code>3221225751 - 0xC0000117</code></pre></td>
<td>Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_ldt_size</code></pre></td>
<td>Error</td>
<td><pre><code>3221225752 - 0xC0000118</code></pre></td>
<td>Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_ldt_offset</code></pre></td>
<td>Error</td>
<td><pre><code>3221225753 - 0xC0000119</code></pre></td>
<td>Indicates that the starting value for the LDT information was not an integral multiple of the selector size.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_ldt_descriptor</code></pre></td>
<td>Error</td>
<td><pre><code>3221225754 - 0xC000011A</code></pre></td>
<td>Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_ne_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221225755 - 0xC000011B</code></pre></td>
<td>The specified image file did not have the correct format. It appears to be NE format.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_rxact_invalid_state</code></pre></td>
<td>Error</td>
<td><pre><code>3221225756 - 0xC000011C</code></pre></td>
<td>Indicates that the transaction state of a registry subtree is incompatible with the requested operation. For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_rxact_commit_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225757 - 0xC000011D</code></pre></td>
<td>Indicates an error has occurred during a registry transaction commit. The database has been left in an unknown, but probably inconsistent, state. The state of the registry transaction is left as COMMITTING.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_mapped_file_size_zero</code></pre></td>
<td>Error</td>
<td><pre><code>3221225758 - 0xC000011E</code></pre></td>
<td>An attempt was made to map a file of size zero with the maximum size specified as zero.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_too_many_opened_files</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225759 - 0xC000011F</code></pre></td>
<td>Too many files are opened on a remote server. This error should only be returned by the Windows redirector on a remote drive.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_cancelled</code></pre></td>
<td>Error</td>
<td><pre><code>3221225760 - 0xC0000120</code></pre></td>
<td>The I/O request was canceled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_cannot_delete</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225761 - 0xC0000121</code></pre></td>
<td>An attempt has been made to remove a file or directory that cannot be deleted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_computer_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221225762 - 0xC0000122</code></pre></td>
<td>Indicates a name that was specified as a remote computer name is syntactically invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_file_deleted</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225763 - 0xC0000123</code></pre></td>
<td>An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_special_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221225764 - 0xC0000124</code></pre></td>
<td>Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_special_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225765 - 0xC0000125</code></pre></td>
<td>The operation requested may not be performed on the specified group because it is a built-in special group.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_special_user</code></pre></td>
<td>Error</td>
<td><pre><code>3221225766 - 0xC0000126</code></pre></td>
<td>The operation requested may not be performed on the specified user because it is a built-in special user.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_members_primary_group</code></pre></td>
<td>Error</td>
<td><pre><code>3221225767 - 0xC0000127</code></pre></td>
<td>Indicates a member cannot be removed from a group because the group is currently the member's primary group.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_file_closed</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225768 - 0xC0000128</code></pre></td>
<td>An I/O request other than close and several other special case operations was attempted using a file object that had already been closed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_threads</code></pre></td>
<td>Error</td>
<td><pre><code>3221225769 - 0xC0000129</code></pre></td>
<td>Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_thread_not_in_process</code></pre></td>
<td>Error</td>
<td><pre><code>3221225770 - 0xC000012A</code></pre></td>
<td>An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_token_already_in_use</code></pre></td>
<td>Error</td>
<td><pre><code>3221225771 - 0xC000012B</code></pre></td>
<td>An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pagefile_quota_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225772 - 0xC000012C</code></pre></td>
<td>The page file quota was exceeded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_commitment_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221225773 - 0xC000012D</code></pre></td>
<td>{Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_le_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221225774 - 0xC000012E</code></pre></td>
<td>The specified image file did not have the correct format: it appears to be LE format.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_not_mz</code></pre></td>
<td>Error</td>
<td><pre><code>3221225775 - 0xC000012F</code></pre></td>
<td>The specified image file did not have the correct format: it did not have an initial MZ.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_protect</code></pre></td>
<td>Error</td>
<td><pre><code>3221225776 - 0xC0000130</code></pre></td>
<td>The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_win_16</code></pre></td>
<td>Error</td>
<td><pre><code>3221225777 - 0xC0000131</code></pre></td>
<td>The specified image file did not have the correct format: it appears to be a 16-bit Windows image.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_logon_server_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221225778 - 0xC0000132</code></pre></td>
<td>The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_time_difference_at_dc</code></pre></td>
<td>Error</td>
<td><pre><code>3221225779 - 0xC0000133</code></pre></td>
<td>The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_synchronization_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221225780 - 0xC0000134</code></pre></td>
<td>The SAM database on a Windows&amp;nbsp;Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_dll_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225781 - 0xC0000135</code></pre></td>
<td>{Unable To Locate Component} This application has failed to start because the component was not found. Reinstalling the application may fix this problem.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_open_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225782 - 0xC0000136</code></pre></td>
<td>The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_privilege_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225783 - 0xC0000137</code></pre></td>
<td>{Privilege Failed} The I/O permissions for the process could not be changed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ordinal_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225784 - 0xC0000138</code></pre></td>
<td>{Ordinal Not Found} The ordinal could not be located in the dynamic link library.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_entrypoint_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225785 - 0xC0000139</code></pre></td>
<td>{Entry Point Not Found} The procedure entry point could not be located in the dynamic link library.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_control_c_exit</code></pre></td>
<td>Error</td>
<td><pre><code>3221225786 - 0xC000013A</code></pre></td>
<td>{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_local_disconnect</code></pre></td>
<td>Error</td>
<td><pre><code>3221225787 - 0xC000013B</code></pre></td>
<td>{Virtual Circuit Closed} The network transport on your computer has closed a network connection. There may or may not be I/O requests outstanding.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_disconnect</code></pre></td>
<td>Error</td>
<td><pre><code>3221225788 - 0xC000013C</code></pre></td>
<td>{Virtual Circuit Closed} The network transport on a remote computer has closed a network connection. There may or may not be I/O requests outstanding.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_resources</code></pre></td>
<td>Error</td>
<td><pre><code>3221225789 - 0xC000013D</code></pre></td>
<td>{Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request. For example, the remote computer may not have enough available memory to carry out the request at this time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_link_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225790 - 0xC000013E</code></pre></td>
<td>{Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_link_timeout</code></pre></td>
<td>Error</td>
<td><pre><code>3221225791 - 0xC000013F</code></pre></td>
<td>{Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_connection</code></pre></td>
<td>Error</td>
<td><pre><code>3221225792 - 0xC0000140</code></pre></td>
<td>The connection handle that was given to the transport was invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_address</code></pre></td>
<td>Error</td>
<td><pre><code>3221225793 - 0xC0000141</code></pre></td>
<td>The address handle that was given to the transport was invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_dll_init_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225794 - 0xC0000142</code></pre></td>
<td>{DLL Initialization Failed} Initialization of the dynamic link library failed. The process is terminating abnormally.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_missing_systemfile</code></pre></td>
<td>Error</td>
<td><pre><code>3221225795 - 0xC0000143</code></pre></td>
<td>{Missing System File} The required system file is bad or missing.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unhandled_exception</code></pre></td>
<td>Error</td>
<td><pre><code>3221225796 - 0xC0000144</code></pre></td>
<td>{Application Error} An exception occurred in the application.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_app_init_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225797 - 0xC0000145</code></pre></td>
<td>{Application Error} The application failed to initialize properly. Click OK to terminate the application.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pagefile_create_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225798 - 0xC0000146</code></pre></td>
<td>{Unable to Create Paging File} The creation of the paging file failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_pagefile</code></pre></td>
<td>Error</td>
<td><pre><code>3221225799 - 0xC0000147</code></pre></td>
<td>{No Paging File Specified} No paging file was specified in the system configuration.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_level</code></pre></td>
<td>Error</td>
<td><pre><code>3221225800 - 0xC0000148</code></pre></td>
<td>{Incorrect System Call Level} An invalid level was passed into the specified system call.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wrong_password_core</code></pre></td>
<td>Error</td>
<td><pre><code>3221225801 - 0xC0000149</code></pre></td>
<td>{Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_illegal_float_context</code></pre></td>
<td>Error</td>
<td><pre><code>3221225802 - 0xC000014A</code></pre></td>
<td>{EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pipe_broken</code></pre></td>
<td>Error</td>
<td><pre><code>3221225803 - 0xC000014B</code></pre></td>
<td>The pipe operation has failed because the other end of the pipe has been closed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_registry_corrupt</code></pre></td>
<td>Error</td>
<td><pre><code>3221225804 - 0xC000014C</code></pre></td>
<td>{The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_registry_io_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225805 - 0xC000014D</code></pre></td>
<td>An I/O operation initiated by the Registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_event_pair</code></pre></td>
<td>Error</td>
<td><pre><code>3221225806 - 0xC000014E</code></pre></td>
<td>An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unrecognized_volume</code></pre></td>
<td>Error</td>
<td><pre><code>3221225807 - 0xC000014F</code></pre></td>
<td>The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupt.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_serial_no_device_inited</code></pre></td>
<td>Error</td>
<td><pre><code>3221225808 - 0xC0000150</code></pre></td>
<td>No serial device was successfully initialized. The serial driver will unload.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_alias</code></pre></td>
<td>Error</td>
<td><pre><code>3221225809 - 0xC0000151</code></pre></td>
<td>The specified local group does not exist.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_member_not_in_alias</code></pre></td>
<td>Error</td>
<td><pre><code>3221225810 - 0xC0000152</code></pre></td>
<td>The specified account name is not a member of the group.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_member_in_alias</code></pre></td>
<td>Error</td>
<td><pre><code>3221225811 - 0xC0000153</code></pre></td>
<td>The specified account name is already a member of the group.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_alias_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225812 - 0xC0000154</code></pre></td>
<td>The specified local group already exists.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_logon_not_granted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225813 - 0xC0000155</code></pre></td>
<td>A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system. Ask the system administrator to grant the necessary form of logon.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_secrets</code></pre></td>
<td>Error</td>
<td><pre><code>3221225814 - 0xC0000156</code></pre></td>
<td>The maximum number of secrets that may be stored in a single system was exceeded. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_secret_too_long</code></pre></td>
<td>Error</td>
<td><pre><code>3221225815 - 0xC0000157</code></pre></td>
<td>The length of a secret exceeds the maximum allowable length. The length and number of secrets is limited to satisfy U.S. State Department export restrictions.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_internal_db_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225816 - 0xC0000158</code></pre></td>
<td>The local security authority (LSA) database contains an internal inconsistency.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_fullscreen_mode</code></pre></td>
<td>Error</td>
<td><pre><code>3221225817 - 0xC0000159</code></pre></td>
<td>The requested operation cannot be performed in full-screen mode.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_context_ids</code></pre></td>
<td>Error</td>
<td><pre><code>3221225818 - 0xC000015A</code></pre></td>
<td>During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation. Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_logon_type_not_granted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225819 - 0xC000015B</code></pre></td>
<td>A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_registry_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221225820 - 0xC000015C</code></pre></td>
<td>The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_nt_cross_encryption_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221225821 - 0xC000015D</code></pre></td>
<td>An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_domain_ctrlr_config_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225822 - 0xC000015E</code></pre></td>
<td>A Windows&amp;nbsp;Server has an incorrect configuration.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ft_missing_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221225823 - 0xC000015F</code></pre></td>
<td>An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ill_formed_service_entry</code></pre></td>
<td>Error</td>
<td><pre><code>3221225824 - 0xC0000160</code></pre></td>
<td>A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_illegal_character</code></pre></td>
<td>Error</td>
<td><pre><code>3221225825 - 0xC0000161</code></pre></td>
<td>An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unmappable_character</code></pre></td>
<td>Error</td>
<td><pre><code>3221225826 - 0xC0000162</code></pre></td>
<td>No mapping for the Unicode character exists in the target multibyte code page.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_undefined_character</code></pre></td>
<td>Error</td>
<td><pre><code>3221225827 - 0xC0000163</code></pre></td>
<td>The Unicode character is not defined in the Unicode character set that is installed on the system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_floppy_volume</code></pre></td>
<td>Error</td>
<td><pre><code>3221225828 - 0xC0000164</code></pre></td>
<td>The paging file cannot be created on a floppy disk.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_floppy_id_mark_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225829 - 0xC0000165</code></pre></td>
<td>{Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_floppy_wrong_cylinder</code></pre></td>
<td>Error</td>
<td><pre><code>3221225830 - 0xC0000166</code></pre></td>
<td>{Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_floppy_unknown_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225831 - 0xC0000167</code></pre></td>
<td>{Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_floppy_bad_registers</code></pre></td>
<td>Error</td>
<td><pre><code>3221225832 - 0xC0000168</code></pre></td>
<td>{Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_disk_recalibrate_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225833 - 0xC0000169</code></pre></td>
<td>{Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_disk_operation_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225834 - 0xC000016A</code></pre></td>
<td>{Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_disk_reset_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225835 - 0xC000016B</code></pre></td>
<td>{Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_shared_irq_busy</code></pre></td>
<td>Error</td>
<td><pre><code>3221225836 - 0xC000016C</code></pre></td>
<td>An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened. Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ft_orphaning</code></pre></td>
<td>Error</td>
<td><pre><code>3221225837 - 0xC000016D</code></pre></td>
<td>{FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bios_failed_to_connect_interrupt</code></pre></td>
<td>Error</td>
<td><pre><code>3221225838 - 0xC000016E</code></pre></td>
<td>The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_partition_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225842 - 0xC0000172</code></pre></td>
<td>The tape could not be partitioned.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_block_length</code></pre></td>
<td>Error</td>
<td><pre><code>3221225843 - 0xC0000173</code></pre></td>
<td>When accessing a new tape of a multi-volume partition, the current blocksize is incorrect.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_not_partitioned</code></pre></td>
<td>Error</td>
<td><pre><code>3221225844 - 0xC0000174</code></pre></td>
<td>The tape partition information could not be found when loading a tape.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_unable_to_lock_media</code></pre></td>
<td>Error</td>
<td><pre><code>3221225845 - 0xC0000175</code></pre></td>
<td>An attempt to lock the eject media mechanism failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unable_to_unload_media</code></pre></td>
<td>Error</td>
<td><pre><code>3221225846 - 0xC0000176</code></pre></td>
<td>An attempt to unload media failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_eom_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221225847 - 0xC0000177</code></pre></td>
<td>The physical end of tape was detected.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_media</code></pre></td>
<td>Error</td>
<td><pre><code>3221225848 - 0xC0000178</code></pre></td>
<td>{No Media} There is no media in the drive.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_such_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221225850 - 0xC000017A</code></pre></td>
<td>A member could not be added to or removed from the local group because the member does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221225851 - 0xC000017B</code></pre></td>
<td>A new member could not be added to a local group because the member has the wrong account type.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_key_deleted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225852 - 0xC000017C</code></pre></td>
<td>An illegal operation was attempted on a registry key that has been marked for deletion.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_log_space</code></pre></td>
<td>Error</td>
<td><pre><code>3221225853 - 0xC000017D</code></pre></td>
<td>The system could not allocate the required space in a registry log.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_sids</code></pre></td>
<td>Error</td>
<td><pre><code>3221225854 - 0xC000017E</code></pre></td>
<td>Too many SIDs have been specified.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_lm_cross_encryption_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221225855 - 0xC000017F</code></pre></td>
<td>An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_key_has_children</code></pre></td>
<td>Error</td>
<td><pre><code>3221225856 - 0xC0000180</code></pre></td>
<td>An attempt was made to create a symbolic link in a registry key that already has subkeys or values.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_child_must_be_volatile</code></pre></td>
<td>Error</td>
<td><pre><code>3221225857 - 0xC0000181</code></pre></td>
<td>An attempt was made to create a stable subkey under a volatile parent key.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_configuration_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225858 - 0xC0000182</code></pre></td>
<td>The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_internal_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225859 - 0xC0000183</code></pre></td>
<td>An error was detected between two drivers or within an I/O driver.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_invalid_device_state</code></pre></td>
<td>Error</td>
<td><pre><code>3221225860 - 0xC0000184</code></pre></td>
<td>The device is not in a valid state to perform this request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_device_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225861 - 0xC0000185</code></pre></td>
<td>The I/O device reported an I/O error.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_protocol_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221225862 - 0xC0000186</code></pre></td>
<td>A protocol error was detected between the driver and the device.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_backup_controller</code></pre></td>
<td>Error</td>
<td><pre><code>3221225863 - 0xC0000187</code></pre></td>
<td>This operation is only allowed for the primary domain controller of the domain.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_log_file_full</code></pre></td>
<td>Error</td>
<td><pre><code>3221225864 - 0xC0000188</code></pre></td>
<td>The log file space is insufficient to support this operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_late</code></pre></td>
<td>Error</td>
<td><pre><code>3221225865 - 0xC0000189</code></pre></td>
<td>A write operation was attempted to a volume after it was dismounted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_trust_lsa_secret</code></pre></td>
<td>Error</td>
<td><pre><code>3221225866 - 0xC000018A</code></pre></td>
<td>The workstation does not have a trust secret for the primary domain in the local LSA database.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_trust_sam_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221225867 - 0xC000018B</code></pre></td>
<td>The SAM database on the Windows&amp;nbsp;Server does not have a computer account for this workstation trust relationship.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_trusted_domain_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225868 - 0xC000018C</code></pre></td>
<td>The logon request failed because the trust relationship between the primary domain and the trusted domain failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_trusted_relationship_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225869 - 0xC000018D</code></pre></td>
<td>The logon request failed because the trust relationship between this workstation and the primary domain failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_eventlog_file_corrupt</code></pre></td>
<td>Error</td>
<td><pre><code>3221225870 - 0xC000018E</code></pre></td>
<td>The Eventlog log file is corrupt.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_eventlog_cant_start</code></pre></td>
<td>Error</td>
<td><pre><code>3221225871 - 0xC000018F</code></pre></td>
<td>No Eventlog log file could be opened. The Eventlog service did not start.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_trust_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221225872 - 0xC0000190</code></pre></td>
<td>The network logon failed. This may be because the validation authority cannot be reached.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_mutant_limit_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221225873 - 0xC0000191</code></pre></td>
<td>An attempt was made to acquire a mutant such that its maximum count would have been exceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_netlogon_not_started</code></pre></td>
<td>Error</td>
<td><pre><code>3221225874 - 0xC0000192</code></pre></td>
<td>An attempt was made to logon, but the NetLogon service was not started.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_account_expired</code></pre></td>
<td>Error</td>
<td><pre><code>3221225875 - 0xC0000193</code></pre></td>
<td>The user account has expired.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_possible_deadlock</code></pre></td>
<td>Error</td>
<td><pre><code>3221225876 - 0xC0000194</code></pre></td>
<td>{EXCEPTION} Possible deadlock condition.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_network_credential_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221225877 - 0xC0000195</code></pre></td>
<td>Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_session_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221225878 - 0xC0000196</code></pre></td>
<td>An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_eventlog_file_changed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225879 - 0xC0000197</code></pre></td>
<td>The log file has changed between reads.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_nologon_interdomain_trust_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221225880 - 0xC0000198</code></pre></td>
<td>The account used is an interdomain trust account. Use your global user account or local user account to access this server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_nologon_workstation_trust_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221225881 - 0xC0000199</code></pre></td>
<td>The account used is a computer account. Use your global user account or local user account to access this server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_nologon_server_trust_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221225882 - 0xC000019A</code></pre></td>
<td>The account used is a server trust account. Use your global user account or local user account to access this server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_domain_trust_inconsistent</code></pre></td>
<td>Error</td>
<td><pre><code>3221225883 - 0xC000019B</code></pre></td>
<td>The name or SID of the specified domain is inconsistent with the trust information for that domain.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_fs_driver_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221225884 - 0xC000019C</code></pre></td>
<td>A volume has been accessed for which a file system driver is required that has not yet been loaded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_user_session_key</code></pre></td>
<td>Error</td>
<td><pre><code>3221225986 - 0xC0000202</code></pre></td>
<td>There is no user session key for the specified logon session.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_user_session_deleted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225987 - 0xC0000203</code></pre></td>
<td>The remote user session has been deleted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_lang_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221225988 - 0xC0000204</code></pre></td>
<td>Indicates the specified resource language ID cannot be found in the image file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_insuff_server_resources</code></pre></td>
<td>Warning</td>
<td><pre><code>3221225989 - 0xC0000205</code></pre></td>
<td>Insufficient server resources exist to complete the request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_buffer_size</code></pre></td>
<td>Error</td>
<td><pre><code>3221225990 - 0xC0000206</code></pre></td>
<td>The size of the buffer is invalid for the specified operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_address_component</code></pre></td>
<td>Error</td>
<td><pre><code>3221225991 - 0xC0000207</code></pre></td>
<td>The transport rejected the specified network address as invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_address_wildcard</code></pre></td>
<td>Error</td>
<td><pre><code>3221225992 - 0xC0000208</code></pre></td>
<td>The transport rejected the specified network address due to invalid use of a wildcard.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_addresses</code></pre></td>
<td>Error</td>
<td><pre><code>3221225993 - 0xC0000209</code></pre></td>
<td>The transport address could not be opened because all the available addresses are in use.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_address_already_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221225994 - 0xC000020A</code></pre></td>
<td>The transport address could not be opened because it already exists.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_address_closed</code></pre></td>
<td>Error</td>
<td><pre><code>3221225995 - 0xC000020B</code></pre></td>
<td>The transport address is now closed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_disconnected</code></pre></td>
<td>Error</td>
<td><pre><code>3221225996 - 0xC000020C</code></pre></td>
<td>The transport connection is now disconnected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_reset</code></pre></td>
<td>Error</td>
<td><pre><code>3221225997 - 0xC000020D</code></pre></td>
<td>The transport connection has been reset.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_nodes</code></pre></td>
<td>Error</td>
<td><pre><code>3221225998 - 0xC000020E</code></pre></td>
<td>The transport cannot dynamically acquire any more nodes.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_aborted</code></pre></td>
<td>Error</td>
<td><pre><code>3221225999 - 0xC000020F</code></pre></td>
<td>The transport aborted a pending transaction.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_timed_out</code></pre></td>
<td>Error</td>
<td><pre><code>3221226000 - 0xC0000210</code></pre></td>
<td>The transport timed out a request that is waiting for a response.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_no_release</code></pre></td>
<td>Error</td>
<td><pre><code>3221226001 - 0xC0000211</code></pre></td>
<td>The transport did not receive a release for a pending response.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_no_match</code></pre></td>
<td>Error</td>
<td><pre><code>3221226002 - 0xC0000212</code></pre></td>
<td>The transport did not find a transaction that matches the specific token.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_responded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226003 - 0xC0000213</code></pre></td>
<td>The transport had previously responded to a transaction request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_invalid_id</code></pre></td>
<td>Error</td>
<td><pre><code>3221226004 - 0xC0000214</code></pre></td>
<td>The transport does not recognize the specified transaction request ID.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_transaction_invalid_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221226005 - 0xC0000215</code></pre></td>
<td>The transport does not recognize the specified transaction request type.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_server_session</code></pre></td>
<td>Error</td>
<td><pre><code>3221226006 - 0xC0000216</code></pre></td>
<td>The transport can only process the specified request on the server side of a session.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_client_session</code></pre></td>
<td>Error</td>
<td><pre><code>3221226007 - 0xC0000217</code></pre></td>
<td>The transport can only process the specified request on the client side of a session.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cannot_load_registry_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221226008 - 0xC0000218</code></pre></td>
<td>{Registry File Failure} The registry cannot load the hive (file). It is corrupt, absent, or not writable.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_debug_attach_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226009 - 0xC0000219</code></pre></td>
<td>{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_system_process_terminated</code></pre></td>
<td>Error</td>
<td><pre><code>3221226010 - 0xC000021A</code></pre></td>
<td>{Fatal System Error} The system process terminated unexpectedly. The system has been shut down.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_data_not_accepted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226011 - 0xC000021B</code></pre></td>
<td>{Data Not Accepted} The TDI client could not handle the data received during an indication.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_browser_servers_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226012 - 0xC000021C</code></pre></td>
<td>{Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_vdm_hard_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226013 - 0xC000021D</code></pre></td>
<td>NTVDM encountered a hard error.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_cancel_timeout</code></pre></td>
<td>Error</td>
<td><pre><code>3221226014 - 0xC000021E</code></pre></td>
<td>{Cancel Timeout} The driver failed to complete a canceled I/O request in the allotted time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_reply_message_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226015 - 0xC000021F</code></pre></td>
<td>{Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_mapped_alignment</code></pre></td>
<td>Error</td>
<td><pre><code>3221226016 - 0xC0000220</code></pre></td>
<td>{Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_checksum_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226017 - 0xC0000221</code></pre></td>
<td>{Bad Image Checksum} The image is possibly corrupt. The header checksum does not match the computed checksum.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_lost_writebehind_data</code></pre></td>
<td>Error</td>
<td><pre><code>3221226018 - 0xC0000222</code></pre></td>
<td>{Delayed Write Failed} Windows was unable to save all the data for the file. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_client_server_parameters_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226019 - 0xC0000223</code></pre></td>
<td>The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_status_password_must_change</code></pre></td>
<td>Error</td>
<td><pre><code>3221226020 - 0xC0000224</code></pre></td>
<td>The user password must be changed before logging on the first time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226021 - 0xC0000225</code></pre></td>
<td>The object was not found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_tiny_stream</code></pre></td>
<td>Error</td>
<td><pre><code>3221226022 - 0xC0000226</code></pre></td>
<td>The stream is not a tiny stream.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_recovery_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226023 - 0xC0000227</code></pre></td>
<td>A transaction recovery failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_stack_overflow_read</code></pre></td>
<td>Error</td>
<td><pre><code>3221226024 - 0xC0000228</code></pre></td>
<td>The request must be handled by the stack overflow code.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_fail_check</code></pre></td>
<td>Error</td>
<td><pre><code>3221226025 - 0xC0000229</code></pre></td>
<td>A consistency check failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_duplicate_objectid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226026 - 0xC000022A</code></pre></td>
<td>The attempt to insert the ID in the index failed because the ID is already in the index.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_objectid_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221226027 - 0xC000022B</code></pre></td>
<td>The attempt to set the object ID failed because the object already has an ID.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_convert_to_large</code></pre></td>
<td>Error</td>
<td><pre><code>3221226028 - 0xC000022C</code></pre></td>
<td>Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_retry</code></pre></td>
<td>Error</td>
<td><pre><code>3221226029 - 0xC000022D</code></pre></td>
<td>The request needs to be retried.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_found_out_of_scope</code></pre></td>
<td>Error</td>
<td><pre><code>3221226030 - 0xC000022E</code></pre></td>
<td>The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_allocate_bucket</code></pre></td>
<td>Error</td>
<td><pre><code>3221226031 - 0xC000022F</code></pre></td>
<td>The bucket array must be grown. Retry the transaction after doing so.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_propset_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226032 - 0xC0000230</code></pre></td>
<td>The specified property set does not exist on the object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_marshall_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221226033 - 0xC0000231</code></pre></td>
<td>The user/kernel marshaling buffer has overflowed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_variant</code></pre></td>
<td>Error</td>
<td><pre><code>3221226034 - 0xC0000232</code></pre></td>
<td>The supplied variant structure contains invalid data.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_domain_controller_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226035 - 0xC0000233</code></pre></td>
<td>A domain controller for this domain was not found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_account_locked_out</code></pre></td>
<td>Error</td>
<td><pre><code>3221226036 - 0xC0000234</code></pre></td>
<td>The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_handle_not_closable</code></pre></td>
<td>Warning</td>
<td><pre><code>3221226037 - 0xC0000235</code></pre></td>
<td>NtClose was called on a handle that was protected from close via NtSetInformationObject.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_refused</code></pre></td>
<td>Error</td>
<td><pre><code>3221226038 - 0xC0000236</code></pre></td>
<td>The transport-connection attempt was refused by the remote system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_graceful_disconnect</code></pre></td>
<td>Error</td>
<td><pre><code>3221226039 - 0xC0000237</code></pre></td>
<td>The transport connection was gracefully closed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_address_already_associated</code></pre></td>
<td>Error</td>
<td><pre><code>3221226040 - 0xC0000238</code></pre></td>
<td>The transport endpoint already has an address associated with it.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_address_not_associated</code></pre></td>
<td>Error</td>
<td><pre><code>3221226041 - 0xC0000239</code></pre></td>
<td>An address has not yet been associated with the transport endpoint.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226042 - 0xC000023A</code></pre></td>
<td>An operation was attempted on a nonexistent transport connection.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_active</code></pre></td>
<td>Error</td>
<td><pre><code>3221226043 - 0xC000023B</code></pre></td>
<td>An invalid operation was attempted on an active transport connection.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_network_unreachable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226044 - 0xC000023C</code></pre></td>
<td>The remote network is not reachable by the transport.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_host_unreachable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226045 - 0xC000023D</code></pre></td>
<td>The remote system is not reachable by the transport.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_protocol_unreachable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226046 - 0xC000023E</code></pre></td>
<td>The remote system does not support the transport protocol.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_port_unreachable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226047 - 0xC000023F</code></pre></td>
<td>No service is operating at the destination port of the transport on the remote system.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_request_aborted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226048 - 0xC0000240</code></pre></td>
<td>The request was aborted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_aborted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226049 - 0xC0000241</code></pre></td>
<td>The transport connection was aborted by the local system.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_compression_buffer</code></pre></td>
<td>Error</td>
<td><pre><code>3221226050 - 0xC0000242</code></pre></td>
<td>The specified buffer contains ill-formed data.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_user_mapped_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221226051 - 0xC0000243</code></pre></td>
<td>The requested operation cannot be performed on a file with a user mapped section open.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_audit_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226052 - 0xC0000244</code></pre></td>
<td>{Audit Failed} An attempt to generate a security audit failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_timer_resolution_not_set</code></pre></td>
<td>Error</td>
<td><pre><code>3221226053 - 0xC0000245</code></pre></td>
<td>The timer resolution was not previously set by the current process.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_connection_count_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221226054 - 0xC0000246</code></pre></td>
<td>A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_login_time_restriction</code></pre></td>
<td>Error</td>
<td><pre><code>3221226055 - 0xC0000247</code></pre></td>
<td>Attempting to log on during an unauthorized time of day for this account.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_login_wksta_restriction</code></pre></td>
<td>Error</td>
<td><pre><code>3221226056 - 0xC0000248</code></pre></td>
<td>The account is not authorized to log on from this station.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_image_mp_up_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226057 - 0xC0000249</code></pre></td>
<td>{UP/MP Image Mismatch} The image has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_insufficient_logon_info</code></pre></td>
<td>Error</td>
<td><pre><code>3221226064 - 0xC0000250</code></pre></td>
<td>There is insufficient account information to log you on.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_dll_entrypoint</code></pre></td>
<td>Error</td>
<td><pre><code>3221226065 - 0xC0000251</code></pre></td>
<td>{Invalid DLL Entrypoint} The dynamic link library is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_service_entrypoint</code></pre></td>
<td>Error</td>
<td><pre><code>3221226066 - 0xC0000252</code></pre></td>
<td>{Invalid Service Callback Entrypoint} The service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_lpc_reply_lost</code></pre></td>
<td>Error</td>
<td><pre><code>3221226067 - 0xC0000253</code></pre></td>
<td>The server received the messages but did not send a reply.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ip_address_conflict1</code></pre></td>
<td>Error</td>
<td><pre><code>3221226068 - 0xC0000254</code></pre></td>
<td>There is an IP address conflict with another system on the network.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ip_address_conflict2</code></pre></td>
<td>Error</td>
<td><pre><code>3221226069 - 0xC0000255</code></pre></td>
<td>There is an IP address conflict with another system on the network.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_registry_quota_limit</code></pre></td>
<td>Error</td>
<td><pre><code>3221226070 - 0xC0000256</code></pre></td>
<td>{Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_status_path_not_covered</code></pre></td>
<td>Error</td>
<td><pre><code>3221226071 - 0xC0000257</code></pre></td>
<td>The contacted server does not support the indicated part of the DFS namespace.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_callback_active</code></pre></td>
<td>Error</td>
<td><pre><code>3221226072 - 0xC0000258</code></pre></td>
<td>A callback return system service cannot be executed when no callback is active.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_license_quota_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226073 - 0xC0000259</code></pre></td>
<td>The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has already accepted the maximum number of connections.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pwd_too_short</code></pre></td>
<td>Error</td>
<td><pre><code>3221226074 - 0xC000025A</code></pre></td>
<td>The password provided is too short to meet the policy of your user account. Choose a longer password.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pwd_too_recent</code></pre></td>
<td>Error</td>
<td><pre><code>3221226075 - 0xC000025B</code></pre></td>
<td>The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pwd_history_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221226076 - 0xC000025C</code></pre></td>
<td>You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_plugplay_no_device</code></pre></td>
<td>Error</td>
<td><pre><code>3221226078 - 0xC000025E</code></pre></td>
<td>You have attempted to load a legacy device driver while its device instance had been disabled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unsupported_compression</code></pre></td>
<td>Error</td>
<td><pre><code>3221226079 - 0xC000025F</code></pre></td>
<td>The specified compression format is unsupported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_hw_profile</code></pre></td>
<td>Error</td>
<td><pre><code>3221226080 - 0xC0000260</code></pre></td>
<td>The specified hardware profile configuration is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_plugplay_device_path</code></pre></td>
<td>Error</td>
<td><pre><code>3221226081 - 0xC0000261</code></pre></td>
<td>The specified Plug and Play registry device path is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_ordinal_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226082 - 0xC0000262</code></pre></td>
<td>{Driver Entry Point Not Found} The device driver could not locate the ordinal in driver.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_entrypoint_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226083 - 0xC0000263</code></pre></td>
<td>{Driver Entry Point Not Found} The device driver could not locate the entry point in driver.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_resource_not_owned</code></pre></td>
<td>Error</td>
<td><pre><code>3221226084 - 0xC0000264</code></pre></td>
<td>{Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_links</code></pre></td>
<td>Error</td>
<td><pre><code>3221226085 - 0xC0000265</code></pre></td>
<td>An attempt was made to create more links on a file than the file system supports.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_quota_list_inconsistent</code></pre></td>
<td>Error</td>
<td><pre><code>3221226086 - 0xC0000266</code></pre></td>
<td>The specified quota list is internally inconsistent with its descriptor.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_is_offline</code></pre></td>
<td>Error</td>
<td><pre><code>3221226087 - 0xC0000267</code></pre></td>
<td>The specified file has been relocated to offline storage.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_evaluation_expiration</code></pre></td>
<td>Error</td>
<td><pre><code>3221226088 - 0xC0000268</code></pre></td>
<td>{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_illegal_dll_relocation</code></pre></td>
<td>Error</td>
<td><pre><code>3221226089 - 0xC0000269</code></pre></td>
<td>{Illegal System DLL Relocation} The system DLL was relocated in memory. The application will not run properly. The relocation occurred because the DLL occupied an address range that is reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_license_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221226090 - 0xC000026A</code></pre></td>
<td>{License Violation} The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with the product type is not permitted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_dll_init_failed_logoff</code></pre></td>
<td>Error</td>
<td><pre><code>3221226091 - 0xC000026B</code></pre></td>
<td>{DLL Initialization Failed} The application failed to initialize because the window station is shutting down.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_unable_to_load</code></pre></td>
<td>Error</td>
<td><pre><code>3221226092 - 0xC000026C</code></pre></td>
<td>{Unable to Load Device Driver} The device driver could not be loaded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_dfs_unavailable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226093 - 0xC000026D</code></pre></td>
<td>DFS is unavailable on the contacted server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_volume_dismounted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226094 - 0xC000026E</code></pre></td>
<td>An operation was attempted to a volume after it was dismounted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_internal_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226095 - 0xC000026F</code></pre></td>
<td>An internal error occurred in the Win32 x86 emulation subsystem.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wx86_float_stack_check</code></pre></td>
<td>Error</td>
<td><pre><code>3221226096 - 0xC0000270</code></pre></td>
<td>Win32 x86 emulation subsystem floating-point stack check.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_validate_continue</code></pre></td>
<td>Error</td>
<td><pre><code>3221226097 - 0xC0000271</code></pre></td>
<td>The validation process needs to continue on to the next step.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_match</code></pre></td>
<td>Error</td>
<td><pre><code>3221226098 - 0xC0000272</code></pre></td>
<td>There was no match for the specified key in the index.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_more_matches</code></pre></td>
<td>Error</td>
<td><pre><code>3221226099 - 0xC0000273</code></pre></td>
<td>There are no more matches for the current index enumeration.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_a_reparse_point</code></pre></td>
<td>Error</td>
<td><pre><code>3221226101 - 0xC0000275</code></pre></td>
<td>The NTFS file or directory is not a reparse point.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_reparse_tag_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226102 - 0xC0000276</code></pre></td>
<td>The Windows I/O reparse tag passed for the NTFS reparse point is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_reparse_tag_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226103 - 0xC0000277</code></pre></td>
<td>The Windows I/O reparse tag does not match the one that is in the NTFS reparse point.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_reparse_data_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226104 - 0xC0000278</code></pre></td>
<td>The user data passed for the NTFS reparse point is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_io_reparse_tag_not_handled</code></pre></td>
<td>Error</td>
<td><pre><code>3221226105 - 0xC0000279</code></pre></td>
<td>The layered file system driver for this I/O tag did not handle it when needed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_reparse_point_not_resolved</code></pre></td>
<td>Error</td>
<td><pre><code>3221226112 - 0xC0000280</code></pre></td>
<td>The NTFS symbolic link could not be resolved even though the initial file name is valid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_directory_is_a_reparse_point</code></pre></td>
<td>Error</td>
<td><pre><code>3221226113 - 0xC0000281</code></pre></td>
<td>The NTFS directory is a reparse point.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_range_list_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221226114 - 0xC0000282</code></pre></td>
<td>The range could not be added to the range list because of a conflict.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_source_element_empty</code></pre></td>
<td>Error</td>
<td><pre><code>3221226115 - 0xC0000283</code></pre></td>
<td>The specified medium changer source element contains no media.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_destination_element_full</code></pre></td>
<td>Error</td>
<td><pre><code>3221226116 - 0xC0000284</code></pre></td>
<td>The specified medium changer destination element already contains media.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_illegal_element_address</code></pre></td>
<td>Error</td>
<td><pre><code>3221226117 - 0xC0000285</code></pre></td>
<td>The specified medium changer element does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_magazine_not_present</code></pre></td>
<td>Error</td>
<td><pre><code>3221226118 - 0xC0000286</code></pre></td>
<td>The specified element is contained in a magazine that is no longer present.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_reinitialization_needed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226119 - 0xC0000287</code></pre></td>
<td>The device requires re-initialization due to hardware errors.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_encryption_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226122 - 0xC000028A</code></pre></td>
<td>The file encryption attempt failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_decryption_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226123 - 0xC000028B</code></pre></td>
<td>The file decryption attempt failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_range_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226124 - 0xC000028C</code></pre></td>
<td>The specified range could not be found in the range list.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_recovery_policy</code></pre></td>
<td>Error</td>
<td><pre><code>3221226125 - 0xC000028D</code></pre></td>
<td>There is no encryption recovery policy configured for this system.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_efs</code></pre></td>
<td>Error</td>
<td><pre><code>3221226126 - 0xC000028E</code></pre></td>
<td>The required encryption driver is not loaded for this system.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wrong_efs</code></pre></td>
<td>Error</td>
<td><pre><code>3221226127 - 0xC000028F</code></pre></td>
<td>The file was encrypted with a different encryption driver than is currently loaded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_user_keys</code></pre></td>
<td>Error</td>
<td><pre><code>3221226128 - 0xC0000290</code></pre></td>
<td>There are no EFS keys defined for the user.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_not_encrypted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226129 - 0xC0000291</code></pre></td>
<td>The specified file is not encrypted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_export_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221226130 - 0xC0000292</code></pre></td>
<td>The specified file is not in the defined EFS export format.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_file_encrypted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226131 - 0xC0000293</code></pre></td>
<td>The specified file is encrypted and the user does not have the ability to decrypt it.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_guid_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226133 - 0xC0000295</code></pre></td>
<td>The GUID passed was not recognized as valid by a WMI data provider.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_instance_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226134 - 0xC0000296</code></pre></td>
<td>The instance name passed was not recognized as valid by a WMI data provider.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_itemid_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226135 - 0xC0000297</code></pre></td>
<td>The data item ID passed was not recognized as valid by a WMI data provider.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_try_again</code></pre></td>
<td>Error</td>
<td><pre><code>3221226136 - 0xC0000298</code></pre></td>
<td>The WMI request could not be completed and should be retried.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_shared_policy</code></pre></td>
<td>Error</td>
<td><pre><code>3221226137 - 0xC0000299</code></pre></td>
<td>The policy object is shared and can only be modified at the root.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_policy_object_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226138 - 0xC000029A</code></pre></td>
<td>The policy object does not exist when it should.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_policy_only_in_ds</code></pre></td>
<td>Error</td>
<td><pre><code>3221226139 - 0xC000029B</code></pre></td>
<td>The requested policy information only lives in the Ds.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_volume_not_upgraded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226140 - 0xC000029C</code></pre></td>
<td>The volume must be upgraded to enable this feature.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_storage_not_active</code></pre></td>
<td>Error</td>
<td><pre><code>3221226141 - 0xC000029D</code></pre></td>
<td>The remote storage service is not operational at this time.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_remote_storage_media_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226142 - 0xC000029E</code></pre></td>
<td>The remote storage service encountered a media error.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_tracking_service</code></pre></td>
<td>Error</td>
<td><pre><code>3221226143 - 0xC000029F</code></pre></td>
<td>The tracking (workstation) service is not running.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_server_sid_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226144 - 0xC00002A0</code></pre></td>
<td>The server process is running under a SID that is different from the SID that is required by client.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_attribute_or_value</code></pre></td>
<td>Error</td>
<td><pre><code>3221226145 - 0xC00002A1</code></pre></td>
<td>The specified directory service attribute or value does not exist.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_invalid_attribute_syntax</code></pre></td>
<td>Error</td>
<td><pre><code>3221226146 - 0xC00002A2</code></pre></td>
<td>The attribute syntax specified to the directory service is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_attribute_type_undefined</code></pre></td>
<td>Error</td>
<td><pre><code>3221226147 - 0xC00002A3</code></pre></td>
<td>The attribute type specified to the directory service is not defined.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_attribute_or_value_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221226148 - 0xC00002A4</code></pre></td>
<td>The specified directory service attribute or value already exists.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_busy</code></pre></td>
<td>Error</td>
<td><pre><code>3221226149 - 0xC00002A5</code></pre></td>
<td>The directory service is busy.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_unavailable</code></pre></td>
<td>Error</td>
<td><pre><code>3221226150 - 0xC00002A6</code></pre></td>
<td>The directory service is unavailable.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_rids_allocated</code></pre></td>
<td>Error</td>
<td><pre><code>3221226151 - 0xC00002A7</code></pre></td>
<td>The directory service was unable to allocate a relative identifier.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_more_rids</code></pre></td>
<td>Error</td>
<td><pre><code>3221226152 - 0xC00002A8</code></pre></td>
<td>The directory service has exhausted the pool of relative identifiers.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_incorrect_role_owner</code></pre></td>
<td>Error</td>
<td><pre><code>3221226153 - 0xC00002A9</code></pre></td>
<td>The requested operation could not be performed because the directory service is not the master for that type of operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_ridmgr_init_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226154 - 0xC00002AA</code></pre></td>
<td>The directory service was unable to initialize the subsystem that allocates relative identifiers.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_obj_class_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221226155 - 0xC00002AB</code></pre></td>
<td>The requested operation did not satisfy one or more constraints that are associated with the class of the object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cant_on_non_leaf</code></pre></td>
<td>Error</td>
<td><pre><code>3221226156 - 0xC00002AC</code></pre></td>
<td>The directory service can perform the requested operation only on a leaf object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cant_on_rdn</code></pre></td>
<td>Error</td>
<td><pre><code>3221226157 - 0xC00002AD</code></pre></td>
<td>The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cant_mod_obj_class</code></pre></td>
<td>Error</td>
<td><pre><code>3221226158 - 0xC00002AE</code></pre></td>
<td>The directory service detected an attempt to modify the object class of an object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cross_dom_move_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226159 - 0xC00002AF</code></pre></td>
<td>An error occurred while performing a cross domain move operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_gc_not_available</code></pre></td>
<td>Error</td>
<td><pre><code>3221226160 - 0xC00002B0</code></pre></td>
<td>Unable to contact the global catalog server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_directory_service_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221226161 - 0xC00002B1</code></pre></td>
<td>The requested operation requires a directory service, and none was available.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_reparse_attribute_conflict</code></pre></td>
<td>Error</td>
<td><pre><code>3221226162 - 0xC00002B2</code></pre></td>
<td>The reparse attribute cannot be set because it is incompatible with an existing attribute.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cant_enable_deny_only</code></pre></td>
<td>Error</td>
<td><pre><code>3221226163 - 0xC00002B3</code></pre></td>
<td>A group marked 'use for deny only' cannot be enabled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_multiple_faults</code></pre></td>
<td>Error</td>
<td><pre><code>3221226164 - 0xC00002B4</code></pre></td>
<td>{EXCEPTION} Multiple floating-point faults.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_float_multiple_traps</code></pre></td>
<td>Error</td>
<td><pre><code>3221226165 - 0xC00002B5</code></pre></td>
<td>{EXCEPTION} Multiple floating-point traps.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_removed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226166 - 0xC00002B6</code></pre></td>
<td>The device has been removed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_journal_delete_in_progress</code></pre></td>
<td>Error</td>
<td><pre><code>3221226167 - 0xC00002B7</code></pre></td>
<td>The volume change journal is being deleted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_journal_not_active</code></pre></td>
<td>Error</td>
<td><pre><code>3221226168 - 0xC00002B8</code></pre></td>
<td>The volume change journal is not active.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_nointerface</code></pre></td>
<td>Error</td>
<td><pre><code>3221226169 - 0xC00002B9</code></pre></td>
<td>The requested interface is not supported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_admin_limit_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226177 - 0xC00002C1</code></pre></td>
<td>A directory service resource limit has been exceeded.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_failed_sleep</code></pre></td>
<td>Error</td>
<td><pre><code>3221226178 - 0xC00002C2</code></pre></td>
<td>{System Standby Failed} The driver does not support standby mode. Updating this driver may allow the system to go to standby mode.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_mutual_authentication_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226179 - 0xC00002C3</code></pre></td>
<td>Mutual Authentication failed. The server password is out of date at the domain controller.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_corrupt_system_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221226180 - 0xC00002C4</code></pre></td>
<td>The system file has become corrupt and has been replaced.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_datatype_misalignment_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226181 - 0xC00002C5</code></pre></td>
<td>{EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_read_only</code></pre></td>
<td>Error</td>
<td><pre><code>3221226182 - 0xC00002C6</code></pre></td>
<td>The WMI data item or data block is read-only.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_set_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226183 - 0xC00002C7</code></pre></td>
<td>The WMI data item or data block could not be changed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_commitment_minimum</code></pre></td>
<td>Error</td>
<td><pre><code>3221226184 - 0xC00002C8</code></pre></td>
<td>{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_reg_nat_consumption</code></pre></td>
<td>Error</td>
<td><pre><code>3221226185 - 0xC00002C9</code></pre></td>
<td>{EXCEPTION} Register NaT consumption faults. A NaT value is consumed on a non-speculative instruction.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_transport_full</code></pre></td>
<td>Error</td>
<td><pre><code>3221226186 - 0xC00002CA</code></pre></td>
<td>The transport element of the medium changer contains media, which is causing the operation to fail.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_sam_init_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226187 - 0xC00002CB</code></pre></td>
<td>Security Accounts Manager initialization failed. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_only_if_connected</code></pre></td>
<td>Error</td>
<td><pre><code>3221226188 - 0xC00002CC</code></pre></td>
<td>This operation is supported only when you are connected to the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_sensitive_group_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221226189 - 0xC00002CD</code></pre></td>
<td>Only an administrator can modify the membership list of an administrative group.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pnp_restart_enumeration</code></pre></td>
<td>Error</td>
<td><pre><code>3221226190 - 0xC00002CE</code></pre></td>
<td>A device was removed so enumeration must be restarted.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_journal_entry_deleted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226191 - 0xC00002CF</code></pre></td>
<td>The journal entry has been deleted from the journal.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cant_mod_primarygroupid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226192 - 0xC00002D0</code></pre></td>
<td>Cannot change the primary group ID of a domain controller account.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_system_image_bad_signature</code></pre></td>
<td>Error</td>
<td><pre><code>3221226193 - 0xC00002D1</code></pre></td>
<td>{Fatal System Error} The system image is not properly signed. The file has been replaced with the signed file. The system has been shut down.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pnp_reboot_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221226194 - 0xC00002D2</code></pre></td>
<td>The device will not start without a reboot.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_power_state_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226195 - 0xC00002D3</code></pre></td>
<td>The power state of the current device cannot support this request.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_invalid_group_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221226196 - 0xC00002D4</code></pre></td>
<td>The specified group type is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_nest_globalgroup_in_mixeddomain</code></pre></td>
<td>Error</td>
<td><pre><code>3221226197 - 0xC00002D5</code></pre></td>
<td>In a mixed domain, no nesting of a global group if the group is security enabled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_nest_localgroup_in_mixeddomain</code></pre></td>
<td>Error</td>
<td><pre><code>3221226198 - 0xC00002D6</code></pre></td>
<td>In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_global_cant_have_local_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226199 - 0xC00002D7</code></pre></td>
<td>A global group cannot have a local group as a member.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_global_cant_have_universal_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226200 - 0xC00002D8</code></pre></td>
<td>A global group cannot have a universal group as a member.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_universal_cant_have_local_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226201 - 0xC00002D9</code></pre></td>
<td>A universal group cannot have a local group as a member.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_global_cant_have_crossdomain_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226202 - 0xC00002DA</code></pre></td>
<td>A global group cannot have a cross-domain member.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_local_cant_have_crossdomain_local_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226203 - 0xC00002DB</code></pre></td>
<td>A local group cannot have another cross-domain local group as a member.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_have_primary_members</code></pre></td>
<td>Error</td>
<td><pre><code>3221226204 - 0xC00002DC</code></pre></td>
<td>Cannot change to a security-disabled group because primary members are in this group.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_not_supported</code></pre></td>
<td>Error</td>
<td><pre><code>3221226205 - 0xC00002DD</code></pre></td>
<td>The WMI operation is not supported by the data block or method.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_insufficient_power</code></pre></td>
<td>Error</td>
<td><pre><code>3221226206 - 0xC00002DE</code></pre></td>
<td>There is not enough power to complete the requested operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_sam_need_bootkey_password</code></pre></td>
<td>Error</td>
<td><pre><code>3221226207 - 0xC00002DF</code></pre></td>
<td>The Security Accounts Manager needs to get the boot password.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_sam_need_bootkey_floppy</code></pre></td>
<td>Error</td>
<td><pre><code>3221226208 - 0xC00002E0</code></pre></td>
<td>The Security Accounts Manager needs to get the boot key from the floppy disk.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_cant_start</code></pre></td>
<td>Error</td>
<td><pre><code>3221226209 - 0xC00002E1</code></pre></td>
<td>The directory service cannot start.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_init_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226210 - 0xC00002E2</code></pre></td>
<td>The directory service could not start. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_sam_init_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226211 - 0xC00002E3</code></pre></td>
<td>The Security Accounts Manager initialization failed. Click OK to shut down this system and restart in Safe Mode. Check the event log for more detailed information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_gc_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221226212 - 0xC00002E4</code></pre></td>
<td>The requested operation can be performed only on a global catalog server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_local_member_of_local_only</code></pre></td>
<td>Error</td>
<td><pre><code>3221226213 - 0xC00002E5</code></pre></td>
<td>A local group can only be a member of other local groups in the same domain.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_no_fpo_in_universal_groups</code></pre></td>
<td>Error</td>
<td><pre><code>3221226214 - 0xC00002E6</code></pre></td>
<td>Foreign security principals cannot be members of universal groups.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_machine_account_quota_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226215 - 0xC00002E7</code></pre></td>
<td>Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_multiple_fault_violation</code></pre></td>
<td>Error</td>
<td><pre><code>3221226216 - 0xC00002E8</code></pre></td>
<td></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_current_domain_not_allowed</code></pre></td>
<td>Error</td>
<td><pre><code>3221226217 - 0xC00002E9</code></pre></td>
<td>This operation cannot be performed on the current domain.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_cannot_make</code></pre></td>
<td>Error</td>
<td><pre><code>3221226218 - 0xC00002EA</code></pre></td>
<td>The directory or file cannot be created.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_system_shutdown</code></pre></td>
<td>Error</td>
<td><pre><code>3221226219 - 0xC00002EB</code></pre></td>
<td>The system is in the process of shutting down.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_init_failure_console</code></pre></td>
<td>Error</td>
<td><pre><code>3221226220 - 0xC00002EC</code></pre></td>
<td>Directory Services could not start. Click OK to shut down the system. You can use the recovery console to diagnose the system further.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_sam_init_failure_console</code></pre></td>
<td>Error</td>
<td><pre><code>3221226221 - 0xC00002ED</code></pre></td>
<td>Security Accounts Manager initialization failed. Click OK to shut down the system. You can use the recovery console to diagnose the system further.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unfinished_context_deleted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226222 - 0xC00002EE</code></pre></td>
<td>A security context was deleted before the context was completed. This is considered a logon failure.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_tgt_reply</code></pre></td>
<td>Error</td>
<td><pre><code>3221226223 - 0xC00002EF</code></pre></td>
<td>The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_objectid_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221226224 - 0xC00002F0</code></pre></td>
<td>An object ID was not found in the file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_ip_addresses</code></pre></td>
<td>Error</td>
<td><pre><code>3221226225 - 0xC00002F1</code></pre></td>
<td>Unable to accomplish the requested task because the local machine does not have any IP addresses.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wrong_credential_handle</code></pre></td>
<td>Error</td>
<td><pre><code>3221226226 - 0xC00002F2</code></pre></td>
<td>The supplied credential handle does not match the credential that is associated with the security context.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_crypto_system_invalid</code></pre></td>
<td>Error</td>
<td><pre><code>3221226227 - 0xC00002F3</code></pre></td>
<td>The crypto system or checksum function is invalid because a required function is unavailable.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_max_referrals_exceeded</code></pre></td>
<td>Error</td>
<td><pre><code>3221226228 - 0xC00002F4</code></pre></td>
<td>The number of maximum ticket referrals has been exceeded.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_must_be_kdc</code></pre></td>
<td>Error</td>
<td><pre><code>3221226229 - 0xC00002F5</code></pre></td>
<td>The local machine must be a Kerberos KDC (domain controller) and it is not.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_strong_crypto_not_supported</code></pre></td>
<td>Error</td>
<td><pre><code>3221226230 - 0xC00002F6</code></pre></td>
<td>The other end of the security negotiation requires strong crypto but it is not supported on the local machine.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_too_many_principals</code></pre></td>
<td>Error</td>
<td><pre><code>3221226231 - 0xC00002F7</code></pre></td>
<td>The KDC reply contained more than one principal name.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_pa_data</code></pre></td>
<td>Error</td>
<td><pre><code>3221226232 - 0xC00002F8</code></pre></td>
<td>Expected to find PA data for a hint of what etype to use, but it was not found.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pkinit_name_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226233 - 0xC00002F9</code></pre></td>
<td>The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_logon_required</code></pre></td>
<td>Error</td>
<td><pre><code>3221226234 - 0xC00002FA</code></pre></td>
<td>Smart card logon is required and was not used.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_kdc_invalid_request</code></pre></td>
<td>Error</td>
<td><pre><code>3221226235 - 0xC00002FB</code></pre></td>
<td>An invalid request was sent to the KDC.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_kdc_unable_to_refer</code></pre></td>
<td>Error</td>
<td><pre><code>3221226236 - 0xC00002FC</code></pre></td>
<td>The KDC was unable to generate a referral for the service requested.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_kdc_unknown_etype</code></pre></td>
<td>Error</td>
<td><pre><code>3221226237 - 0xC00002FD</code></pre></td>
<td>The encryption type requested is not supported by the KDC.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_shutdown_in_progress</code></pre></td>
<td>Error</td>
<td><pre><code>3221226238 - 0xC00002FE</code></pre></td>
<td>A system shutdown is in progress.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_server_shutdown_in_progress</code></pre></td>
<td>Error</td>
<td><pre><code>3221226239 - 0xC00002FF</code></pre></td>
<td>The server machine is shutting down.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_supported_on_sbs</code></pre></td>
<td>Error</td>
<td><pre><code>3221226240 - 0xC0000300</code></pre></td>
<td>This operation is not supported on a computer running Windows Server&amp;nbsp;2003 for Small Business Server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_guid_disconnected</code></pre></td>
<td>Error</td>
<td><pre><code>3221226241 - 0xC0000301</code></pre></td>
<td>The WMI GUID is no longer available.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_already_disabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221226242 - 0xC0000302</code></pre></td>
<td>Collection or events for the WMI GUID is already disabled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_wmi_already_enabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221226243 - 0xC0000303</code></pre></td>
<td>Collection or events for the WMI GUID is already enabled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_mft_too_fragmented</code></pre></td>
<td>Error</td>
<td><pre><code>3221226244 - 0xC0000304</code></pre></td>
<td>The master file table on the volume is too fragmented to complete this operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_copy_protection_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226245 - 0xC0000305</code></pre></td>
<td>Copy protection failure.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_authentication_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226246 - 0xC0000306</code></pre></td>
<td>Copy protection error—DVD CSS Authentication failed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_key_not_present</code></pre></td>
<td>Error</td>
<td><pre><code>3221226247 - 0xC0000307</code></pre></td>
<td>Copy protection error—The specified sector does not contain a valid key.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_key_not_established</code></pre></td>
<td>Error</td>
<td><pre><code>3221226248 - 0xC0000308</code></pre></td>
<td>Copy protection error—DVD session key not established.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_scrambled_sector</code></pre></td>
<td>Error</td>
<td><pre><code>3221226249 - 0xC0000309</code></pre></td>
<td>Copy protection error—The read failed because the sector is encrypted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_region_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221226250 - 0xC000030A</code></pre></td>
<td>Copy protection error—The region of the specified DVD does not correspond to the region setting of the drive.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_css_resets_exhausted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226251 - 0xC000030B</code></pre></td>
<td>Copy protection error—The region setting of the drive may be permanent.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_pkinit_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226272 - 0xC0000320</code></pre></td>
<td>The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon. There is more information in the system event log.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_subsystem_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226273 - 0xC0000321</code></pre></td>
<td>The Kerberos protocol encountered an error while attempting to use the smart card subsystem.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_no_kerb_key</code></pre></td>
<td>Error</td>
<td><pre><code>3221226274 - 0xC0000322</code></pre></td>
<td>The target server does not have acceptable Kerberos credentials.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_host_down</code></pre></td>
<td>Error</td>
<td><pre><code>3221226320 - 0xC0000350</code></pre></td>
<td>The transport determined that the remote system is down.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_unsupported_preauth</code></pre></td>
<td>Error</td>
<td><pre><code>3221226321 - 0xC0000351</code></pre></td>
<td>An unsupported pre-authentication mechanism was presented to the Kerberos package.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_efs_alg_blob_too_big</code></pre></td>
<td>Error</td>
<td><pre><code>3221226322 - 0xC0000352</code></pre></td>
<td>The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_port_not_set</code></pre></td>
<td>Error</td>
<td><pre><code>3221226323 - 0xC0000353</code></pre></td>
<td>An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_debugger_inactive</code></pre></td>
<td>Error</td>
<td><pre><code>3221226324 - 0xC0000354</code></pre></td>
<td>An attempt to do an operation on a debug port failed because the port is in the process of being deleted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_version_check_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226325 - 0xC0000355</code></pre></td>
<td>This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_auditing_disabled</code></pre></td>
<td>Error</td>
<td><pre><code>3221226326 - 0xC0000356</code></pre></td>
<td>The specified event is currently not being audited.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_prent4_machine_account</code></pre></td>
<td>Error</td>
<td><pre><code>3221226327 - 0xC0000357</code></pre></td>
<td>The machine account was created prior to Windows&amp;nbsp;NT 4.0. The account needs to be recreated.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_ds_ag_cant_have_universal_member</code></pre></td>
<td>Error</td>
<td><pre><code>3221226328 - 0xC0000358</code></pre></td>
<td>An account group cannot have a universal group as a member.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_win_32</code></pre></td>
<td>Error</td>
<td><pre><code>3221226329 - 0xC0000359</code></pre></td>
<td>The specified image file did not have the correct format; it appears to be a 32-bit Windows image.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_image_win_64</code></pre></td>
<td>Error</td>
<td><pre><code>3221226330 - 0xC000035A</code></pre></td>
<td>The specified image file did not have the correct format; it appears to be a 64-bit Windows image.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_bad_bindings</code></pre></td>
<td>Error</td>
<td><pre><code>3221226331 - 0xC000035B</code></pre></td>
<td>The client's supplied SSPI channel bindings were incorrect.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_network_session_expired</code></pre></td>
<td>Error</td>
<td><pre><code>3221226332 - 0xC000035C</code></pre></td>
<td>The client session has expired; so the client must re-authenticate to continue accessing the remote resources.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_apphelp_block</code></pre></td>
<td>Error</td>
<td><pre><code>3221226333 - 0xC000035D</code></pre></td>
<td>The AppHelp dialog box canceled; thus preventing the application from starting.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_all_sids_filtered</code></pre></td>
<td>Error</td>
<td><pre><code>3221226334 - 0xC000035E</code></pre></td>
<td>The SID filtering operation removed all SIDs.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_not_safe_mode_driver</code></pre></td>
<td>Error</td>
<td><pre><code>3221226335 - 0xC000035F</code></pre></td>
<td>The driver was not loaded because the system is starting in safe mode.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_access_disabled_by_policy_default</code></pre></td>
<td>Error</td>
<td><pre><code>3221226337 - 0xC0000361</code></pre></td>
<td>Access has been restricted by your Administrator by the default software restriction policy level.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_access_disabled_by_policy_path</code></pre></td>
<td>Error</td>
<td><pre><code>3221226338 - 0xC0000362</code></pre></td>
<td>Access has been restricted by your Administrator by location with policy rule.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_access_disabled_by_policy_publisher</code></pre></td>
<td>Error</td>
<td><pre><code>3221226339 - 0xC0000363</code></pre></td>
<td>Access has been restricted by your Administrator by software publisher policy.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_access_disabled_by_policy_other</code></pre></td>
<td>Error</td>
<td><pre><code>3221226340 - 0xC0000364</code></pre></td>
<td>Access to has been restricted by your Administrator by policy rule.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_failed_driver_entry</code></pre></td>
<td>Error</td>
<td><pre><code>3221226341 - 0xC0000365</code></pre></td>
<td>The driver was not loaded because it failed its initialization call.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_device_enumeration_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226342 - 0xC0000366</code></pre></td>
<td>The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_mount_point_not_resolved</code></pre></td>
<td>Error</td>
<td><pre><code>3221226344 - 0xC0000368</code></pre></td>
<td>The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_device_object_parameter</code></pre></td>
<td>Error</td>
<td><pre><code>3221226345 - 0xC0000369</code></pre></td>
<td>The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_mca_occured</code></pre></td>
<td>Error</td>
<td><pre><code>3221226346 - 0xC000036A</code></pre></td>
<td>A machine check error has occurred. Check the system event log for additional information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_blocked_critical</code></pre></td>
<td>Error</td>
<td><pre><code>3221226347 - 0xC000036B</code></pre></td>
<td>Driver has been blocked from loading.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_blocked</code></pre></td>
<td>Error</td>
<td><pre><code>3221226348 - 0xC000036C</code></pre></td>
<td>Driver has been blocked from loading.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_database_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226349 - 0xC000036D</code></pre></td>
<td>There was error processing the driver database.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_system_hive_too_large</code></pre></td>
<td>Error</td>
<td><pre><code>3221226350 - 0xC000036E</code></pre></td>
<td>System hive size has exceeded its limit.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_invalid_import_of_non_dll</code></pre></td>
<td>Error</td>
<td><pre><code>3221226351 - 0xC000036F</code></pre></td>
<td>A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_wrong_pin</code></pre></td>
<td>Error</td>
<td><pre><code>3221226368 - 0xC0000380</code></pre></td>
<td>An incorrect PIN was presented to the smart card.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_card_blocked</code></pre></td>
<td>Error</td>
<td><pre><code>3221226369 - 0xC0000381</code></pre></td>
<td>The smart card is blocked.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_card_not_authenticated</code></pre></td>
<td>Error</td>
<td><pre><code>3221226370 - 0xC0000382</code></pre></td>
<td>No PIN was presented to the smart card.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_no_card</code></pre></td>
<td>Error</td>
<td><pre><code>3221226371 - 0xC0000383</code></pre></td>
<td>No smart card is available.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_no_key_container</code></pre></td>
<td>Error</td>
<td><pre><code>3221226372 - 0xC0000384</code></pre></td>
<td>The requested key container does not exist on the smart card.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_no_certificate</code></pre></td>
<td>Error</td>
<td><pre><code>3221226373 - 0xC0000385</code></pre></td>
<td>The requested certificate does not exist on the smart card.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_no_keyset</code></pre></td>
<td>Error</td>
<td><pre><code>3221226374 - 0xC0000386</code></pre></td>
<td>The requested keyset does not exist.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_io_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221226375 - 0xC0000387</code></pre></td>
<td>A communication error with the smart card has been detected.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_downgrade_detected</code></pre></td>
<td>Error</td>
<td><pre><code>3221226376 - 0xC0000388</code></pre></td>
<td>The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_cert_revoked</code></pre></td>
<td>Error</td>
<td><pre><code>3221226377 - 0xC0000389</code></pre></td>
<td>The smart card certificate used for authentication has been revoked. Contact your system administrator. There may be additional information in the event log.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_issuing_ca_untrusted</code></pre></td>
<td>Error</td>
<td><pre><code>3221226378 - 0xC000038A</code></pre></td>
<td>An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_revocation_offline_c</code></pre></td>
<td>Error</td>
<td><pre><code>3221226379 - 0xC000038B</code></pre></td>
<td>The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_pkinit_client_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221226380 - 0xC000038C</code></pre></td>
<td>The smart card certificate used for authentication was not trusted. Contact your system administrator.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_smartcard_cert_expired</code></pre></td>
<td>Error</td>
<td><pre><code>3221226381 - 0xC000038D</code></pre></td>
<td>The smart card certificate used for authentication has expired. Contact your system administrator.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>NT_status_driver_failed_prior_unload</code></pre></td>
<td>Error</td>
<td><pre><code>3221226382 - 0xC000038E</code></pre></td>
<td>The driver could not be loaded because a previous version of the driver is still in memory.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>NT_status_wow_assertion</code></pre></td>
<td>Error</td>
<td><pre><code>3221264536 - 0xC0009898</code></pre></td>
<td>WOW Assertion Error.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_string_binding</code></pre></td>
<td>Error</td>
<td><pre><code>3221356545 - 0xC0020001</code></pre></td>
<td>The string binding is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_wrong_kind_of_binding</code></pre></td>
<td>Error</td>
<td><pre><code>3221356546 - 0xC0020002</code></pre></td>
<td>The binding handle is not the correct type.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_binding</code></pre></td>
<td>Error</td>
<td><pre><code>3221356547 - 0xC0020003</code></pre></td>
<td>The binding handle is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_protseq_not_supported</code></pre></td>
<td>Error</td>
<td><pre><code>3221356548 - 0xC0020004</code></pre></td>
<td>The RPC protocol sequence is not supported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_rpc_protseq</code></pre></td>
<td>Error</td>
<td><pre><code>3221356549 - 0xC0020005</code></pre></td>
<td>The RPC protocol sequence is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_string_uuid</code></pre></td>
<td>Error</td>
<td><pre><code>3221356550 - 0xC0020006</code></pre></td>
<td>The string UUID is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_endpoint_format</code></pre></td>
<td>Error</td>
<td><pre><code>3221356551 - 0xC0020007</code></pre></td>
<td>The endpoint format is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_net_addr</code></pre></td>
<td>Error</td>
<td><pre><code>3221356552 - 0xC0020008</code></pre></td>
<td>The network address is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_endpoint_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356553 - 0xC0020009</code></pre></td>
<td>No endpoint was found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_timeout</code></pre></td>
<td>Error</td>
<td><pre><code>3221356554 - 0xC002000A</code></pre></td>
<td>The time-out value is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_object_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356555 - 0xC002000B</code></pre></td>
<td>The object UUID was not found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_already_registered</code></pre></td>
<td>Error</td>
<td><pre><code>3221356556 - 0xC002000C</code></pre></td>
<td>The object UUID has already been registered.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_type_already_registered</code></pre></td>
<td>Error</td>
<td><pre><code>3221356557 - 0xC002000D</code></pre></td>
<td>The type UUID has already been registered.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_already_listening</code></pre></td>
<td>Error</td>
<td><pre><code>3221356558 - 0xC002000E</code></pre></td>
<td>The RPC server is already listening.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_protseqs_registered</code></pre></td>
<td>Error</td>
<td><pre><code>3221356559 - 0xC002000F</code></pre></td>
<td>No protocol sequences have been registered.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_not_listening</code></pre></td>
<td>Error</td>
<td><pre><code>3221356560 - 0xC0020010</code></pre></td>
<td>The RPC server is not listening.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_mgr_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221356561 - 0xC0020011</code></pre></td>
<td>The manager type is unknown.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_if</code></pre></td>
<td>Error</td>
<td><pre><code>3221356562 - 0xC0020012</code></pre></td>
<td>The interface is unknown.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_bindings</code></pre></td>
<td>Error</td>
<td><pre><code>3221356563 - 0xC0020013</code></pre></td>
<td>There are no bindings.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_protseqs</code></pre></td>
<td>Error</td>
<td><pre><code>3221356564 - 0xC0020014</code></pre></td>
<td>There are no protocol sequences.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_cant_create_endpoint</code></pre></td>
<td>Error</td>
<td><pre><code>3221356565 - 0xC0020015</code></pre></td>
<td>The endpoint cannot be created.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_out_of_resources</code></pre></td>
<td>Error</td>
<td><pre><code>3221356566 - 0xC0020016</code></pre></td>
<td>Insufficient resources are available to complete this operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_server_unavailable</code></pre></td>
<td>Error</td>
<td><pre><code>3221356567 - 0xC0020017</code></pre></td>
<td>The RPC server is unavailable.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_server_too_busy</code></pre></td>
<td>Error</td>
<td><pre><code>3221356568 - 0xC0020018</code></pre></td>
<td>The RPC server is too busy to complete this operation.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_network_options</code></pre></td>
<td>Error</td>
<td><pre><code>3221356569 - 0xC0020019</code></pre></td>
<td>The network options are invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_call_active</code></pre></td>
<td>Error</td>
<td><pre><code>3221356570 - 0xC002001A</code></pre></td>
<td>No RPCs are active on this thread.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_call_failed</code></pre></td>
<td>Error</td>
<td><pre><code>3221356571 - 0xC002001B</code></pre></td>
<td>The RPC failed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_call_failed_dne</code></pre></td>
<td>Error</td>
<td><pre><code>3221356572 - 0xC002001C</code></pre></td>
<td>The RPC failed and did not execute.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_protocol_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221356573 - 0xC002001D</code></pre></td>
<td>An RPC protocol error occurred.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unsupported_trans_syn</code></pre></td>
<td>Error</td>
<td><pre><code>3221356575 - 0xC002001F</code></pre></td>
<td>The RPC server does not support the transfer syntax.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unsupported_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221356577 - 0xC0020021</code></pre></td>
<td>The type UUID is not supported.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_tag</code></pre></td>
<td>Error</td>
<td><pre><code>3221356578 - 0xC0020022</code></pre></td>
<td>The tag is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_bound</code></pre></td>
<td>Error</td>
<td><pre><code>3221356579 - 0xC0020023</code></pre></td>
<td>The array bounds are invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_entry_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221356580 - 0xC0020024</code></pre></td>
<td>The binding does not contain an entry name.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_name_syntax</code></pre></td>
<td>Error</td>
<td><pre><code>3221356581 - 0xC0020025</code></pre></td>
<td>The name syntax is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unsupported_name_syntax</code></pre></td>
<td>Error</td>
<td><pre><code>3221356582 - 0xC0020026</code></pre></td>
<td>The name syntax is not supported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_uuid_no_address</code></pre></td>
<td>Error</td>
<td><pre><code>3221356584 - 0xC0020028</code></pre></td>
<td>No network address is available to construct a UUID.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_duplicate_endpoint</code></pre></td>
<td>Error</td>
<td><pre><code>3221356585 - 0xC0020029</code></pre></td>
<td>The endpoint is a duplicate.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_authn_type</code></pre></td>
<td>Error</td>
<td><pre><code>3221356586 - 0xC002002A</code></pre></td>
<td>The authentication type is unknown.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_max_calls_too_small</code></pre></td>
<td>Error</td>
<td><pre><code>3221356587 - 0xC002002B</code></pre></td>
<td>The maximum number of calls is too small.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_string_too_long</code></pre></td>
<td>Error</td>
<td><pre><code>3221356588 - 0xC002002C</code></pre></td>
<td>The string is too long.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_protseq_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356589 - 0xC002002D</code></pre></td>
<td>The RPC protocol sequence was not found.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_procnum_out_of_range</code></pre></td>
<td>Error</td>
<td><pre><code>3221356590 - 0xC002002E</code></pre></td>
<td>The procedure number is out of range.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_binding_has_no_auth</code></pre></td>
<td>Error</td>
<td><pre><code>3221356591 - 0xC002002F</code></pre></td>
<td>The binding does not contain any authentication information.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_authn_service</code></pre></td>
<td>Error</td>
<td><pre><code>3221356592 - 0xC0020030</code></pre></td>
<td>The authentication service is unknown.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_authn_level</code></pre></td>
<td>Error</td>
<td><pre><code>3221356593 - 0xC0020031</code></pre></td>
<td>The authentication level is unknown.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_auth_identity</code></pre></td>
<td>Error</td>
<td><pre><code>3221356594 - 0xC0020032</code></pre></td>
<td>The security context is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unknown_authz_service</code></pre></td>
<td>Error</td>
<td><pre><code>3221356595 - 0xC0020033</code></pre></td>
<td>The authorization service is unknown.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EPT_NT_invalid_entry</code></pre></td>
<td>Error</td>
<td><pre><code>3221356596 - 0xC0020034</code></pre></td>
<td>The entry is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>EPT_NT_cant_perform_op</code></pre></td>
<td>Error</td>
<td><pre><code>3221356597 - 0xC0020035</code></pre></td>
<td>The operation cannot be performed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EPT_NT_not_registered</code></pre></td>
<td>Error</td>
<td><pre><code>3221356598 - 0xC0020036</code></pre></td>
<td>No more endpoints are available from the endpoint mapper.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_nothing_to_export</code></pre></td>
<td>Error</td>
<td><pre><code>3221356599 - 0xC0020037</code></pre></td>
<td>No interfaces have been exported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_incomplete_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221356600 - 0xC0020038</code></pre></td>
<td>The entry name is incomplete.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_vers_option</code></pre></td>
<td>Error</td>
<td><pre><code>3221356601 - 0xC0020039</code></pre></td>
<td>The version option is invalid.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_more_members</code></pre></td>
<td>Error</td>
<td><pre><code>3221356602 - 0xC002003A</code></pre></td>
<td>There are no more members.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_not_all_objs_unexported</code></pre></td>
<td>Error</td>
<td><pre><code>3221356603 - 0xC002003B</code></pre></td>
<td>There is nothing to unexport.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_interface_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356604 - 0xC002003C</code></pre></td>
<td>The interface was not found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_entry_already_exists</code></pre></td>
<td>Error</td>
<td><pre><code>3221356605 - 0xC002003D</code></pre></td>
<td>The entry already exists.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_entry_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356606 - 0xC002003E</code></pre></td>
<td>The entry was not found.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_name_service_unavailable</code></pre></td>
<td>Error</td>
<td><pre><code>3221356607 - 0xC002003F</code></pre></td>
<td>The name service is unavailable.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_naf_id</code></pre></td>
<td>Error</td>
<td><pre><code>3221356608 - 0xC0020040</code></pre></td>
<td>The network address family is invalid.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_cannot_support</code></pre></td>
<td>Error</td>
<td><pre><code>3221356609 - 0xC0020041</code></pre></td>
<td>The requested operation is not supported.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_context_available</code></pre></td>
<td>Error</td>
<td><pre><code>3221356610 - 0xC0020042</code></pre></td>
<td>No security context is available to allow impersonation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_internal_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221356611 - 0xC0020043</code></pre></td>
<td>An internal error occurred in the RPC.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_zero_divide</code></pre></td>
<td>Error</td>
<td><pre><code>3221356612 - 0xC0020044</code></pre></td>
<td>The RPC server attempted to divide an integer by zero.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_address_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221356613 - 0xC0020045</code></pre></td>
<td>An addressing error occurred in the RPC server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_fp_div_zero</code></pre></td>
<td>Error</td>
<td><pre><code>3221356614 - 0xC0020046</code></pre></td>
<td>A floating point operation at the RPC server caused a divide by zero.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_fp_underflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221356615 - 0xC0020047</code></pre></td>
<td>A floating point underflow occurred at the RPC server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_fp_overflow</code></pre></td>
<td>Error</td>
<td><pre><code>3221356616 - 0xC0020048</code></pre></td>
<td>A floating point overflow occurred at the RPC server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_call_in_progress</code></pre></td>
<td>Error</td>
<td><pre><code>3221356617 - 0xC0020049</code></pre></td>
<td>An RPC is already in progress for this thread.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_more_bindings</code></pre></td>
<td>Error</td>
<td><pre><code>3221356618 - 0xC002004A</code></pre></td>
<td>There are no more bindings.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_group_member_not_found</code></pre></td>
<td>Error</td>
<td><pre><code>3221356619 - 0xC002004B</code></pre></td>
<td>The group member was not found.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>EPT_NT_cant_create</code></pre></td>
<td>Error</td>
<td><pre><code>3221356620 - 0xC002004C</code></pre></td>
<td>The endpoint mapper database entry could not be created.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_object</code></pre></td>
<td>Error</td>
<td><pre><code>3221356621 - 0xC002004D</code></pre></td>
<td>The object UUID is the nil UUID.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_interfaces</code></pre></td>
<td>Error</td>
<td><pre><code>3221356623 - 0xC002004F</code></pre></td>
<td>No interfaces have been registered.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_call_cancelled</code></pre></td>
<td>Error</td>
<td><pre><code>3221356624 - 0xC0020050</code></pre></td>
<td>The RPC was canceled.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_binding_incomplete</code></pre></td>
<td>Error</td>
<td><pre><code>3221356625 - 0xC0020051</code></pre></td>
<td>The binding handle does not contain all the required information.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_comm_failure</code></pre></td>
<td>Error</td>
<td><pre><code>3221356626 - 0xC0020052</code></pre></td>
<td>A communications failure occurred during an RPC.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_unsupported_authn_level</code></pre></td>
<td>Error</td>
<td><pre><code>3221356627 - 0xC0020053</code></pre></td>
<td>The requested authentication level is not supported.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_princ_name</code></pre></td>
<td>Error</td>
<td><pre><code>3221356628 - 0xC0020054</code></pre></td>
<td>No principal name was registered.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_not_rpc_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221356629 - 0xC0020055</code></pre></td>
<td>The error specified is not a valid Windows RPC error code.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_sec_pkg_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221356631 - 0xC0020057</code></pre></td>
<td>A security package-specific error occurred.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_not_cancelled</code></pre></td>
<td>Error</td>
<td><pre><code>3221356632 - 0xC0020058</code></pre></td>
<td>The thread was not canceled.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_async_handle</code></pre></td>
<td>Error</td>
<td><pre><code>3221356642 - 0xC0020062</code></pre></td>
<td>Invalid asynchronous RPC handle.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_async_call</code></pre></td>
<td>Error</td>
<td><pre><code>3221356643 - 0xC0020063</code></pre></td>
<td>Invalid asynchronous RPC call handle for this operation.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_proxy_access_denied</code></pre></td>
<td>Error</td>
<td><pre><code>3221356644 - 0xC0020064</code></pre></td>
<td>Access to the HTTP proxy is denied.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_no_more_entries</code></pre></td>
<td>Error</td>
<td><pre><code>3221422081 - 0xC0030001</code></pre></td>
<td>The list of RPC servers available for auto-handle binding has been exhausted.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_char_trans_open_fail</code></pre></td>
<td>Error</td>
<td><pre><code>3221422082 - 0xC0030002</code></pre></td>
<td>The file designated by DCERPCCHARTRANS cannot be opened.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_char_trans_short_file</code></pre></td>
<td>Error</td>
<td><pre><code>3221422083 - 0xC0030003</code></pre></td>
<td>The file containing the character translation table has fewer than 512 bytes.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_in_null_context</code></pre></td>
<td>Error</td>
<td><pre><code>3221422084 - 0xC0030004</code></pre></td>
<td>A null context handle is passed as an [in] parameter.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_context_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221422085 - 0xC0030005</code></pre></td>
<td>The context handle does not match any known context handles.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_context_damaged</code></pre></td>
<td>Error</td>
<td><pre><code>3221422086 - 0xC0030006</code></pre></td>
<td>The context handle changed during a call.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_handles_mismatch</code></pre></td>
<td>Error</td>
<td><pre><code>3221422087 - 0xC0030007</code></pre></td>
<td>The binding handles passed to an RPC do not match.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_ss_cannot_get_call_handle</code></pre></td>
<td>Error</td>
<td><pre><code>3221422088 - 0xC0030008</code></pre></td>
<td>The stub is unable to get the call handle.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_null_ref_pointer</code></pre></td>
<td>Error</td>
<td><pre><code>3221422089 - 0xC0030009</code></pre></td>
<td>A null reference pointer was passed to the stub.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_enum_value_out_of_range</code></pre></td>
<td>Error</td>
<td><pre><code>3221422090 - 0xC003000A</code></pre></td>
<td>The enumeration value is out of range.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_byte_count_too_small</code></pre></td>
<td>Error</td>
<td><pre><code>3221422091 - 0xC003000B</code></pre></td>
<td>The byte count is too small.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_bad_stub_data</code></pre></td>
<td>Error</td>
<td><pre><code>3221422092 - 0xC003000C</code></pre></td>
<td>The stub received bad data.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_es_action</code></pre></td>
<td>Error</td>
<td><pre><code>3221422169 - 0xC0030059</code></pre></td>
<td>Invalid operation on the encoding/decoding handle.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_wrong_es_version</code></pre></td>
<td>Error</td>
<td><pre><code>3221422170 - 0xC003005A</code></pre></td>
<td>Incompatible version of the serializing package.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_wrong_stub_version</code></pre></td>
<td>Error</td>
<td><pre><code>3221422171 - 0xC003005B</code></pre></td>
<td>Incompatible version of the RPC stub.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_pipe_object</code></pre></td>
<td>Error</td>
<td><pre><code>3221422172 - 0xC003005C</code></pre></td>
<td>The RPC pipe object is invalid or corrupt.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_invalid_pipe_operation</code></pre></td>
<td>Error</td>
<td><pre><code>3221422173 - 0xC003005D</code></pre></td>
<td>An invalid operation was attempted on an RPC pipe object.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_wrong_pipe_version</code></pre></td>
<td>Error</td>
<td><pre><code>3221422174 - 0xC003005E</code></pre></td>
<td>Unsupported RPC pipe version.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_pipe_closed</code></pre></td>
<td>Error</td>
<td><pre><code>3221422175 - 0xC003005F</code></pre></td>
<td>The RPC pipe object has already been closed.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_pipe_discipline_error</code></pre></td>
<td>Error</td>
<td><pre><code>3221422176 - 0xC0030060</code></pre></td>
<td>The RPC call completed before all pipes were processed.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>RPC_NT_pipe_empty</code></pre></td>
<td>Error</td>
<td><pre><code>3221422177 - 0xC0030061</code></pre></td>
<td>No more data is available from the RPC pipe.</td>
</tr>
</tbody>
</table>

### Type [smbsubcommand](#type-smbsubcommand)

This field does not allow any custom items.

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 33%" />
<col style="width: 33%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_set_nmpipe_state</code></pre></td>
<td><pre><code>1:37:1</code></pre></td>
<td>The TRANS_SET_NMPIPE_STATE subcommand allows a client to set the read mode and the non-blocking mode of a specified named pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_raw_read_nmpipe</code></pre></td>
<td><pre><code>1:37:17</code></pre></td>
<td>The TRANS_RAW_READ_NMPIPE subcommand allows for a raw read of data from a name pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_query_nmpipe_state</code></pre></td>
<td><pre><code>1:37:33</code></pre></td>
<td>The TRANS_QUERY_NMPIPE_STATE subcommand allows a client to retrieve information about a specified named pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_query_nmpipe_info</code></pre></td>
<td><pre><code>1:37:34</code></pre></td>
<td>The TRANS_QUERY_NMPIPE_INFO subcommand allows for a client to retrieve information about a specified named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_peek_nmpipe</code></pre></td>
<td><pre><code>1:37:35</code></pre></td>
<td>The TRANS_PEEK_NMPIPE subcommand is used to copy data out of a named pipe without removing it and to retrieve information about data in a named pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_transact_nmpipe</code></pre></td>
<td><pre><code>1:37:38</code></pre></td>
<td>The TRANS_TRANSACT_NMPIPE subcommand is used to execute a transacted exchange against a named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_raw_write_nmpipe</code></pre></td>
<td><pre><code>1:37:49</code></pre></td>
<td>The TRANS_RAW_WRITE_NMPIPE subcommand allows for a raw write of data to a named pipe. Raw writes to named pipes put bytes directly into a pipe in byte mode, regardless of whether it is a message mode pipe or byte mode pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_read_nmpipe</code></pre></td>
<td><pre><code>1:37:54</code></pre></td>
<td>The TRANS_READ_NMPIPE subcommand allows a client to read data from a named pipe.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_write_nmpipe</code></pre></td>
<td><pre><code>1:37:55</code></pre></td>
<td>The TRANS_WRITE_NMPIPE subcommand allows a client to write data to a named pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_wait_nmpipe</code></pre></td>
<td><pre><code>1:37:83</code></pre></td>
<td>The TRANS_WAIT_NMPIPE subcommand allows a client to be notified when the specified named pipe is available to be connected to.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS_call_nmpipe</code></pre></td>
<td><pre><code>1:37:84</code></pre></td>
<td>The TRANS_CALL_NMPIPE subcommand allows a client to open a named pipe, issue a write to the named pipe, issue a read from the named pipe, and close the named pipe.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_open2</code></pre></td>
<td><pre><code>1:50:0</code></pre></td>
<td>Open or create a file and set extended attributes on the file.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_find_first2</code></pre></td>
<td><pre><code>1:50:1</code></pre></td>
<td>Begin a search for file(s) within a directory or for a directory.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_find_next2</code></pre></td>
<td><pre><code>1:50:2</code></pre></td>
<td>Continue a search for file(s) within a directory or for a directory. The search MUST have been initiated using TRANS2_FIND_FIRST2.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_query_fs_info</code></pre></td>
<td><pre><code>1:50:3</code></pre></td>
<td>Request information about the object store underlying a share on the server.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_set_fs_information</code></pre></td>
<td><pre><code>1:50:4</code></pre></td>
<td>This subcommand is reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_query_path_information</code></pre></td>
<td><pre><code>1:50:5</code></pre></td>
<td>Get information about a specific file or directory. There are several information levels that can be queried.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_set_path_information</code></pre></td>
<td><pre><code>1:50:6</code></pre></td>
<td>Set the standard and extended attribute information of a specific file or directory on the server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_query_file_information</code></pre></td>
<td><pre><code>1:50:7</code></pre></td>
<td>This transaction is an alternative to TRANS2_QUERY_PATH_INFORMATION.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_set_file_information</code></pre></td>
<td><pre><code>1:50:8</code></pre></td>
<td>This transaction is an alternative to TRANS2_SET_PATH_INFORMATION.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_fsctl</code></pre></td>
<td><pre><code>1:50:9</code></pre></td>
<td>This subcommand is reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_ioctl2</code></pre></td>
<td><pre><code>1:50:10</code></pre></td>
<td>This subcommand is reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_find_notify_first</code></pre></td>
<td><pre><code>1:50:11</code></pre></td>
<td>This command was rendered obsolete.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_find_notify_next</code></pre></td>
<td><pre><code>1:50:12</code></pre></td>
<td>This command was rendered obsolete.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_create_directory</code></pre></td>
<td><pre><code>1:50:13</code></pre></td>
<td>This transaction is used to create a new directory and can be used to set extended attribute information.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_session_setup</code></pre></td>
<td><pre><code>1:50:14</code></pre></td>
<td>This subcommand is reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_get_dfs_referral</code></pre></td>
<td><pre><code>1:50:16</code></pre></td>
<td>Request a referral for a disk object in DFS.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_TRANS2_report_dfs_inconsistency</code></pre></td>
<td><pre><code>1:50:17</code></pre></td>
<td>This subcommand is reserved but not implemented.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_create</code></pre></td>
<td><pre><code>1:160:1</code></pre></td>
<td>This transaction subcommand is used to create or open a file or directory when extended attributes (EAs) or a security descriptor (SD) need to be applied.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_ioctl</code></pre></td>
<td><pre><code>1:160:2</code></pre></td>
<td>This transaction subcommand allows IOCTL and FSCTL functions to be transferred transparently from client to server. This command is useful for sending platform-specific or implementation-specific information to the server.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_set_security_desc</code></pre></td>
<td><pre><code>1:160:3</code></pre></td>
<td>This transaction subcommand allows a client to set the security descriptors for a file.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_notify_change</code></pre></td>
<td><pre><code>1:160:4</code></pre></td>
<td>This command notifies the client when the directory, specified by FID, is modified. It also returns the names of all file system objects that changed, and the ways in which they were modified. The command is a "single shot" and therefore needs to be reissued to watch for more directory changes.</td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_rename</code></pre></td>
<td><pre><code>1:160:5</code></pre></td>
<td>This subcommand was reserved but not implemented.</td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>SMB_NT_TRANSACT_query_security_desc</code></pre></td>
<td><pre><code>1:160:6</code></pre></td>
<td>This transaction subcommand allows a client to retrieve the security descriptor for a file.</td>
</tr>
</tbody>
</table>

### Type [tls\_version](#type-tls_version)

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th>Name</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>SSL 3.0</code></pre></td>
<td><pre><code>48 - 0x30</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TLS 1.0</code></pre></td>
<td><pre><code>49 - 0x31</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TLS 1.1</code></pre></td>
<td><pre><code>50 - 0x32</code></pre></td>
</tr>
<tr class="even">
<td><pre style="white-space: pre-wrap"><code>TLS 1.2</code></pre></td>
<td><pre><code>51 - 0x33</code></pre></td>
</tr>
<tr class="odd">
<td><pre style="white-space: pre-wrap"><code>TLS 1.3</code></pre></td>
<td><pre><code>52 - 0x34</code></pre></td>
</tr>
</tbody>
</table>
