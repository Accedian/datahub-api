---
title: 'PVX API :: Documentation\> Definitions'
---

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

<table id="fields-list-table" class="List">
<thead>
<tr><th>Field Name</th><th>Type</th><th>Layers</th><th>Description</th></tr>
</thead>
<tbody>

  <tr>
    <th><a id="field-aborts"><pre>aborts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of aborted Citrix sessions</td>
  </tr>

  <tr>
    <th><a id="field-aborts.ratio"><pre>aborts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The ratio of aborts to the total number of launch attempts</td>
  </tr>

  <tr>
    <th><a id="field-ajax.requests"><pre>ajax.requests</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of javascript requests</td>
  </tr>

  <tr>
    <th><a id="field-alert.access_denied"><pre>alert.access_denied</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A valid certificate was received, but when access control was applied, the sender decided not to proceed with negotiation. Code 49.</td>
  </tr>

  <tr>
    <th><a id="field-alert.bad_certificate"><pre>alert.bad_certificate</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A certificate was corrupt, contained signatures that did not verify correctly, etc. Code 42.</td>
  </tr>

  <tr>
    <th><a id="field-alert.bad_record_mac"><pre>alert.bad_record_mac</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This alert is returned if a record is received with an incorrect MAC. Code 20.</td>
  </tr>

  <tr>
    <th><a id="field-alert.certificate_expired"><pre>alert.certificate_expired</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A certificate has expired or is not currently valid. Code 45.</td>
  </tr>

  <tr>
    <th><a id="field-alert.certificate_revoked"><pre>alert.certificate_revoked</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A certificate was revoked by its signer. Code 44.</td>
  </tr>

  <tr>
    <th><a id="field-alert.certificate_unknown"><pre>alert.certificate_unknown</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable. Code 46.</td>
  </tr>

  <tr>
    <th><a id="field-alert.close_notify"><pre>alert.close_notify</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This message notifies the recipient that the sender will not send any more messages on this connection. Code 0.</td>
  </tr>

  <tr>
    <th><a id="field-alert.decode_error"><pre>alert.decode_error</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A message could not be decoded because some field was out of the specified range or the length of the message was incorrect. Code 50.</td>
  </tr>

  <tr>
    <th><a id="field-alert.decompression_failure"><pre>alert.decompression_failure</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The decompression function received improper input (e.g., data that would expand to excessive length). Code 30.</td>
  </tr>

  <tr>
    <th><a id="field-alert.decrypt_error"><pre>alert.decrypt_error</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A handshake cryptographic operation failed, including being unable to correctly verify a signature or validate a Finished message. Code 51.</td>
  </tr>

  <tr>
    <th><a id="field-alert.decryption_failed"><pre>alert.decryption_failed</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This alert was used in some earlier versions of TLS, and may have permitted certain attacks against the CBC mode. Code 21.</td>
  </tr>

  <tr>
    <th><a id="field-alert.export_restriction"><pre>alert.export_restriction</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This alert was used in some earlier versions of TLS. Code 60.</td>
  </tr>

  <tr>
    <th><a id="field-alert.handshake_failure"><pre>alert.handshake_failure</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Reception of a handshake failure alert message indicates that the sender was unable to negotiate an acceptable set of security parameters given the options available. Code 40.</td>
  </tr>

  <tr>
    <th><a id="field-alert.illegal_parameter"><pre>alert.illegal_parameter</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A field in the handshake was out of range or inconsistent with other fields. Code 47.</td>
  </tr>

  <tr>
    <th><a id="field-alert.insufficient_security"><pre>alert.insufficient_security</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Returned instead of a handshake failure when a negotiation has failed specifically because the server requires ciphers more secure than those supported by the client. Code 71.</td>
  </tr>

  <tr>
    <th><a id="field-alert.internal_error"><pre>alert.internal_error</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">An internal error unrelated to the peer or the correctness of the protocol (such as a memory allocation failure) makes it impossible to continue. Code 80.</td>
  </tr>

  <tr>
    <th><a id="field-alert.no_certificate"><pre>alert.no_certificate</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This alert was used in SSLv3 but not any version of TLS. Code 41.</td>
  </tr>

  <tr>
    <th><a id="field-alert.no_renegotiation"><pre>alert.no_renegotiation</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Sent by the client in response to a hello request or by the server in response to a client hello after initial handshaking. Code 100.</td>
  </tr>

  <tr>
    <th><a id="field-alert.protocol_version"><pre>alert.protocol_version</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The protocol version the client has attempted to negotiate is recognized but not supported. Code 70.</td>
  </tr>

  <tr>
    <th><a id="field-alert.record_overflow"><pre>alert.record_overflow</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A TLSCiphertext record was received that had a length more than 2^14+2048 bytes, or a record decrypted to a TLSCompressed record with more than 2^14+1024 bytes. Code 22.</td>
  </tr>

  <tr>
    <th><a id="field-alert.unexpected_message"><pre>alert.unexpected_message</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">An inappropriate message was received. Code 10.</td>
  </tr>

  <tr>
    <th><a id="field-alert.unknown_ca"><pre>alert.unknown_ca</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A valid certificate chain or partial chain was received, but the certificate was not accepted because the CA certificate could not be located or couldn't be matched with a known, trusted CA. Code 48.</td>
  </tr>

  <tr>
    <th><a id="field-alert.unsupported_certificate"><pre>alert.unsupported_certificate</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">A certificate was of an unsupported type. Code 43.</td>
  </tr>

  <tr>
    <th><a id="field-alert.unsupported_extension"><pre>alert.unsupported_extension</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Sent by clients that receive an extended server hello containing an extension that they did not put in the corresponding client hello. Code 110.</td>
  </tr>

  <tr>
    <th><a id="field-alert.user_canceled"><pre>alert.user_canceled</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">This handshake is being canceled for some reason unrelated to a protocol failure. Code 90.</td>
  </tr>

  <tr>
    <th><a id="field-alert_types"><pre>alert_types</pre></a></th>
    <td><a href="#type-alerttypes"><pre>alerttypes</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Flags of alerts present in the TLS conversation</td>
  </tr>

  <tr>
    <th><a id="field-application.id"><pre>application.id</pre></a></th>
    <td><a href="#type-application_id"><pre>application_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The application ID</td>
  </tr>

  <tr>
    <th><a id="field-application.name"><pre>application.name</pre></a></th>
    <td><a href="#type-application"><pre>application</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The application</td>
  </tr>

  <tr>
    <th><a id="field-attempts"><pre>attempts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of launch attempts</td>
  </tr>

  <tr>
    <th><a id="field-begins"><pre>begins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of VoIP flows that started</td>
  </tr>

  <tr>
    <th><a id="field-call"><pre>call</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The VoIP call id</td>
  </tr>

  <tr>
    <th><a id="field-call.direction"><pre>call.direction</pre></a></th>
    <td><a href="#type-calldirection"><pre>calldirection</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The direction (inbound, outbound, unknown) of the VoIP calls</td>
  </tr>

  <tr>
    <th><a id="field-call.duration"><pre>call.duration</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total duration of the VoIP calls</td>
  </tr>

  <tr>
    <th><a id="field-call.global.jitter"><pre>call.global.jitter</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average measured jitter for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.global.rtt"><pre>call.global.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.jitter.count"><pre>call.jitter.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of measured jitters for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.jitter.deviation"><pre>call.jitter.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the measured jitter for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.jitter.total"><pre>call.jitter.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The sum of both caller and callee average round-trip times</td>
  </tr>

  <tr>
    <th><a id="field-call.rtt.count"><pre>call.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of round-trip times for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.rtt.deviation"><pre>call.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for call PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-call.rtt.total"><pre>call.rtt.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The sum of both caller and callee average round-trip times</td>
  </tr>

  <tr>
    <th><a id="field-call.state"><pre>call.state</pre></a></th>
    <td><a href="#type-callstate"><pre>callstate</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The latest call state in this conversation</td>
  </tr>

  <tr>
    <th><a id="field-callee"><pre>callee</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The VoIP callee id</td>
  </tr>

  <tr>
    <th><a id="field-callee.codec"><pre>callee.codec</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The voice codec of the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.ip"><pre>callee.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The IP address of the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.jitter"><pre>callee.jitter</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average measured jitter for a PDU (protocol data unit) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.jitter.count"><pre>callee.jitter.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of measured jitters for PDUs (protocol data units) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.jitter.deviation"><pre>callee.jitter.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the measured jitters for PDUs (protocol data units) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.label"><pre>callee.label</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The display name of the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.lost.pdus"><pre>callee.lost.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of lost callee PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-callee.lost.pdus.ratio"><pre>callee.lost.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of lost to the total number of PDUs (protocol data units) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.mac"><pre>callee.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The MAC address of the Callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.rtt"><pre>callee.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-callee.rtt.count"><pre>callee.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-callee.rtt.deviation"><pre>callee.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-callee.zone.id"><pre>callee.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The zone ID of the callee</td>
  </tr>

  <tr>
    <th><a id="field-callee.zone.name"><pre>callee.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The zone of the callee</td>
  </tr>

  <tr>
    <th><a id="field-caller"><pre>caller</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The VoIP caller id</td>
  </tr>

  <tr>
    <th><a id="field-caller.codec"><pre>caller.codec</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The voice codec of the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.ip"><pre>caller.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The IP address of the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.jitter"><pre>caller.jitter</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average measured jitter for a PDU (protocol data unit) emitted by the the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.jitter.count"><pre>caller.jitter.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of measured jitters for PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.jitter.deviation"><pre>caller.jitter.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the measured jitters for PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.label"><pre>caller.label</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The display name of the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.lost.pdus"><pre>caller.lost.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of lost caller PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-caller.lost.pdus.ratio"><pre>caller.lost.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of lost to the total number of PDUs (protocol data units) emitted by the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.mac"><pre>caller.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The MAC address of the Caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.rtt"><pre>caller.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-caller.rtt.count"><pre>caller.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-caller.rtt.deviation"><pre>caller.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the callee</td>
  </tr>

  <tr>
    <th><a id="field-caller.zone.id"><pre>caller.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The zone ID of the caller</td>
  </tr>

  <tr>
    <th><a id="field-caller.zone.name"><pre>caller.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The zone of the caller</td>
  </tr>

  <tr>
    <th><a id="field-capture.hostname"><pre>capture.hostname</pre></a></th>
    <td><a href="#type-poller"><pre>poller</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The probe device hostname that captured this traffic</td>
  </tr>

  <tr>
    <th><a id="field-capture.id"><pre>capture.id</pre></a></th>
    <td><a href="#type-poller_id"><pre>poller_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The probe device ID that captured this traffic</td>
  </tr>

  <tr>
    <th><a id="field-cgp.client.pdus"><pre>cgp.client.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of CGP PDUs (protocol data units) at applicative level emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-cgp.dest.pdus"><pre>cgp.dest.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of CGP PDUs (protocol data units) at applicative level emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-cgp.pdus"><pre>cgp.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of CGP PDUs (protocol data units) at applicative level in both directions</td>
  </tr>

  <tr>
    <th><a id="field-cgp.server.pdus"><pre>cgp.server.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of CGP PDUs (protocol data units) at applicative level emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-cgp.source.pdus"><pre>cgp.source.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of CGP PDUs (protocol data units) at applicative level emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-channel"><pre>channel</pre></a></th>
    <td><a href="#type-channel"><pre>channel</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The Citrix channel</td>
  </tr>

  <tr>
    <th><a id="field-chunked.transfers"><pre>chunked.transfers</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of times the HTTP 'chunked' transfer encoding has been used</td>
  </tr>

  <tr>
    <th><a id="field-cipher"><pre>cipher</pre></a></th>
    <td><a href="#type-ciphersuite"><pre>ciphersuite</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The set of cryptographic algorithms used to secure this conversation</td>
  </tr>

  <tr>
    <th><a id="field-cipher.is_weak"><pre>cipher.is_weak</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Is the TLS cipher weak?</td>
  </tr>

  <tr>
    <th><a id="field-citrix.application"><pre>citrix.application</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>citrix
citrix_channels</pre></td>
    <td class="description">The published Citrix application being executed</td>
  </tr>

  <tr>
    <th><a id="field-client.common_name"><pre>client.common_name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The Common Name of the client certificate</td>
  </tr>

  <tr>
    <th><a id="field-client.compressed.pdus"><pre>client.compressed.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The number of compressed client PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-client.compressed.pdus.ratio"><pre>client.compressed.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The ratio of compressions to the total number of PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.data"><pre>client.data</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of client data PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-client.datasource.kind"><pre>client.datasource.kind</pre></a></th>
    <td><a href="#type-pktsourcekind"><pre>pktsourcekind</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.datasource.name"><pre>client.datasource.name</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source name on which this traffic has been captured (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.datasource.pair"><pre>client.datasource.pair</pre></a></th>
    <td><a href="#type-pktsourcepair"><pre>pktsourcepair</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type and name on which this traffic has been captured (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.diffserv"><pre>client.diffserv</pre></a></th>
    <td><a href="#type-diffserv"><pre>diffserv</pre></a></td>
    <td><pre>icmp
other_ip
tcp
udp</pre></td>
    <td class="description">The client differentiated service</td>
  </tr>

  <tr>
    <th><a id="field-client.dtt"><pre>client.dtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The average data-transfer time for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.dtt.count"><pre>client.dtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The number of data-transfer times for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.dtt.deviation"><pre>client.dtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the data-transfer time for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.dupacks"><pre>client.dupacks</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of duplicated ACK packets from the client</td>
  </tr>

  <tr>
    <th><a id="field-client.dupacks.ratio"><pre>client.dupacks.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of duplicated ACKs to the total number of packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.emtu"><pre>client.emtu</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp
non_ip
other_ip
tcp
udp</pre></td>
    <td class="description">The maximum payload in a single ethernet packet emmited by the client in these conversations (this value is assumed to be the MTU of the client's network interface, although the actual MTU value might be greater)</td>
  </tr>

  <tr>
    <th><a id="field-client.error.ip"><pre>client.error.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The IP address of the client, as it appears in the headers of the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-client.error.port"><pre>client.error.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The port of the client, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-client.error.zone.id"><pre>client.error.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone ID of the client, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-client.error.zone.name"><pre>client.error.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone of the client, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-client.expiration"><pre>client.expiration</pre></a></th>
    <td><a href="#type-time"><pre>time</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The expiration date of the client certificate</td>
  </tr>

  <tr>
    <th><a id="field-client.file"><pre>client.file</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the Pcap File used as traffic source (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.fins"><pre>client.fins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of FIN packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.fins.ratio"><pre>client.fins.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of client FIN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-client.interface"><pre>client.interface</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.ip"><pre>client.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The IP address of the client</td>
  </tr>

  <tr>
    <th><a id="field-client.ja3"><pre>client.ja3</pre></a></th>
    <td><a href="#type-tls_fingerprint"><pre>tls_fingerprint</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The JA3 client fingerprint</td>
  </tr>

  <tr>
    <th><a id="field-client.keepalives"><pre>client.keepalives</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of keep alives from the client</td>
  </tr>

  <tr>
    <th><a id="field-client.key.bits"><pre>client.key.bits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of bits in the client key</td>
  </tr>

  <tr>
    <th><a id="field-client.key.type"><pre>client.key.type</pre></a></th>
    <td><a href="#type-keytype"><pre>keytype</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The type of the client key</td>
  </tr>

  <tr>
    <th><a id="field-client.mac"><pre>client.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The MAC address of the client</td>
  </tr>

  <tr>
    <th><a id="field-client.meta"><pre>client.meta</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of client metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
  </tr>

  <tr>
    <th><a id="field-client.os"><pre>client.os</pre></a></th>
    <td><a href="#type-os"><pre>os</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The client operating system</td>
  </tr>

  <tr>
    <th><a id="field-client.payload"><pre>client.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.payload.pdus"><pre>client.payload.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) with payload emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.payload.ratio"><pre>client.payload.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The ratio of payload bytes to the entire traffic emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.pdus"><pre>client.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.port"><pre>client.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</pre></td>
    <td class="description">The TCP/UDP port of the client</td>
  </tr>

  <tr>
    <th><a id="field-client.rd"><pre>client.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average retransmission delay for PDUs emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.rd.count"><pre>client.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of retransmission delays for PDUs emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.rd.deviation"><pre>client.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the retransmission delay for PDUs emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.remote"><pre>client.remote</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured via rpcapd (client-side)</td>
  </tr>

  <tr>
    <th><a id="field-client.retrans.payload"><pre>client.retrans.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.retrans.pdus.ratio"><pre>client.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.retrans.traffic"><pre>client.retrans.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes in retransmitted PDUs emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.retrans.traffic.ratio"><pre>client.retrans.traffic.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmitted traffic to the entire traffic emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.rsts"><pre>client.rsts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of RST packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.rsts.ratio"><pre>client.rsts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of client RST packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-client.rtt"><pre>client.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.rtt.count"><pre>client.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.rtt.deviation"><pre>client.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.payload"><pre>client.signalization.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.pdus"><pre>client.signalization.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rd"><pre>client.signalization.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average retransmission delay for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rd.count"><pre>client.signalization.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of retransmission delays for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rd.deviation"><pre>client.signalization.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.retrans.pdus.ratio"><pre>client.signalization.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rtt"><pre>client.signalization.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rtt.count"><pre>client.signalization.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.rtt.deviation"><pre>client.signalization.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-client.signalization.traffic"><pre>client.signalization.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes in signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.signature"><pre>client.signature</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The client signature</td>
  </tr>

  <tr>
    <th><a id="field-client.traffic"><pre>client.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.vlan"><pre>client.vlan</pre></a></th>
    <td><a href="#type-vlan"><pre>vlan</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The VLAN id on the client side of the transaction</td>
  </tr>

  <tr>
    <th><a id="field-client.zero_windows"><pre>client.zero_windows</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of zero-window size packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.zero_windows.ratio"><pre>client.zero_windows.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of zero-window size to the total number of packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-client.zone.id"><pre>client.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone id of the client</td>
  </tr>

  <tr>
    <th><a id="field-client.zone.name"><pre>client.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone of the client</td>
  </tr>

  <tr>
    <th><a id="field-closes"><pre>closes</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of TCP sessions that ended properly (by acked FIN or RST)</td>
  </tr>

  <tr>
    <th><a id="field-command"><pre>command</pre></a></th>
    <td><a href="#type-databasecommand"><pre>databasecommand</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The database command type</td>
  </tr>

  <tr>
    <th><a id="field-compressed.pdus"><pre>compressed.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The total number of compressed PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-compressed.pdus.ratio"><pre>compressed.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The ratio of compressions to the total number of PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-compressed.responses"><pre>compressed.responses</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of compressed HTTP responses</td>
  </tr>

  <tr>
    <th><a id="field-ct"><pre>ct</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp
tls</pre></td>
    <td class="description">The average connection time</td>
  </tr>

  <tr>
    <th><a id="field-ct.count"><pre>ct.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp
tls</pre></td>
    <td class="description">The number of successful handshakes</td>
  </tr>

  <tr>
    <th><a id="field-ct.deviation"><pre>ct.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp
tls</pre></td>
    <td class="description">The deviation of the connection time</td>
  </tr>

  <tr>
    <th><a id="field-data.payload"><pre>data.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of data in both directions</td>
  </tr>

  <tr>
    <th><a id="field-database"><pre>database</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The name of the database</td>
  </tr>

  <tr>
    <th><a id="field-dcerpc"><pre>dcerpc</pre></a></th>
    <td><a href="#type-dcerpc"><pre>dcerpc</pre></a></td>
    <td><pre>tcp
udp</pre></td>
    <td class="description">The identifier of the DCE/RPC service</td>
  </tr>

  <tr>
    <th><a id="field-decrypted"><pre>decrypted</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of decrypted conversations</td>
  </tr>

  <tr>
    <th><a id="field-dest.common_name"><pre>dest.common_name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The Common Name of the destination certificate</td>
  </tr>

  <tr>
    <th><a id="field-dest.compressed.pdus"><pre>dest.compressed.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The number of compressed destination PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-dest.compressed.pdus.ratio"><pre>dest.compressed.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The ratio of compressions to the total number of PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.data"><pre>dest.data</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of destination data PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-dest.datasource.kind"><pre>dest.datasource.kind</pre></a></th>
    <td><a href="#type-pktsourcekind"><pre>pktsourcekind</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.datasource.name"><pre>dest.datasource.name</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source name on which this traffic has been captured (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.datasource.pair"><pre>dest.datasource.pair</pre></a></th>
    <td><a href="#type-pktsourcepair"><pre>pktsourcepair</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type and name on which this traffic has been captured (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.diffserv"><pre>dest.diffserv</pre></a></th>
    <td><a href="#type-diffserv"><pre>diffserv</pre></a></td>
    <td><pre>icmp
other_ip
tcp
udp</pre></td>
    <td class="description">The destination differentiated service</td>
  </tr>

  <tr>
    <th><a id="field-dest.dtt"><pre>dest.dtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The average data-transfer time for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.dtt.count"><pre>dest.dtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The number of data-transfer times for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.dtt.deviation"><pre>dest.dtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the data-transfer time for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.dupacks"><pre>dest.dupacks</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of duplicated ACK packets from the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.dupacks.ratio"><pre>dest.dupacks.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of duplicated ACKs to the total number of packets emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.emtu"><pre>dest.emtu</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp
non_ip
other_ip
tcp
udp</pre></td>
    <td class="description">The maximum payload in a single ethernet packet emmited by the destination in these conversations (this value is assumed to be the MTU of the destination's network interface, although the actual MTU value might be greater)</td>
  </tr>

  <tr>
    <th><a id="field-dest.error.ip"><pre>dest.error.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The IP address of the destination, as it appears in the headers of the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-dest.error.port"><pre>dest.error.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The port of the destination, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-dest.error.zone.id"><pre>dest.error.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone ID of the destination, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-dest.error.zone.name"><pre>dest.error.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone of the destination, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-dest.expiration"><pre>dest.expiration</pre></a></th>
    <td><a href="#type-time"><pre>time</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The expiration date of the destination certificate</td>
  </tr>

  <tr>
    <th><a id="field-dest.file"><pre>dest.file</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the Pcap File used as traffic source (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.fins"><pre>dest.fins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of FIN packets emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.fins.ratio"><pre>dest.fins.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of destination FIN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-dest.interface"><pre>dest.interface</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.ip"><pre>dest.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The IP address of the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.ja3"><pre>dest.ja3</pre></a></th>
    <td><a href="#type-tls_fingerprint"><pre>tls_fingerprint</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The JA3 destination fingerprint</td>
  </tr>

  <tr>
    <th><a id="field-dest.keepalives"><pre>dest.keepalives</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of keep alives from the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.key.bits"><pre>dest.key.bits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of bits in the destination key</td>
  </tr>

  <tr>
    <th><a id="field-dest.key.type"><pre>dest.key.type</pre></a></th>
    <td><a href="#type-keytype"><pre>keytype</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The type of the destination key</td>
  </tr>

  <tr>
    <th><a id="field-dest.mac"><pre>dest.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The MAC address of the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.meta"><pre>dest.meta</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of destination metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
  </tr>

  <tr>
    <th><a id="field-dest.os"><pre>dest.os</pre></a></th>
    <td><a href="#type-os"><pre>os</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The destination operating system</td>
  </tr>

  <tr>
    <th><a id="field-dest.payload"><pre>dest.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.payload.pdus"><pre>dest.payload.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) with payload emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.payload.ratio"><pre>dest.payload.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The ratio of payload bytes to the entire traffic emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.pdus"><pre>dest.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.port"><pre>dest.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</pre></td>
    <td class="description">The TCP/UDP port of the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.rd"><pre>dest.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average retransmission delay for PDUs emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.rd.count"><pre>dest.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of retransmission delays for PDUs emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.rd.deviation"><pre>dest.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the retransmission delay for PDUs emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.remote"><pre>dest.remote</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured via rpcapd (destination-side)</td>
  </tr>

  <tr>
    <th><a id="field-dest.retrans.payload"><pre>dest.retrans.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.retrans.pdus.ratio"><pre>dest.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.retrans.traffic"><pre>dest.retrans.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes in retransmitted PDUs emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.retrans.traffic.ratio"><pre>dest.retrans.traffic.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmitted traffic to the entire traffic emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.rsts"><pre>dest.rsts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of RST packets emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.rsts.ratio"><pre>dest.rsts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of destination RST packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-dest.rtt"><pre>dest.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.rtt.count"><pre>dest.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.rtt.deviation"><pre>dest.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.payload"><pre>dest.signalization.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.pdus"><pre>dest.signalization.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rd"><pre>dest.signalization.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average retransmission delay for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rd.count"><pre>dest.signalization.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of retransmission delays for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rd.deviation"><pre>dest.signalization.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.retrans.pdus.ratio"><pre>dest.signalization.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rtt"><pre>dest.signalization.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rtt.count"><pre>dest.signalization.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.rtt.deviation"><pre>dest.signalization.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-dest.signalization.traffic"><pre>dest.signalization.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes in signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.signature"><pre>dest.signature</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The destination signature</td>
  </tr>

  <tr>
    <th><a id="field-dest.traffic"><pre>dest.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.vlan"><pre>dest.vlan</pre></a></th>
    <td><a href="#type-vlan"><pre>vlan</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The VLAN id on the destination side of the transaction</td>
  </tr>

  <tr>
    <th><a id="field-dest.zero_windows"><pre>dest.zero_windows</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of zero-window size packets emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.zero_windows.ratio"><pre>dest.zero_windows.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of zero-window size to the total number of packets emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.zone.id"><pre>dest.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone id of the destination</td>
  </tr>

  <tr>
    <th><a id="field-dest.zone.name"><pre>dest.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone of the destination</td>
  </tr>

  <tr>
    <th><a id="field-dns.rt"><pre>dns.rt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The average DNS response time</td>
  </tr>

  <tr>
    <th><a id="field-dns.rt.deviation"><pre>dns.rt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The deviation of the DNS response time</td>
  </tr>

  <tr>
    <th><a id="field-domain"><pre>domain</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>citrix
citrix_channels
smb</pre></td>
    <td class="description">The Windows Domain of the user</td>
  </tr>

  <tr>
    <th><a id="field-domain.primary"><pre>domain.primary</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http
tls</pre></td>
    <td class="description">The primary domain name (www.example.org -&gt; example.org)</td>
  </tr>

  <tr>
    <th><a id="field-domain.short"><pre>domain.short</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http
tls</pre></td>
    <td class="description">The primary domain name, without TLD</td>
  </tr>

  <tr>
    <th><a id="field-domain.toplevel"><pre>domain.toplevel</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http
tls</pre></td>
    <td class="description">The top-level domain name (TLD)</td>
  </tr>

  <tr>
    <th><a id="field-dtt.count"><pre>dtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The total number of data-transfer times in both directions</td>
  </tr>

  <tr>
    <th><a id="field-dtt.deviation"><pre>dtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the data-transfer time in both directions</td>
  </tr>

  <tr>
    <th><a id="field-dtt.total"><pre>dtt.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The sum of both client and server average data-transfer times</td>
  </tr>

  <tr>
    <th><a id="field-dupacks"><pre>dupacks</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of duplicated ACK packets in both directions</td>
  </tr>

  <tr>
    <th><a id="field-dupacks.ratio"><pre>dupacks.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of duplicated ACKs to the total number of packets in both directions</td>
  </tr>

  <tr>
    <th><a id="field-encryption"><pre>encryption</pre></a></th>
    <td><a href="#type-encryption"><pre>encryption</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The Citrix encryption type</td>
  </tr>

  <tr>
    <th><a id="field-ends"><pre>ends</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of VoIP flows that ended</td>
  </tr>

  <tr>
    <th><a id="field-error.alerts"><pre>error.alerts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of error alerts (everything but close notifications)</td>
  </tr>

  <tr>
    <th><a id="field-error.code"><pre>error.code</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The error code, specific to some databases (MySQL, TDS and TNS)</td>
  </tr>

  <tr>
    <th><a id="field-error.hits"><pre>error.hits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of hits with a response code of at least 400</td>
  </tr>

  <tr>
    <th><a id="field-error.message"><pre>error.message</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The database error message</td>
  </tr>

  <tr>
    <th><a id="field-error.protocol"><pre>error.protocol</pre></a></th>
    <td><a href="#type-ipprotocol"><pre>ipprotocol</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The IP protocol of the PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-error.status"><pre>error.status</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The database error status</td>
  </tr>

  <tr>
    <th><a id="field-errors"><pre>errors</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
dns
smb
voip</pre></td>
    <td class="description">The number of errors</td>
  </tr>

  <tr>
    <th><a id="field-errors.ratio"><pre>errors.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
dns
smb
voip</pre></td>
    <td class="description">The ratio of errors to the total number of queries</td>
  </tr>

  <tr>
    <th><a id="field-file"><pre>file</pre></a></th>
    <td><a href="#type-path"><pre>path</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The file path</td>
  </tr>

  <tr>
    <th><a id="field-file.count"><pre>file.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of processed files</td>
  </tr>

  <tr>
    <th><a id="field-file.id"><pre>file.id</pre></a></th>
    <td><a href="#type-descriptor"><pre>descriptor</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The CIFS file descriptor id</td>
  </tr>

  <tr>
    <th><a id="field-fins"><pre>fins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of FIN packets in both directions</td>
  </tr>

  <tr>
    <th><a id="field-fins.ratio"><pre>fins.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of FIN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-global.dtt"><pre>global.dtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The average data-transfer time in both directions</td>
  </tr>

  <tr>
    <th><a id="field-global.emtu"><pre>global.emtu</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp
non_ip
other_ip
tcp
udp</pre></td>
    <td class="description">The maximum payload in a single ethernet packet in both directions</td>
  </tr>

  <tr>
    <th><a id="field-global.rd"><pre>global.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average retransmission delay in both directions</td>
  </tr>

  <tr>
    <th><a id="field-global.rtt"><pre>global.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average round-trip time in both directions</td>
  </tr>

  <tr>
    <th><a id="field-global.signalization.rd"><pre>global.signalization.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average retransmission delay for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-global.signalization.rtt"><pre>global.signalization.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-has_contributed"><pre>has_contributed</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Did this hit contribute to the metrics of the page it is attached to?</td>
  </tr>

  <tr>
    <th><a id="field-has_timeouted"><pre>has_timeouted</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>databases
http
smb</pre></td>
    <td class="description">Did this transaction timeout?</td>
  </tr>

  <tr>
    <th><a id="field-has_voice"><pre>has_voice</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">Was there any voice in the conversation?</td>
  </tr>

  <tr>
    <th><a id="field-headers"><pre>headers</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of headers in both query and response PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-hit"><pre>hit</pre></a></th>
    <td><a href="#type-uuid"><pre>uuid</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">This hit's unique identifier</td>
  </tr>

  <tr>
    <th><a id="field-hit.parent"><pre>hit.parent</pre></a></th>
    <td><a href="#type-uuid"><pre>uuid</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">This hit's parent's unique identifier</td>
  </tr>

  <tr>
    <th><a id="field-hit.referrer"><pre>hit.referrer</pre></a></th>
    <td><a href="#type-uuid"><pre>uuid</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">This hit's referrer's unique identifier</td>
  </tr>

  <tr>
    <th><a id="field-hit.rt"><pre>hit.rt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The average hit response time</td>
  </tr>

  <tr>
    <th><a id="field-hit.rt.count"><pre>hit.rt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of HTTP hit response times</td>
  </tr>

  <tr>
    <th><a id="field-hit.rt.deviation"><pre>hit.rt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The deviation of the hit response time</td>
  </tr>

  <tr>
    <th><a id="field-hits"><pre>hits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of HTTP hits</td>
  </tr>

  <tr>
    <th><a id="field-host"><pre>host</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The URL Host</td>
  </tr>

  <tr>
    <th><a id="field-icmp.code"><pre>icmp.code</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The ICMP message code</td>
  </tr>

  <tr>
    <th><a id="field-icmp.message"><pre>icmp.message</pre></a></th>
    <td><a href="#type-icmpmessage"><pre>icmpmessage</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The ICMP message</td>
  </tr>

  <tr>
    <th><a id="field-icmp.type"><pre>icmp.type</pre></a></th>
    <td><a href="#type-icmptype"><pre>icmptype</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The ICMP message type</td>
  </tr>

  <tr>
    <th><a id="field-ip.family"><pre>ip.family</pre></a></th>
    <td><a href="#type-ipfamily"><pre>ipfamily</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The IP address family</td>
  </tr>

  <tr>
    <th><a id="field-ip.protocol"><pre>ip.protocol</pre></a></th>
    <td><a href="#type-ipprotocol"><pre>ipprotocol</pre></a></td>
    <td><pre>other_ip
voip</pre></td>
    <td class="description">The IP protocol</td>
  </tr>

  <tr>
    <th><a id="field-is_ajax"><pre>is_ajax</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Is this hit requested through javascript?</td>
  </tr>

  <tr>
    <th><a id="field-is_chunked"><pre>is_chunked</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Does this hit use HTTP 'chunked' transfer encoding?</td>
  </tr>

  <tr>
    <th><a id="field-is_compressed"><pre>is_compressed</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Is this hit compressed?</td>
  </tr>

  <tr>
    <th><a id="field-is_deepinspect"><pre>is_deepinspect</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Was page reconstruction activated for this hit?</td>
  </tr>

  <tr>
    <th><a id="field-is_main"><pre>is_main</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Is this hit the main resource of the page?</td>
  </tr>

  <tr>
    <th><a id="field-is_root"><pre>is_root</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">Is this a root hit?</td>
  </tr>

  <tr>
    <th><a id="field-keepalives"><pre>keepalives</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The total number of keep alives in both directions</td>
  </tr>

  <tr>
    <th><a id="field-launch.time"><pre>launch.time</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The average launch time for Citrix applications</td>
  </tr>

  <tr>
    <th><a id="field-launch.time.deviation"><pre>launch.time.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The deviation of the launch time</td>
  </tr>

  <tr>
    <th><a id="field-layer"><pre>layer</pre></a></th>
    <td><a href="#type-layer"><pre>layer</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The layer</td>
  </tr>

  <tr>
    <th><a id="field-login.time"><pre>login.time</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The average login time</td>
  </tr>

  <tr>
    <th><a id="field-login.time.count"><pre>login.time.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of logins</td>
  </tr>

  <tr>
    <th><a id="field-login.time.deviation"><pre>login.time.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The deviation of the login time</td>
  </tr>

  <tr>
    <th><a id="field-lost.pdus"><pre>lost.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of lost PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-lost.pdus.ratio"><pre>lost.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of lost to the total number of PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-metadata.payload"><pre>metadata.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of metadata in both directions</td>
  </tr>

  <tr>
    <th><a id="field-metadata.read"><pre>metadata.read</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of metadata read by SMB commands (directory listing commands, for example)</td>
  </tr>

  <tr>
    <th><a id="field-metadata.written"><pre>metadata.written</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of metadata written by SMB commands</td>
  </tr>

  <tr>
    <th><a id="field-method"><pre>method</pre></a></th>
    <td><a href="#type-httpquerymethod"><pre>httpquerymethod</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The HTTP request method</td>
  </tr>

  <tr>
    <th><a id="field-module"><pre>module</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The name of the Citrix module used by the client</td>
  </tr>

  <tr>
    <th><a id="field-mos"><pre>mos</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The VOIP mean opinion score</td>
  </tr>

  <tr>
    <th><a id="field-netflow.ip"><pre>netflow.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>icmp
tcp
udp</pre></td>
    <td class="description">The IP address of the emitter</td>
  </tr>

  <tr>
    <th><a id="field-nonip.protocol"><pre>nonip.protocol</pre></a></th>
    <td><a href="#type-ethernetprotocol"><pre>ethernetprotocol</pre></a></td>
    <td><pre>non_ip</pre></td>
    <td class="description">The OSI layer 2 protocol</td>
  </tr>

  <tr>
    <th><a id="field-origin.ip"><pre>origin.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The original client's IP, as it appears in the HTTP header</td>
  </tr>

  <tr>
    <th><a id="field-page.errors"><pre>page.errors</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of errors in all the hits that contributed to these pages, errors consisting of HTTP response codes of at least 400</td>
  </tr>

  <tr>
    <th><a id="field-page.hits"><pre>page.hits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of hits that contributed to these pages</td>
  </tr>

  <tr>
    <th><a id="field-page.load.time"><pre>page.load.time</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The average page load time</td>
  </tr>

  <tr>
    <th><a id="field-page.load.time.deviation"><pre>page.load.time.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The deviation of the page load time</td>
  </tr>

  <tr>
    <th><a id="field-page.request.traffic"><pre>page.request.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of request traffic (headers + payload) in all the hits that contributed to these pages</td>
  </tr>

  <tr>
    <th><a id="field-page.response.traffic"><pre>page.response.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of response traffic (headers + payload) in all the hits that contributed to these pages</td>
  </tr>

  <tr>
    <th><a id="field-page.timeouts"><pre>page.timeouts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of timeouts in all the hits that contributed to these pages</td>
  </tr>

  <tr>
    <th><a id="field-page.traffic"><pre>page.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of query and response traffic (headers + payload) in all the hits that contributed to these pages</td>
  </tr>

  <tr>
    <th><a id="field-pages"><pre>pages</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of HTTP pages</td>
  </tr>

  <tr>
    <th><a id="field-payload"><pre>payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
udp
voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-payload.pdus"><pre>payload.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) with payload in both directions</td>
  </tr>

  <tr>
    <th><a id="field-payload.ratio"><pre>payload.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The ratio of payload bytes to the entire traffic in both directions</td>
  </tr>

  <tr>
    <th><a id="field-pcap"><pre>pcap</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>dns
tcp
voip</pre></td>
    <td class="description">The link to the associated captured PCAP file (generated according to the configuration of zones and applications)</td>
  </tr>

  <tr>
    <th><a id="field-pdus"><pre>pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
dns
icmp
non_ip
other_ip
smb
tcp
udp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level in both directions</td>
  </tr>

  <tr>
    <th><a id="field-points"><pre>points</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The number of points</td>
  </tr>

  <tr>
    <th><a id="field-protostack"><pre>protostack</pre></a></th>
    <td><a href="#type-protostack"><pre>protostack</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
icmp
non_ip
other_ip
smb
tcp
tls
udp
voip</pre></td>
    <td class="description">The protocol stack</td>
  </tr>

  <tr>
    <th><a id="field-queries"><pre>queries</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
dns
smb</pre></td>
    <td class="description">The number of queries</td>
  </tr>

  <tr>
    <th><a id="field-query"><pre>query</pre></a></th>
    <td><a href="#type-databasequery"><pre>databasequery</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The database query</td>
  </tr>

  <tr>
    <th><a id="field-query.class"><pre>query.class</pre></a></th>
    <td><a href="#type-dnsclass"><pre>dnsclass</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The class of the DNS query</td>
  </tr>

  <tr>
    <th><a id="field-query.name"><pre>query.name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The name of the DNS query</td>
  </tr>

  <tr>
    <th><a id="field-query.payload"><pre>query.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
smb</pre></td>
    <td class="description">The total amount of bytes of payload in query PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-query.pdus"><pre>query.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
smb</pre></td>
    <td class="description">The total number of query PDUs (protocol data units) at applicative level</td>
  </tr>

  <tr>
    <th><a id="field-query.tcp_pdus"><pre>query.tcp_pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of TCP packets that form up these HTTP queries</td>
  </tr>

  <tr>
    <th><a id="field-query.type"><pre>query.type</pre></a></th>
    <td><a href="#type-dnstype"><pre>dnstype</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The type of the DNS query</td>
  </tr>

  <tr>
    <th><a id="field-query.write"><pre>query.write</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of data to be written</td>
  </tr>

  <tr>
    <th><a id="field-query_256"><pre>query_256</pre></a></th>
    <td><a href="#type-databasequery"><pre>databasequery</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">First 256 characters of the query</td>
  </tr>

  <tr>
    <th><a id="field-rd.count"><pre>rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of retransmission delays in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rd.deviation"><pre>rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the retransmission delay in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rd.total"><pre>rd.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The sum of both client and server average data-transfer times</td>
  </tr>

  <tr>
    <th><a id="field-request.content_length"><pre>request.content_length</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The average Content-Length in the headers of these HTTP requests</td>
  </tr>

  <tr>
    <th><a id="field-request.content_length.count"><pre>request.content_length.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of HTTP requests with a Content-Length header</td>
  </tr>

  <tr>
    <th><a id="field-request.content_pack"><pre>request.content_pack</pre></a></th>
    <td><a href="#type-path"><pre>path</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The path to the pack file that contains the HTTP request content</td>
  </tr>

  <tr>
    <th><a id="field-request.content_type"><pre>request.content_type</pre></a></th>
    <td><a href="#type-mimetype"><pre>mimetype</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The mime-type in the Content-Type header of the HTTP request</td>
  </tr>

  <tr>
    <th><a id="field-request.headers"><pre>request.headers</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of headers in request  PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-request.payload"><pre>request.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of payload in request PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-request.payload.md5"><pre>request.payload.md5</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The hash md5 calculated using the bytes of payload in request PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-request.traffic"><pre>request.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes (headers + payload) in request PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-response.category"><pre>response.category</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The HTTP response mime-type's category</td>
  </tr>

  <tr>
    <th><a id="field-response.class"><pre>response.class</pre></a></th>
    <td><a href="#type-dnsclass"><pre>dnsclass</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The class of the DNS response</td>
  </tr>

  <tr>
    <th><a id="field-response.code"><pre>response.code</pre></a></th>
    <td><a href="#type-dnscode"><pre>dnscode</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The DNS response code</td>
  </tr>

  <tr>
    <th><a id="field-response.content_length"><pre>response.content_length</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The average Content-Length in the headers of these HTTP responses</td>
  </tr>

  <tr>
    <th><a id="field-response.content_length.count"><pre>response.content_length.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of HTTP responses with a Content-Length header</td>
  </tr>

  <tr>
    <th><a id="field-response.content_pack"><pre>response.content_pack</pre></a></th>
    <td><a href="#type-path"><pre>path</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The path to the pack file that contains the HTTP response content</td>
  </tr>

  <tr>
    <th><a id="field-response.content_type"><pre>response.content_type</pre></a></th>
    <td><a href="#type-mimetype"><pre>mimetype</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The mime-type in the Content-Type header of the HTTP response</td>
  </tr>

  <tr>
    <th><a id="field-response.headers"><pre>response.headers</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes of headers in response PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-response.payload"><pre>response.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
http
smb</pre></td>
    <td class="description">The total amount of bytes of payload in response PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-response.payload.md5"><pre>response.payload.md5</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The hash md5 calculated using the bytes of payload in response PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-response.pdus"><pre>response.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>databases
smb</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-response.read"><pre>response.read</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of data read by SMB commands</td>
  </tr>

  <tr>
    <th><a id="field-response.status"><pre>response.status</pre></a></th>
    <td><a href="#type-httpstatus"><pre>httpstatus</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The HTTP response code</td>
  </tr>

  <tr>
    <th><a id="field-response.status.category"><pre>response.status.category</pre></a></th>
    <td><a href="#type-httpstatuscategory"><pre>httpstatuscategory</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The category of the response status code</td>
  </tr>

  <tr>
    <th><a id="field-response.tcp_pdus"><pre>response.tcp_pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of TCP packets that form up these HTTP responses</td>
  </tr>

  <tr>
    <th><a id="field-response.traffic"><pre>response.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The total amount of bytes (headers + payload) in response PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-response.type"><pre>response.type</pre></a></th>
    <td><a href="#type-dnstype"><pre>dnstype</pre></a></td>
    <td><pre>dns</pre></td>
    <td class="description">The type of the DNS response</td>
  </tr>

  <tr>
    <th><a id="field-response.written"><pre>response.written</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The total amount of bytes of data effectively written by SMB commands</td>
  </tr>

  <tr>
    <th><a id="field-resumed"><pre>resumed</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of resumed sessions</td>
  </tr>

  <tr>
    <th><a id="field-retrans.payload"><pre>retrans.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in retransmitted PDUs in both directions</td>
  </tr>

  <tr>
    <th><a id="field-retrans.pdus.ratio"><pre>retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmissions to the total number of PDUs (protocol data units) with payload in both directions</td>
  </tr>

  <tr>
    <th><a id="field-retrans.traffic"><pre>retrans.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
icmp
non_ip
other_ip
tcp
udp
voip</pre></td>
    <td class="description">The total amount of bytes in retransmitted PDUs in both directions</td>
  </tr>

  <tr>
    <th><a id="field-retrans.traffic.ratio"><pre>retrans.traffic.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmitted traffic to the entire traffic in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rows.integrated"><pre>rows.integrated</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of integrated rows</td>
  </tr>

  <tr>
    <th><a id="field-rows.integrated.per_minute"><pre>rows.integrated.per_minute</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of integrated rows per minute</td>
  </tr>

  <tr>
    <th><a id="field-rows.total"><pre>rows.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The total number of analyzed rows</td>
  </tr>

  <tr>
    <th><a id="field-rows.total.per_minute"><pre>rows.total.per_minute</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of total rows per minute</td>
  </tr>

  <tr>
    <th><a id="field-rows.truncated"><pre>rows.truncated</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of truncated rows</td>
  </tr>

  <tr>
    <th><a id="field-rows.truncated.per_minute"><pre>rows.truncated.per_minute</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>flows</pre></td>
    <td class="description">The number of truncated rows per minute</td>
  </tr>

  <tr>
    <th><a id="field-rsts"><pre>rsts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of RST packets in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rsts.ratio"><pre>rsts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of RST packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-rtt.count"><pre>rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of round-trip times in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rtt.deviation"><pre>rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the round-trip time in both directions</td>
  </tr>

  <tr>
    <th><a id="field-rtt.total"><pre>rtt.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The sum of both client and server average round-trip times</td>
  </tr>

  <tr>
    <th><a id="field-server.common_name"><pre>server.common_name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The Common Name of the server certificate</td>
  </tr>

  <tr>
    <th><a id="field-server.compressed.pdus"><pre>server.compressed.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The number of compressed server PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-server.compressed.pdus.ratio"><pre>server.compressed.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The ratio of compressions to the total number of PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.data"><pre>server.data</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of server data PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-server.datasource.kind"><pre>server.datasource.kind</pre></a></th>
    <td><a href="#type-pktsourcekind"><pre>pktsourcekind</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.datasource.name"><pre>server.datasource.name</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source name on which this traffic has been captured (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.datasource.pair"><pre>server.datasource.pair</pre></a></th>
    <td><a href="#type-pktsourcepair"><pre>pktsourcepair</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type and name on which this traffic has been captured (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.diffserv"><pre>server.diffserv</pre></a></th>
    <td><a href="#type-diffserv"><pre>diffserv</pre></a></td>
    <td><pre>icmp
other_ip
tcp
udp</pre></td>
    <td class="description">The server differentiated service</td>
  </tr>

  <tr>
    <th><a id="field-server.dtt"><pre>server.dtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The average data-transfer time for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.dtt.count"><pre>server.dtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The number of data-transfer times for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.dtt.deviation"><pre>server.dtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the data-transfer time for PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.dupacks"><pre>server.dupacks</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of duplicated ACK packets from the server</td>
  </tr>

  <tr>
    <th><a id="field-server.dupacks.ratio"><pre>server.dupacks.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of duplicated ACKs to the total number of packets emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.emtu"><pre>server.emtu</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp
non_ip
other_ip
tcp
udp</pre></td>
    <td class="description">The maximum payload in a single ethernet packet emmited by the server in these conversations (this value is assumed to be the MTU of the server's network interface, although the actual MTU value might be greater)</td>
  </tr>

  <tr>
    <th><a id="field-server.error.ip"><pre>server.error.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The IP address of the server, as it appears in the headers of the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-server.error.port"><pre>server.error.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The port of the server, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-server.error.zone.id"><pre>server.error.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone ID of the server, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-server.error.zone.name"><pre>server.error.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone of the server, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-server.expiration"><pre>server.expiration</pre></a></th>
    <td><a href="#type-time"><pre>time</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The expiration date of the server certificate</td>
  </tr>

  <tr>
    <th><a id="field-server.file"><pre>server.file</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the Pcap File used as traffic source (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.fins"><pre>server.fins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of FIN packets emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.fins.ratio"><pre>server.fins.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of server FIN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-server.interface"><pre>server.interface</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.ip"><pre>server.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The IP address of the server</td>
  </tr>

  <tr>
    <th><a id="field-server.ja3"><pre>server.ja3</pre></a></th>
    <td><a href="#type-tls_fingerprint"><pre>tls_fingerprint</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The JA3 server fingerprint</td>
  </tr>

  <tr>
    <th><a id="field-server.keepalives"><pre>server.keepalives</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of keep alives from the server</td>
  </tr>

  <tr>
    <th><a id="field-server.key.bits"><pre>server.key.bits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of bits in the server key</td>
  </tr>

  <tr>
    <th><a id="field-server.key.type"><pre>server.key.type</pre></a></th>
    <td><a href="#type-keytype"><pre>keytype</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The type of the server key</td>
  </tr>

  <tr>
    <th><a id="field-server.mac"><pre>server.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The MAC address of the server</td>
  </tr>

  <tr>
    <th><a id="field-server.meta"><pre>server.meta</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of server metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
  </tr>

  <tr>
    <th><a id="field-server.os"><pre>server.os</pre></a></th>
    <td><a href="#type-os"><pre>os</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The server operating system</td>
  </tr>

  <tr>
    <th><a id="field-server.payload"><pre>server.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.payload.pdus"><pre>server.payload.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) with payload emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.payload.ratio"><pre>server.payload.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The ratio of payload bytes to the entire traffic emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.pdus"><pre>server.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.port"><pre>server.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</pre></td>
    <td class="description">The TCP/UDP port of the server</td>
  </tr>

  <tr>
    <th><a id="field-server.rd"><pre>server.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average retransmission delay for PDUs emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.rd.count"><pre>server.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of retransmission delays for PDUs emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.rd.deviation"><pre>server.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the retransmission delay for PDUs emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.remote"><pre>server.remote</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured via rpcapd (server-side)</td>
  </tr>

  <tr>
    <th><a id="field-server.retrans.payload"><pre>server.retrans.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.retrans.pdus.ratio"><pre>server.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.retrans.traffic"><pre>server.retrans.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes in retransmitted PDUs emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.retrans.traffic.ratio"><pre>server.retrans.traffic.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmitted traffic to the entire traffic emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.rsts"><pre>server.rsts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of RST packets emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.rsts.ratio"><pre>server.rsts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of server RST packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-server.rt"><pre>server.rt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
smb
tcp
tls</pre></td>
    <td class="description">The average server response time (SRT)</td>
  </tr>

  <tr>
    <th><a id="field-server.rt.count"><pre>server.rt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
smb
tcp
tls</pre></td>
    <td class="description">The number of server response times</td>
  </tr>

  <tr>
    <th><a id="field-server.rt.deviation"><pre>server.rt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the server response time</td>
  </tr>

  <tr>
    <th><a id="field-server.rtt"><pre>server.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.rtt.count"><pre>server.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.rtt.deviation"><pre>server.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.last_code"><pre>server.signalization.last_code</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">Last SIP or MGCP response code</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.payload"><pre>server.signalization.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.pdus"><pre>server.signalization.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rd"><pre>server.signalization.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average retransmission delay for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rd.count"><pre>server.signalization.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of retransmission delays for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rd.deviation"><pre>server.signalization.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.retrans.pdus.ratio"><pre>server.signalization.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rt"><pre>server.signalization.rt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average server response time for signalization PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rt.count"><pre>server.signalization.rt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of server response times for signalization PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rt.deviation"><pre>server.signalization.rt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the server response time for signalization PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rtt"><pre>server.signalization.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rtt.count"><pre>server.signalization.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.rtt.deviation"><pre>server.signalization.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-server.signalization.traffic"><pre>server.signalization.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes in signalization PDUs (protocol data units) emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.signature"><pre>server.signature</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The server signature</td>
  </tr>

  <tr>
    <th><a id="field-server.traffic"><pre>server.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.vlan"><pre>server.vlan</pre></a></th>
    <td><a href="#type-vlan"><pre>vlan</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The VLAN id on the server side of the transaction</td>
  </tr>

  <tr>
    <th><a id="field-server.zero_windows"><pre>server.zero_windows</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of zero-window size packets emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.zero_windows.ratio"><pre>server.zero_windows.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of zero-window size to the total number of packets emitted by the server</td>
  </tr>

  <tr>
    <th><a id="field-server.zone.id"><pre>server.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone id of the server</td>
  </tr>

  <tr>
    <th><a id="field-server.zone.name"><pre>server.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone of the server</td>
  </tr>

  <tr>
    <th><a id="field-server_name"><pre>server_name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The Server Name Indication of the conversation</td>
  </tr>

  <tr>
    <th><a id="field-signalization.pdus"><pre>signalization.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rd.count"><pre>signalization.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of retransmission delays for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rd.deviation"><pre>signalization.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the retransmission delay for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rd.total"><pre>signalization.rd.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The sum of both client and server average retransmission delays for signalization PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-signalization.retrans.pdus.ratio"><pre>signalization.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of retransmissions to the total number of signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rtt.count"><pre>signalization.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of round-trip times for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rtt.deviation"><pre>signalization.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-signalization.rtt.total"><pre>signalization.rtt.total</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The sum of both client and server average round-trip times</td>
  </tr>

  <tr>
    <th><a id="field-signalization.traffic"><pre>signalization.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes in signalization PDUs (protocol data units) in both directions</td>
  </tr>

  <tr>
    <th><a id="field-smb.command"><pre>smb.command</pre></a></th>
    <td><a href="#type-smbcommand"><pre>smbcommand</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The SMB command</td>
  </tr>

  <tr>
    <th><a id="field-smb.command.code"><pre>smb.command.code</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The raw SMB command</td>
  </tr>

  <tr>
    <th><a id="field-smb.status"><pre>smb.status</pre></a></th>
    <td><a href="#type-smbstatus"><pre>smbstatus</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The SMB status</td>
  </tr>

  <tr>
    <th><a id="field-smb.subcommand"><pre>smb.subcommand</pre></a></th>
    <td><a href="#type-smbsubcommand"><pre>smbsubcommand</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The SMB subcommand</td>
  </tr>

  <tr>
    <th><a id="field-smb.subcommand.code"><pre>smb.subcommand.code</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The raw SMB subcommand</td>
  </tr>

  <tr>
    <th><a id="field-smb.version"><pre>smb.version</pre></a></th>
    <td><a href="#type-smb_version"><pre>smb_version</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The SMB protocol version</td>
  </tr>

  <tr>
    <th><a id="field-software"><pre>software</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The software in the Server header of the HTTP response</td>
  </tr>

  <tr>
    <th><a id="field-source.common_name"><pre>source.common_name</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The Common Name of the source certificate</td>
  </tr>

  <tr>
    <th><a id="field-source.compressed.pdus"><pre>source.compressed.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The number of compressed source PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-source.compressed.pdus.ratio"><pre>source.compressed.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix_channels</pre></td>
    <td class="description">The ratio of compressions to the total number of PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.data"><pre>source.data</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of source data PDUs (protocol data units)</td>
  </tr>

  <tr>
    <th><a id="field-source.datasource.kind"><pre>source.datasource.kind</pre></a></th>
    <td><a href="#type-pktsourcekind"><pre>pktsourcekind</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type (pcap file, netflow, network iface, rpcapd) on which this traffic has been captured (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.datasource.name"><pre>source.datasource.name</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source name on which this traffic has been captured (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.datasource.pair"><pre>source.datasource.pair</pre></a></th>
    <td><a href="#type-pktsourcepair"><pre>pktsourcepair</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The packet source type and name on which this traffic has been captured (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.diffserv"><pre>source.diffserv</pre></a></th>
    <td><a href="#type-diffserv"><pre>diffserv</pre></a></td>
    <td><pre>icmp
other_ip
tcp
udp</pre></td>
    <td class="description">The source differentiated service</td>
  </tr>

  <tr>
    <th><a id="field-source.dtt"><pre>source.dtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The average data-transfer time for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.dtt.count"><pre>source.dtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The number of data-transfer times for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.dtt.deviation"><pre>source.dtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls</pre></td>
    <td class="description">The deviation of the data-transfer time for PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.dupacks"><pre>source.dupacks</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of duplicated ACK packets from the source</td>
  </tr>

  <tr>
    <th><a id="field-source.dupacks.ratio"><pre>source.dupacks.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of duplicated ACKs to the total number of packets emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.emtu"><pre>source.emtu</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>icmp
non_ip
other_ip
tcp
udp</pre></td>
    <td class="description">The maximum payload in a single ethernet packet emmited by the source in these conversations (this value is assumed to be the MTU of the source's network interface, although the actual MTU value might be greater)</td>
  </tr>

  <tr>
    <th><a id="field-source.error.ip"><pre>source.error.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The IP address of the source, as it appears in the headers of the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-source.error.port"><pre>source.error.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The port of the source, as it appears in the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-source.error.zone.id"><pre>source.error.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone ID of the source, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-source.error.zone.name"><pre>source.error.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>icmp</pre></td>
    <td class="description">The zone of the source, determined using the TCP/UDP PDU (protocol data unit) transported by the ICMP error message</td>
  </tr>

  <tr>
    <th><a id="field-source.expiration"><pre>source.expiration</pre></a></th>
    <td><a href="#type-time"><pre>time</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The expiration date of the source certificate</td>
  </tr>

  <tr>
    <th><a id="field-source.file"><pre>source.file</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the Pcap File used as traffic source (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.fins"><pre>source.fins</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of FIN packets emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.fins.ratio"><pre>source.fins.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of source FIN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-source.interface"><pre>source.interface</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.ip"><pre>source.ip</pre></a></th>
    <td><a href="#type-ip"><pre>ip</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The IP address of the source</td>
  </tr>

  <tr>
    <th><a id="field-source.ja3"><pre>source.ja3</pre></a></th>
    <td><a href="#type-tls_fingerprint"><pre>tls_fingerprint</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The JA3 source fingerprint</td>
  </tr>

  <tr>
    <th><a id="field-source.keepalives"><pre>source.keepalives</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of keep alives from the source</td>
  </tr>

  <tr>
    <th><a id="field-source.key.bits"><pre>source.key.bits</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The number of bits in the source key</td>
  </tr>

  <tr>
    <th><a id="field-source.key.type"><pre>source.key.type</pre></a></th>
    <td><a href="#type-keytype"><pre>keytype</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The type of the source key</td>
  </tr>

  <tr>
    <th><a id="field-source.mac"><pre>source.mac</pre></a></th>
    <td><a href="#type-mac"><pre>mac</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The MAC address of the source</td>
  </tr>

  <tr>
    <th><a id="field-source.meta"><pre>source.meta</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The total number of source metadata (handshake, change cipher spec &amp; alerts PDU types)</td>
  </tr>

  <tr>
    <th><a id="field-source.os"><pre>source.os</pre></a></th>
    <td><a href="#type-os"><pre>os</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The source operating system</td>
  </tr>

  <tr>
    <th><a id="field-source.payload"><pre>source.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.payload.pdus"><pre>source.payload.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) with payload emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.payload.ratio"><pre>source.payload.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
tcp
tls
udp
voip</pre></td>
    <td class="description">The ratio of payload bytes to the entire traffic emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.pdus"><pre>source.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
citrix_channels
dns
icmp
non_ip
other_ip
tcp
udp
voip</pre></td>
    <td class="description">The total number of PDUs (protocol data units) at applicative level emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.port"><pre>source.port</pre></a></th>
    <td><a href="#type-port"><pre>port</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
http
smb
tcp
tls
udp
voip</pre></td>
    <td class="description">The TCP/UDP port of the source</td>
  </tr>

  <tr>
    <th><a id="field-source.rd"><pre>source.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average retransmission delay for PDUs emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.rd.count"><pre>source.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of retransmission delays for PDUs emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.rd.deviation"><pre>source.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the retransmission delay for PDUs emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.remote"><pre>source.remote</pre></a></th>
    <td><a href="#type-pktsourcename"><pre>pktsourcename</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The name of the network interface on which this traffic has been captured via rpcapd (source-side)</td>
  </tr>

  <tr>
    <th><a id="field-source.retrans.payload"><pre>source.retrans.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in retransmitted PDUs emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.retrans.pdus.ratio"><pre>source.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmissions to the total number of PDUs (protocol data units) with payload emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.retrans.traffic"><pre>source.retrans.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total amount of bytes in retransmitted PDUs emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.retrans.traffic.ratio"><pre>source.retrans.traffic.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of retransmitted traffic to the entire traffic emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.rsts"><pre>source.rsts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of RST packets emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.rsts.ratio"><pre>source.rsts.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of source RST packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-source.rtt"><pre>source.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average round-trip time for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.rtt.count"><pre>source.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of round-trip times for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.rtt.deviation"><pre>source.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The deviation of the round-trip time for PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.payload"><pre>source.signalization.payload</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes of data (without headers) in all signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.pdus"><pre>source.signalization.pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total number of signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rd"><pre>source.signalization.rd</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average retransmission delay for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rd.count"><pre>source.signalization.rd.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of retransmission delays for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rd.deviation"><pre>source.signalization.rd.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the retransmission delay for signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.retrans.pdus.ratio"><pre>source.signalization.retrans.pdus.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The ratio of retransmissions to the total number of signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rtt"><pre>source.signalization.rtt</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The average round-trip time for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rtt.count"><pre>source.signalization.rtt.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The number of round-trip times for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.rtt.deviation"><pre>source.signalization.rtt.deviation</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The deviation of the round-trip time for signalization PDUs (protocol data units) emitted by the destination</td>
  </tr>

  <tr>
    <th><a id="field-source.signalization.traffic"><pre>source.signalization.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">The total amount of bytes in signalization PDUs (protocol data units) emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.signature"><pre>source.signature</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The source signature</td>
  </tr>

  <tr>
    <th><a id="field-source.traffic"><pre>source.traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
icmp
non_ip
other_ip
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.vlan"><pre>source.vlan</pre></a></th>
    <td><a href="#type-vlan"><pre>vlan</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The VLAN id on the source side of the transaction</td>
  </tr>

  <tr>
    <th><a id="field-source.zero_windows"><pre>source.zero_windows</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of zero-window size packets emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.zero_windows.ratio"><pre>source.zero_windows.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of zero-window size to the total number of packets emitted by the source</td>
  </tr>

  <tr>
    <th><a id="field-source.zone.id"><pre>source.zone.id</pre></a></th>
    <td><a href="#type-zone_id"><pre>zone_id</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone id of the source</td>
  </tr>

  <tr>
    <th><a id="field-source.zone.name"><pre>source.zone.name</pre></a></th>
    <td><a href="#type-zone"><pre>zone</pre></a></td>
    <td><pre>citrix
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
voip</pre></td>
    <td class="description">The zone of the source</td>
  </tr>

  <tr>
    <th><a id="field-successes"><pre>successes</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
databases
dns
smb
voip</pre></td>
    <td class="description">The number of successes</td>
  </tr>

  <tr>
    <th><a id="field-successes.ratio"><pre>successes.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix
databases
dns
smb
voip</pre></td>
    <td class="description">The ratio of successes</td>
  </tr>

  <tr>
    <th><a id="field-syns"><pre>syns</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of SYN packets emitted by the client</td>
  </tr>

  <tr>
    <th><a id="field-syns.ratio"><pre>syns.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The average number of SYN packets in a connection</td>
  </tr>

  <tr>
    <th><a id="field-system"><pre>system</pre></a></th>
    <td><a href="#type-databasesystem"><pre>databasesystem</pre></a></td>
    <td><pre>databases</pre></td>
    <td class="description">The database system</td>
  </tr>

  <tr>
    <th><a id="field-tcp_pdus"><pre>tcp_pdus</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The number of TCP packets that form up the HTTP queries and responses</td>
  </tr>

  <tr>
    <th><a id="field-timeouts"><pre>timeouts</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>citrix</pre></td>
    <td class="description">The number of flows that timeouted</td>
  </tr>

  <tr>
    <th><a id="field-tls.version"><pre>tls.version</pre></a></th>
    <td><a href="#type-tls_version"><pre>tls_version</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The TLS protocol version</td>
  </tr>

  <tr>
    <th><a id="field-tls.version.is_weak"><pre>tls.version.is_weak</pre></a></th>
    <td><a href="#type-bool"><pre>bool</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">Is the TLS protocol version weak?</td>
  </tr>

  <tr>
    <th><a id="field-tls.version.major"><pre>tls.version.major</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The TLS protocol major version</td>
  </tr>

  <tr>
    <th><a id="field-tls.version.minor"><pre>tls.version.minor</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tls</pre></td>
    <td class="description">The TLS protocol minor version</td>
  </tr>

  <tr>
    <th><a id="field-traffic"><pre>traffic</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>dns
http
icmp
non_ip
other_ip
tcp
tls
udp
voip</pre></td>
    <td class="description">The total amount of bytes in both directions</td>
  </tr>

  <tr>
    <th><a id="field-tree"><pre>tree</pre></a></th>
    <td><a href="#type-path"><pre>path</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The tree this CIFS command relates to</td>
  </tr>

  <tr>
    <th><a id="field-tree.id"><pre>tree.id</pre></a></th>
    <td><a href="#type-descriptor"><pre>descriptor</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The id of the tree this CIFS command relates to</td>
  </tr>

  <tr>
    <th><a id="field-unclosed"><pre>unclosed</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The number of TCP sessions that didn't properly end</td>
  </tr>

  <tr>
    <th><a id="field-url"><pre>url</pre></a></th>
    <td><a href="#type-url"><pre>url</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The path, query and fragment parts of the URL</td>
  </tr>

  <tr>
    <th><a id="field-url.base"><pre>url.base</pre></a></th>
    <td><a href="#type-url"><pre>url</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The URL without the query string and fragment</td>
  </tr>

  <tr>
    <th><a id="field-url.path"><pre>url.path</pre></a></th>
    <td><a href="#type-path"><pre>path</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The URL path</td>
  </tr>

  <tr>
    <th><a id="field-user"><pre>user</pre></a></th>
    <td><a href="#type-string"><pre>string</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
smb</pre></td>
    <td class="description">The user</td>
  </tr>

  <tr>
    <th><a id="field-user.experience"><pre>user.experience</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The end-user experience (sum of RTTs, DTTs and SRT)</td>
  </tr>

  <tr>
    <th><a id="field-user_agent"><pre>user_agent</pre></a></th>
    <td><a href="#type-useragent"><pre>useragent</pre></a></td>
    <td><pre>http</pre></td>
    <td class="description">The user-agent</td>
  </tr>

  <tr>
    <th><a id="field-uuid"><pre>uuid</pre></a></th>
    <td><a href="#type-uuid"><pre>uuid</pre></a></td>
    <td><pre>citrix
citrix_channels
databases
dns
http
smb
tcp
tls
voip</pre></td>
    <td class="description">The unique identifier of this TCP session</td>
  </tr>

  <tr>
    <th><a id="field-voice.count"><pre>voice.count</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>voip</pre></td>
    <td class="description">Number of packets where we had voice in the conversation</td>
  </tr>

  <tr>
    <th><a id="field-warnings"><pre>warnings</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The number of warnings (mainly client-side)</td>
  </tr>

  <tr>
    <th><a id="field-warnings.ratio"><pre>warnings.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>smb</pre></td>
    <td class="description">The ratio of warnings to the total number of SMB queries</td>
  </tr>

  <tr>
    <th><a id="field-zero_windows"><pre>zero_windows</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The total number of zero-window size packets in both directions</td>
  </tr>

  <tr>
    <th><a id="field-zero_windows.ratio"><pre>zero_windows.ratio</pre></a></th>
    <td><a href="#type-number"><pre>number</pre></a></td>
    <td><pre>tcp</pre></td>
    <td class="description">The ratio of zero-window size to the total number of packets in both directions</td>
  </tr>

</tbody>
</table>

### Extra info
