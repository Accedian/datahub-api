---
title: Change Log
---
![](https://accedian.com/wp-content/themes/accedian/images/accedian-logo-gold.svg)

# PVX API — Changelog

Version 0.5.1

  - [Functions](functions)
  - [Definitions](definitions)
  - [PVQL](pvql)
  - [Changelog](changelog)

## \[0.5.1\] - In development

### Added

  - Added new field [smb.md5](./definitions#field-smb.md5)

## \[0.5\]

### Added

  - Added new zone related fields:
      - Added new field
        [client.zone.id](./definitions#field-client.zone.id).
      - Added new field
        [server.zone.id](./definitions#field-server.zone.id).
      - Added new field
        [source.zone.id](./definitions#field-source.zone.id).
      - Added new field
        [dest.zone.id](./definitions#field-dest.zone.id).
      - Added new field
        [client.error.zone.id](./definitions#field-client.error.zone.id).
      - Added new field
        [server.error.zone.id](./definitions#field-server.error.zone.id).
      - Added new field
        [source.error.zone.id](./definitions#field-source.error.zone.id).
      - Added new field
        [dest.error.zone.id](./definitions#field-dest.error.zone.id).
      - Added new field
        [caller.zone.id](./definitions#field-caller.zone.id).
      - Added new field
        [callee.zone.id](./definitions#field-callee.zone.id).
  - Added new field
    [application.id](./definitions#field-application.id).
  - Add fields related to MD5 for HTTP
      - Add new field
        [request.payload.md5](./definitions#field-request.payload.md5)
      - Add new field
        [response.payload.md5](./definitions#field-response.payload.md5)

### Changed

  - Add support for extended IP and MAC masks (`<ip>/<ip>`,
    `<mac>/<mac>`).
  - Fix using `#`(count) operator on complex fields.
  - Zone related changes:
      - Renamed field `client.zone` to
        [client.zone.name](./definitions#field-client.zone.name).
      - Renamed field `server.zone` to
        [server.zone.name](./definitions#field-server.zone.name).
      - Renamed field `source.zone` to
        [source.zone.name](./definitions#field-source.zone.name).
      - Renamed field `dest.zone` to
        [dest.zone.name](./definitions#field-dest.zone.name).
      - Renamed field `client.error.zone` to
        [client.error.zone.name](./definitions#field-client.error.zone.name).
      - Renamed field `server.error.zone` to
        [server.error.zone.name](./definitions#field-server.error.zone.name).
      - Renamed field `source.error.zone` to
        [source.error.zone.name](./definitions#field-source.error.zone.name).
      - Renamed field `dest.error.zone` to
        [dest.error.zone.name](./definitions#field-dest.error.zone.name).
      - Renamed field `caller.zone` to
        [caller.zone.name](./definitions#field-caller.zone.name).
      - Renamed field `callee.zone` to
        [callee.zone.name](./definitions#field-callee.zone.name).
  - Renamed field `application` to
    [application.name](./definitions#field-application.name).

## \[0.4\] - 2020-05-27

### Added

  - Added new field
    [capture.hostname](./definitions#field-capture.hostname).
  - Added new field [caller.label](./definitions#field-caller.label).
  - Added new field [callee.label](./definitions#field-callee.label).
  - Added new field [client.ja3](./definitions#field-client.ja3).
  - Added new field [server.ja3](./definitions#field-server.ja3).
  - Added new field [source.ja3](./definitions#field-source.ja3).
  - Added new field [dest.ja3](./definitions#field-dest.ja3).

### Changed

  - Renamed field `capture` to
    [capture.id](./definitions#field-capture.id).
  - Clause `FROM` is now mandatory.
  - Improve support for mac address querying:
      - Able to match a mac address using both a continuous and non
        continuous mask.
      - Create non continuous mask filtering for mac address.
      - Implement `IN` operation for mac address using a continuous
        mask.
  - Order results in PVQL distinct sets.
  - Add PVQL setting `limit_size_set = 100`.
  - Implement `glob`/`iglob` functions for applications.
  - Ignoring case when sorting by a string field.
  - Fix can't query dicts as values.

### Removed

  - Removed field `storage` from public API.
