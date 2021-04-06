# PVX API — Changelog

Version 0.7.0

## \[0.7\]

### Added

  - Support [flatten](./pvql#flatten) function for `url` type.
  - Added new VLAN related fields. It is possible now to use the
    operator `IN` with a list of VLANs, For example, `traffic FROM tcp
    WHERE 5 IN server.vlans`.
      - Added new field
        [client.vlans](./definitions#field-client.vlans).
      - Added new field
        [server.vlans](./definitions#field-server.vlans).
      - Added new field
        [source.vlans](./definitions#field-source.vlans).
      - Added new field [dest.vlans](./definitions#field-dest.vlans).
      - Added new field
        [client.vlans.outer](./definitions#field-client.vlans.outer).
      - Added new field
        [server.vlans.outer](./definitions#field-server.vlans.outer).
      - Added new field
        [source.vlans.outer](./definitions#field-source.vlans.outer).
      - Added new field
        [dest.vlans.outer](./definitions#field-dest.vlans.outer).
      - Added new field
        [client.vlans.inner](./definitions#field-client.vlans.inner).
      - Added new field
        [server.vlans.inner](./definitions#field-server.vlans.inner).
      - Added new field
        [source.vlans.inner](./definitions#field-source.vlans.inner).
      - Added new field
        [dest.vlans.inner](./definitions#field-dest.vlans.inner).
      - Added new field
        [client.vlans.count](./definitions#field-client.vlans.count).
      - Added new field
        [server.vlans.count](./definitions#field-server.vlans.count).
      - Added new field
        [source.vlans.count](./definitions#field-source.vlans.count).
      - Added new field
        [dest.vlans.count](./definitions#field-dest.vlans.count).
  - Added new fields for time window exclusion:
      - Added new field
        [time\_exclusion.business\_hours](./definitions#field-time_exclusion.business_hours).
      - Added new field
        [time\_exclusion.maintenance\_windows](./definitions#field-time_exclusion.maintenance_windows).
      - Added new field
        [time\_exclusion.any](./definitions#field-time_exclusion.any).
  - Added new fields for DNS-issued hostnames:
      - Added new field
        [client.hostname](./definitions#field-client.hostname).
      - Added new field
        [server.hostname](./definitions#field-server.hostname).
      - Added new field
        [source.hostname](./definitions#field-source.hostname).
      - Added new field
        [dest.hostname](./definitions#field-dest.hostname).
      - Added new field
        [netflow.hostname](./definitions#field-netflow.hostname).

### Deprecated

  - Single VLAN fields are deprecated by fields containing lists of
    VLANs.
      - Deprecated field [client.vlan](./definitions#field-client.vlan).
      - Deprecated field [server.vlan](./definitions#field-server.vlan).
      - Deprecated field [source.vlan](./definitions#field-source.vlan).
      - Deprecated field [dest.vlan](./definitions#field-dest.vlan).

## \[0.6\]

### Added

  - Added new endpoint [query-cancel](./endpoints#get-cancel)
  - Support [flatten](./pvql#flatten) function for `zone_id` type.
  - Added new time related fields:
      - Added new field [begin](./definitions#field-begin).
      - Added new field [end](./definitions#field-end).
      - Added new field
        [request.begin](./definitions#field-request.begin).
      - Added new field [request.end](./definitions#field-request.end).
      - Added new field [query.begin](./definitions#field-query.begin).
      - Added new field [query.end](./definitions#field-query.end).
      - Added new field [page.begin](./definitions#field-page.begin).
      - Added new field [page.end](./definitions#field-page.end).

### Removed

  - `points` function has been removed, field
    [points](./definitions#field-points) should be used instead.

## \[0.5.1\]

### Added

  - Added new field [smb.md5](./definitions#field-smb.md5)
  - Added new endpoint [get-degradations](./endpoints#get-degradations)
  - Added new endpoint [get-layers](./endpoints#get-layers)

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
