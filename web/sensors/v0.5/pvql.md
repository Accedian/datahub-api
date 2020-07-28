---
title: PVQL 
---
![](https://accedian.com/wp-content/themes/accedian/images/accedian-logo-gold.svg)

# PVX API — The PVQL Language

Version 0.5.1

  - [Functions](functions)
  - [Definitions](definitions)
  - [PVQL](pvql)
  - [Changelog](changelog)

# The PVQL Syntax

The complete PVQL syntax is as follows:

    <values> [BY <group>] FROM <source>
        [WHERE <group-filter>] [HAVING <values-filter>]
        [TOP <window-and-ordering>] [SINCE <timestamp>] [UNTIL <timestamp>]
        [RAW]
        [SETTINGS <key-values>]

A valid PVQL query includes at least one `<value>` and one `<source>` in
the `FROM` clause; the `BY`/`WHERE`/`HAVING` clauses are optional, and
all other clauses default to specific values (defined below).

## Group and Values

`<values>` and `<group>` are expressions built from fields; the
exhaustive list of PVQL fields can be found in the
[Definitions](./definitions) page. A field is either a value field (a
metric), or a key field (a group), and can be used in the corresponding
clause.

The fields are the simplest form of expressions, and you can request
them as follows:

    client.traffic FROM transport

To request multiple values at once, use a comma as separator:

    client.traffic, server.traffic FROM transport

Some fields are built from simpler ones; for example, `traffic` is
defined as `client.traffic + server.traffic`. You can use either one
when querying:

    traffic FROM transport

    client.traffic + server.traffic FROM transport

When requesting multiple complex expressions, it is useful to name them
to distinguish which is which. PVQL supports aliases with the `AS`
keyword:

    client.traffic + server.traffic AS "Total traffic",
        client.traffic / (client.traffic + server.traffic) AS "Client Traffic Ratio"
        FROM transport

The group clause (with the `BY` keyword) specifies how to partition the
results: by time, by zones, applications, IP subnets, etc. You can group
by multiple expressions.

    client.traffic BY application FROM transport

    traffic BY client.zone, server.zone FROM transport

    traffic BY time(600) FROM transport

In the last example, we group the data for each period of 10 minutes
(600 s). A given point in PVQL corresponds to the data that preceded it.
For example, when using `BY time(600)`, the point at 12:00:00 is
actually the data accumulated between 11:50:00 and 12:00:00.

## Filtering

The filter specified with the `WHERE` keyword lets you limit the query
to certain keys.

    client.traffic BY layer, application FROM transport WHERE application != "http"

    client.rtt BY client.ip FROM transport WHERE (application = "http"
        OR application = "https") AND server.zone IN "/Local"

Notice the `IN` operator in this last example. It allows for filtering
on the `"/Local"` zone or any of its children.

The `IN` operator may also be used to check if an element belongs to a
set:

    client.traffic FROM transport WHERE server.port IN {80, 443, 8000..8800}

and for wildcard or pattern matching (using [re2
syntax](https://github.com/google/re2/wiki/Syntax)):

    client.traffic FROM tls WHERE server_name IN glob("*.google.*")

    client.traffic FROM http WHERE host IN re("^www\d")

These functions exist in case-insensitive variants (`iglob`, `ire`).
There are also functions `text` / `itext` for simple string comparisons
(default is case-insensitive).

You can further filter the final result with an `HAVING` clause, to keep
only the rows matching the given expression.

    client.traffic BY application FROM transport HAVING client.traffic >= 10000

Additionnaly, if you need to eliminate values at an early stage of the
query, you can filter fields directly in the `WHERE` clause using the
`raw.` prefix. Note that filtering this way requires a certain knowledge
of the way we store data.

    client.traffic, client.dtt BY application FROM transport WHERE raw.client.dtt != 0

## Window and Ordering

The window & ordering clause (which uses the `TOP` keyword) allows to
order and extract a portion of the result. To extract the first 5
results, use the following:

    client.traffic BY application FROM transport TOP 5

To request 10 lines of data while skipping the first 5 (that is, at
offset 5, since offsets start at 0), use the following:

    client.traffic, server.traffic BY client.zone, server.zone FROM transport TOP 10@5

The `ALL` keyword lets you request all lines of data starting at a given
offset:

    client.traffic, server.traffic BY client.zone, server.zone FROM transport TOP ALL@5

As for sorting, PVQL lets you sort on any or all of the values and keys
in the query. The i-th value is referred to by the name `vi`, while the
j-th key is referred to by the name `kj`. These names are used in the
`TOP` clause:

    client.traffic, server.traffic BY client.zone, server.zone FROM transport
        TOP 10@5 {v2 ASC, k1 ASC}

The sort direction accepts `ASC` or `DESC`. By default, the keys are
sorted in ascending order, and the values in descending order.

Some additional names are available in the ordering clause: - `v*`
refers to `v1`, `v2`, `v3`, ... - `k*` refers to `k1`, `k2`, `k3`, ... -
`*` refers to `v1`, `v2`, `v3`, ..., `k1`, `k2`, `k3`, ...

By default the result is sorted by values in descending order unless the
query is grouped by time, in which case the default behavior is to
return the result in chronological order.

Please note that you can only sort on expressions present in the query.

## Source Layer

The `FROM` clause lets you specify which layer to request.

    global.dtt BY application FROM http

## Date Range

The `SINCE` / `UNTIL` clauses allow for limitting the query to a given
time interval. They accept either the ISO8601 standard, or time
expressions:

    global.dtt BY application FROM http SINCE @(2018-02-20T10:00:00) UNTIL @now - 60*60

In this example, `@now` refers to the current time in seconds, thus
`@now - 60*60` refers to 3600 seconds ago (1 hour ago).

## Count Operator

PVQL provides a special `#` operator if we want to retrieve for a key,
the number of distinct elements.

    #client.ip FROM tcp

In this example, we request to PVQL the number of distinct client IPs.
While without this operator, PVQL will return a set of distinct client
IPs.

## Settings

A PVQL query can provide a `SETTINGS` clause to change some internal
behaviors of the query, and can be requested as follows:

    client.traffic FROM transport SETTINGS name = value [, ...]

We provide several settings for PVQL:

`limit_size_set`, which limits the size of the returned sets, for
example when we request a key as a value, the argument can take a
positive number, or a special value `ALL`.

    client.ip FROM transport SETTINGS limit_size_set = 10

This query above will return the first 10 client IPs found during the
execution of the query.

    client.ip FROM transport SETTINGS limit_size_set = ALL

While this query will return all client IPs found during the execution
of the query.

By default, PVQL returns the first 100 elements on a set.

`degradation_mode`, this setting is used to know how much PVQL should
degrade the query. The more a query has been degraded, the faster but
the less accurate it will be, and the less a query has been degraded,
the slower but more precise it will be.

We have several parameters for this setting:

`fast` mode is designed for queries where response time is really
important (ex: a dashboard with many widgets) and where we just need to
have an approximation regarding the result of the query. Generally
speaking, only complex queries are degraded: for example queries
involving keys or values that are expensive to process, or queries
executed on long time ranges.

    client.ip FROM transport SETTINGS degradation_mode = "fast"

`precise` mode will give more accurate results, while keeping the
execution time under control. It's a middle-ground between accuracy and
execution time, it can be used for a single widget with many values or
keys that are complex to process.

    client.ip FROM transport SINCE @(2019-01-20T10:00:00) UNTIL @(2019-02-20T10:00:00) SETTINGS degradation_mode = "precise"

`unlimited` mode is the most accurate mode and will give the result with
the best accuracy as possible, but should be used only if we don't have
any other choice, or for debugging purpose as the execution time will be
unchecked: it might prove too long for real-world queries and may slow
down the whole system.

    client.ip FROM transport SETTINGS degradation_mode = "unlimited"

## Raw

Finally, the `RAW` clause lets you disable result aggregation and
retrieve raw values stored in the database:

    traffic BY application FROM transport RAW

This query does not return the total traffic for each application, but
the traffic and application of each database record.

## String Literals

A string literal in PVQL is an arbitrary sequence of non-null characters
(characters with nonzero values) bounded by double quotes (`"`), for
example `"This is a string"`. To include a double-quote character within
a string literal, write two adjacent double quotes, e.g. `"Alice says
""Hello"" to Bob"`.

PVQL also accepts "escape" string literals, bounded by backquotes
(`` ` ``). Within an escape string, a backslash character (`\`) begins a
*backslash escape sequence*, in which the combination of backslash and
the following character(s) represents a special character. The
recognized escape sequences are:

<table>
<thead>
<tr class="header">
<th>Escape Sequence</th>
<th>Meaning</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><code>\\</code></td>
<td>Backslash</td>
</tr>
<tr class="even">
<td><code>\`</code></td>
<td>Backquote</td>
</tr>
<tr class="odd">
<td><code>\a</code></td>
<td>ASCII Bell (BEL)</td>
</tr>
<tr class="even">
<td><code>\b</code></td>
<td>ASCII Backspace (BS)</td>
</tr>
<tr class="odd">
<td><code>\f</code></td>
<td>ASCII Formfeed (FF)</td>
</tr>
<tr class="even">
<td><code>\n</code></td>
<td>ASCII Linefeed (LF)</td>
</tr>
<tr class="odd">
<td><code>\r</code></td>
<td>ASCII Carriage Return (CR)</td>
</tr>
<tr class="even">
<td><code>\t</code></td>
<td>ASCII Horizontal Tab (TAB)</td>
</tr>
<tr class="odd">
<td><code>\v</code></td>
<td>ASCII Vertical Tab (VT)</td>
</tr>
<tr class="even">
<td><code>\xhh</code></td>
<td>Character with hex value <em>hh</em></td>
</tr>
<tr class="odd">
<td><code>\uxxxx</code></td>
<td>Character with 16-bit hex value <em>xxxx</em></td>
</tr>
<tr class="even">
<td><code>\Uxxxxxxxx</code></td>
<td>Character with 32-bit hex value <em>xxxxxxxx</em></td>
</tr>
<tr class="odd">
<td><code>\N{name}</code></td>
<td>Character named <em>name</em> in the Unicode database</td>
</tr>
</tbody>
</table>

## Variables

PVQL supports variables. This allows you to insert variables with names
you choose (e.g. `$server`) whereever PVQL is expecting a value. When
querying data with such a PVQL expression, you can assign the variables
with custom values. The query is performed as if all variables were
substituted with the corresponding values.

For example, if you want a PVQL query regarding an application for a
specific server, you would usually write something like this:

    server.rt, server.dtt FROM tcp WHERE application = "NC" AND server.ip = 8.8.8.8

However, you might want to be able to easily choose another IP address
without rewriting the query each time. For this purpose, you can
introduce a variable, such as `$server`, in place of the actual value:

    server.rt, server.dtt FROM tcp WHERE application = "NC" AND server.ip = $server

Then wherever you request data using this query, you pass the
corresponding value in the `variables` parameters.

Example:

    => query expr="server.rt, server.dtt FROM tcp WHERE application = \"NC\" AND server.ip = $server" \
    ..       variables={"server": {"value": "8.8.4.4", "type": {"type": "ip"}}}

## Examples

In the following examples, it is implied that the queries are applied on
the last hour (because if neither `SINCE` nor `UNTIL` are provided, the
default time interval is used).

Retrieving the client traffic over time for the "transport" layer (which
is the combination of TCP, UDP, ICMP, Non IP and Other IP layers):

    client.traffic FROM transport BY time()

Retrieving both the client traffic and the server traffic, over time for
each "transport" layer:

    client.traffic, server.traffic FROM transport BY time(), layer

Retrieving the client traffic, the server traffic, and the mean of both,
over time by points of 5 minutes (300 seconds):

    client.traffic, server.traffic, (client.traffic + server.traffic) / 2
        BY time(300) FROM transport

Retrieving the total traffic for each `/24` IPv4 subnet limited to those
in `192.168.0.0/16` (thus for each 256 `192.168.x.0/24` networks):

    traffic BY server.ip[24] FROM transport WHERE server.ip[16] = 192.168.0.0

Retrieving the 20 highest average server response times for a matrix of
application × client zone:

    server.rt BY application, client.zone FROM transport TOP 20

Retrieving the server traffic per client zone:

    server.traffic BY client.zone FROM transport

Retrieving the server traffic for a matrix of client zone × application:

    server.traffic BY client.zone, application FROM transport

Retrieving the total traffic by protocol stack for each IPv4 client
within `192.168.0.0/16`:

    traffic BY protostack, client.ip FROM transport WHERE client.ip[16] = 192.168.0.0

Retrieving the total traffic from the HTTP layer for the given host:

    traffic FROM http WHERE host = "www.google.com"

Retrieving the top 10 total traffic by host from the HTTP layer limited
to those matching the given pattern:

    traffic BY host FROM http WHERE host IN "*.google.com" TOP 10

The `server.ip[n]` expression in these examples refer to subnets.
