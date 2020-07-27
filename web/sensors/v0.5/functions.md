---
title: Functions
---

# Entry Points 
## Query
* list-fields		List all available fields and type descriptions.
* query		Request PVX data with the PVQL language.
## Test
* echo		Echo back the passed arguments.
## Other
* cancel		Cancel an API call.
* get-api-version		Return the API version.

# cancel

Cancel an API call.

## Arguments

- `id`: The ID of the call to cancel.

## Returns

A boolean indicating if the cancellation succeeded.

## Example 

    => cancel id="Query-DXGWL"
    true

# echo

Echo back the passed arguments.

This is a test function, perfect to get a feel of the API.

## Example 

    => echo name="Neptune" radius=24622
    {"name": "Neptune", "radius": 24622}

# get-api-version
Return the API version.

# list-fields
, "layers": [], "category": , "type": {...}, "description": { "default": , "layer1" : , ... }, "title": { "default": , "layer2" : , ... }, "short_title": { "default": , "layer1" : , "layer2" : , ... }, "kind": "regular" }, ...], "types": { : { "value_type": , "strict": , "items": [{ "value": , "name" : , ... }, ...], "default_format": }, ... } } ``` ">
List all available fields and type descriptions.

## Returns

An object of the form:

```
{
    "fields": [{
        "name": ,
        "layers": [],
        "category": ,
        "type": {...},
        "description": {
            "default": ,
            "layer1" : ,
            ...
        },
        "title": {
            "default": ,
            "layer2" : ,
            ...
        },
        "short_title": {
            "default": ,
            "layer1" : ,
            "layer2" : ,
            ...
        },
        "kind": "regular"
    }, ...],
    "types": {
        : {
            "value_type": ,
            "strict": ,
            "items": [{
                "value": ,
                "name" : ,
                ...
            }, ...],
            "default_format":
        },
        ...
    }
}
```
# query
": {"value": "10.0.0.0"}, "traffic": {"value": 89930326910}}, {"": {"value": "172.0.0.0"}, "traffic": {"value": 31681460665}}, {"": {"value": "192.0.0.0"}, "traffic": {"value": 7825192006}}, {"": {"value": "\u00f8"}, "traffic": {"status": "empty"}}, {"": {"value": "55.0.0.0"}, "traffic": {"value": 62848673}} ] } ``` ## The `meta` entry This entry is directly linked to the `data`, i.e. there will be no `meta` entry unless there is a `data` one. It contains the following information: - `sorted`: whether the rows in `data` are sorted or not. - `elapsed`: the duration for building this chunk. - `accumulatedTime`: the total duration since the start of the query. - `emptyData`: whether there was actual data for the requested period of time. If `true`, when using `compact` mode, a `null` value should be interpreted as the absence of data. - `totalRowsToRead`: total number of rows read by ClickHouse. Here is an example. ```json { "meta": { "accumulatedTime": 0.02259683609008789, "elapsed": 0.017426252365112305, "sorted": true, "totalRowsToRead": 554457 } } ``` ">
Request PVX data with the PVQL language.

## Arguments

- `expr`: The PVQL expression to execute.
- `variables`: An optional object to map variables values used in the PVQL expression.
- `format`: The format of the resulting data. Either `plain`,
  `compact` or `named`. Default to `plain`. See more about data format
  below.
- `dry`: When set to `true`, the query is only parsed and analyzed,
  but it is not actually executed. This is convenient for interfaces
  that need to validate syntax and to obtain meta information (which
  columns will actually be requested for instance).

See the [PVQL](./pvql) topic for a detailed description of the language.

## Returns

This function returns a series of chunks.

Each chunk contains one or more of the following entries:

 - `info`: general information on the query.
 - `data`: portion of the result (the result can be split into multiple portions).
 - `meta`: metadata, closely related to the `data`.

More precisely, the chunk contains one of the following set of entries:
 - `info`
 - `data` and `meta`
 - `info`, `data` and `meta`

## The `info` entry

The `info` entry contains important information, such as:

 - `expr`: the requested expression.
 - `level`: the actual aggregation level (either explicitly specified by
   the user, or automatically determined from the query).
 - `step`: the time span of a point in the result.
 - `timerange`: the actual time interval that was queried (which is adjusted
   to align with the step).
 - `meta`: contains miscellaneous information:
   - `meta.context`: all the extra variables made available for the query.
   - `meta.expectedRowCount`: a range of the number of rows to expect in
     the result.
   - `meta.sources`: the partitions of the database that were queried.
   - `meta.sort`: describes how to sort the data when split across multiple
   chunks.
   - `meta.complexity`: contains complexity information.
     - `meta.complexity.max_requested`: the maximum allowed complexity in the query
        (`null` if not bounded).
     - `meta.complexity.selected`: the selected complexity to run the query with.
     - `meta.complexity.thresholds`: the array of complexity thresholds to get more accurate results.

The information in `meta.sort` is structured as an array of items; each
item is in the form `[key-or-value?, index, direction]`, where `key-or-value?`
is either 0 for a key, or 1 for a value, `index` determines which key or value
to sort on (beware that the indices start at 0), and `direction` is the sort
direction (either in ASCending or DESCending order).

we first sort on the first value expression (in descendant order),
then on the first element of the group (is ascendant order).

```json
"sort": [
    ["values", 0, "DESC"],
    ["key", 0, "ASC"]
]
```

## The `data` entry

The `data` entry contains the rows of data resulting from the execution
of the query.

Its structure depends of the `format` argument.

### The `plain` format

In this format, the data are structured as an array of rows, where
each row is made of two parts: the key, and the values.

For example, when querying `traffic`, we obtain the following data:

```json
{
    "data": [{"key": [], "values": [{"value": 138229969750}]}]
}
```

Here, the `data` entry contains a single row: `[{"key": [], "values": [{"value": 138229969750}]}]`.
The key of the row (`[]`), is empty because we are not grouping the values
(no `BY` clause in the query).
On the other hand, the values part (`[{"value": 138229969750}]`)
consists of one object whose value is the traffic.

It may happen that the field value is missing,
for example because it was dropped during aggregation. In this case, the
resulting object looks like

```json
{"status": "merged"}
```

with a single attribute `status` indicating why the value is missing
(`merged`, `invalid`, `ignored` or `empty`).

Array values may be truncated for performance reasons. In this case,
the result objects come with both `"value"` and `"status": "truncated"`
attributes.

Let's consider another example, `traffic BY server.ip[8] TOP 5`, which
results in the following chunk:

```json
{
    "data": [
        {"key": [{"value": "10.0.0.0"}], "values": [{"value": 89930326910}]},
        {"key": [{"value": "172.0.0.0"}], "values": [{"value": 31681460665}]},
        {"key": [{"value": "192.0.0.0"}], "values": [{"value": 7825192006}]},
        {"key": [{"value": "\u00f8"}], "values": [{"status": "empty"}]},
        {"key": [{"value": "55.0.0.0"}], "values": [{"value": 62848673}]}
    ]
}
```

Due to grouping by `server.ip[8]`, each row has a subnet in its key
portion.

### The `compact` format

In this format, the data are structured accordingly to the query.

When querying a single value, such as `traffic`, the data is
represented by just this value:

```json
{
    "data": {"value": 138229969750}
}
```

When querying multiples values, with no groupment, such as `traffic,
pdus`, the data is a simple array:

```json
{
    "data": [{"value": 138229969750}, {"value": 993478670}]
}
```

For queries with groupment, such as `traffic BY server.ip[8] TOP 5`,
the format is close to the `plain` format except that key and values
are grouped:

```json
{
    "data": [
        [{"value": "10.0.0.0"}, {"value": 89930326910}],
        [{"value": "172.0.0.0"}, {"value": 31681460665}],
        [{"value": "192.0.0.0"}, {"value": 7825192006}],
        [{"value": "\u00f8"}, {"status": "empty"}],
        [{"value": "55.0.0.0"}, {"value": 62848673}]
    ]
}
```

### The `named` format

In this format, each row of the result is an object.

For example, for a query such as `traffic BY server.ip[8] FROM transport TOP 5`, this
will return:

```json
{
    "data": [
        {"": {"value": "10.0.0.0"}, "traffic": {"value": 89930326910}},
        {"": {"value": "172.0.0.0"}, "traffic": {"value": 31681460665}},
        {"": {"value": "192.0.0.0"}, "traffic": {"value": 7825192006}},
        {"": {"value": "\u00f8"}, "traffic": {"status": "empty"}},
        {"": {"value": "55.0.0.0"}, "traffic": {"value": 62848673}}
    ]
}
```

## The `meta` entry

This entry is directly linked to the `data`, i.e. there will be no
`meta` entry unless there is a `data` one.

It contains the following information:

 - `sorted`: whether the rows in `data` are sorted or not.
 - `elapsed`: the duration for building this chunk.
 - `accumulatedTime`: the total duration since the start of the query.
 - `emptyData`: whether there was actual data for the requested period
   of time. If `true`, when using `compact` mode, a `null` value
   should be interpreted as the absence of data.
 - `totalRowsToRead`: total number of rows read by ClickHouse.

Here is an example.

```json
{
    "meta": {
        "accumulatedTime": 0.02259683609008789,
        "elapsed": 0.017426252365112305,
        "sorted": true,
        "totalRowsToRead": 554457
    }
}
```
