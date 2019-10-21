# perf-diff

## Quickstart

This header only C library measures micro-architectural event diffs between two 
program locations. To capture the diffs instrument the source as follows.

```
#include "perf_diff.h"

void some_fn() {
  __perf_handle* h = __init_perf(argc, argv); // Setup perf events.
  assert(h != NULL);

  __start_perf(h);  // Start event capture.
  
  // Code to measure goes here.

  __stop_perf(h);   // Stop event capture and flush to disk.
}
```

The events captured is configured by setting `PERF_EVENTS` enviornment variable. 
Set it to a comma seperated list of events. Event names are same as those listed
by a `perf list` as pre-defined events. Currently we only support first three 
groups of events (i.e: Hardware event, Software event, Hardware cache event) 
listed there.

You can control the output file location by setting `PERF_OUTPUT`. The generated
output will be in csv format.

If you are doing performance optimization work which requires inspecting
micro-architectural event differences between optimizations then you can use
`perf-diff.py` to generate a table of diffs between the event counts between 
two captures.

Usage is as follows.

```
./perf-diff.py <before> <after>
```
