# nessus_splitter

`nessus-splitter` turns one large `.nessus` export into smaller, independently
valid Nessus XML files. It is intended for reporting platforms whose upload
limits reject a full scan export.

The splitter preserves the policy and report metadata in every output file and
keeps each complete `<ReportHost>` record together with all of its findings.
It processes host records as a stream, so memory usage does not grow with the
full report size.

## Installation

Python 3.9 or newer is required. The tool has no runtime dependencies.

```bash
git clone https://github.com/w0ot-net/nessus_splitter.git
cd nessus_splitter
python3 -m pip install .
```

For development or direct use from a clone:

```bash
python3 -m pip install -e .
```

## Usage

Split a report into exactly ten non-empty files:

```bash
nessus-splitter scan.nessus --parts 10
```

This creates `scan_split/scan_01.nessus` through
`scan_split/scan_10.nessus`. Exact-count mode balances contiguous host records
by their serialized size rather than merely putting the same number of hosts
in every file.

Create files targeting approximately 100 MB each:

```bash
nessus-splitter scan.nessus --size-mb 100
```

Size mode permits up to 2 MB of overshoot by default. Change that tolerance or
disable it entirely:

```bash
nessus-splitter scan.nessus --size-mb 100 --grace-mb 1
nessus-splitter scan.nessus --size-mb 100 --grace-mb 0
```

Choose a destination and allow replacement of existing split files:

```bash
nessus-splitter scan.nessus --parts 10 --output-dir ./parts --force
```

One MB is treated as 1,048,576 bytes. Output numbering uses at least two
digits and expands automatically: `_01` to `_10`, or `_001` to `_100`.

## Size guarantees

Nessus findings are grouped beneath `<ReportHost>` elements. The splitter
never divides one host across multiple files because doing so can alter import
semantics in downstream reporting tools. If one complete host is larger than
the requested size plus grace, that output file must exceed the target. The
CLI flags and warns about such a file.

The shared policy and report metadata are copied into each output and count
toward its target size. Every temporary output is parsed and validated before
it atomically replaces its final filename.

## Security note

Nessus exports can contain sensitive host data, vulnerability evidence, and
occasionally secrets embedded in plugin output. The repository ignores
`*.nessus` files by default. Review where you store and share split reports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
