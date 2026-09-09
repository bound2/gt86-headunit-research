# Vendored dependency

`lzo-2.10/` contains unmodified miniLZO sources, two support headers and COPYING
from Markus F. X. J. Oberhumer's official LZO 2.10 archive:

- Source: https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
- Archive SHA256: `c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072`
- License: GNU GPL version 2 or later; see [COPYING](lzo-2.10/COPYING) and the
  notices in each source file. Preserve those notices. This dependency is linked
  into `qnxinspect` and the QNX tests; its GPL terms apply when distributing the
  linked program. No project-wide permissive license is asserted here.

Only the five files needed for miniLZO and its license were retained. The archive
itself is in the ignored `downloads/` directory. The existing `fwinspect` target
does not link miniLZO. Building requires no dependency download.

The QNX parser is local research code reading observed byte fields. It does not
vendor QNX headers or vendor firmware. Format references are recorded in the
[second-pass report](../reports/qnx-analysis.md).
