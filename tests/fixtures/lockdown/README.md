# Synthetic Lockdown plist bodies

These independently specified, LF-terminated XML fixtures contain no captured
device data, credentials or real trust records. The product string is synthetic;
it is not an observation about the owner's phone. No fixture establishes CarPlay
support. All four fixtures select GPL-3.0-only.

The C++ suite compares the GetValue encoder's exact bytes with the request and
escaped fixtures. It also sends the request and receives the response/error bodies
through the simulated dispatcher. Python's standard-library plist parser checks
the fixture dictionaries independently. The framing layer keeps responses opaque;
the separate bounded decoder and typed helper now distinguish Error from Value.

plist-binary-vectors.txt adds seven synthetic dictionaries serialized by Python
plistlib 3.14.7 with sort_keys=False. Tests independently verify their semantics
and exact serialization. They contain no real SessionID, escrow bag, trust record
or device capture; all fixtures select GPL-3.0-only. See
[the response report](../../../reports/lockdown-responses.md).

The wire prefix is four bytes, big-endian, containing the BODY length only.
Tests specify this prefix independently; it is not part of these XML files.
