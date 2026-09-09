# Synthetic Lockdown plist bodies

These independently specified, LF-terminated XML fixtures contain no captured
device data, credentials or real trust records. The product string is synthetic;
it is not an observation about the owner's phone. No fixture establishes CarPlay
support. All four fixtures select GPL-3.0-only.

The C++ suite compares the GetValue encoder's exact bytes with the request and
escaped fixtures. It also sends the request and receives the response/error bodies
through the simulated dispatcher. Python's standard-library plist parser checks
the fixture dictionaries independently. The C implementation only frames opaque
responses; it does not yet parse them or interpret Error as a request failure.

The wire prefix is four bytes, big-endian, containing the BODY length only.
Tests specify this prefix independently; it is not part of these XML files.
