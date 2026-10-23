# Synthetic APT signature fixtures

`InRelease` is a synthetic Ubuntu-shaped Release signed by the test-only key in
`archive-public.asc`. It uses `Origin: Ubuntu`, `Label: Ubuntu`, `Suite: noble`
and `Codename: noble`, with no `Valid-Until`. Its Packages hash and byte count
are synthetic; tests supply matching index evidence.

The public key is **not an Ubuntu archive key** and must not be installed as a
trusted repository key. The fixture was generated in a disposable GPG home;
no private key is retained. Tests verify this signature with real GPG tools
when available, then separately exercise rejected signatures and keys.

These fixtures prove the local verification path against synthetic inputs.
They do not prove authentication of a public Ubuntu archive, a real APT
transaction, a download or a privileged installation.
