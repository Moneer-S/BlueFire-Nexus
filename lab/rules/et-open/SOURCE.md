# Emerging Threats Open rule subset

These files are a verbatim, privacy-clean subset of the Emerging Threats Open
rules archive for Suricata 7.0.3 and later, version 11342. The source archive
was fetched on 26 November 2026 from:

`https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz`

The archive is 5,674,186 bytes and its SHA-256 is
`993ba9ec3a0a185e30f418a157e1858e2276f27dc8fb7059402d96ead16c0a88`.
The archive itself is not committed. Each file listed in `SHA256SUMS` compares
byte for byte with the member of the same name in that archive. The three
upstream licence files are included unchanged.

The subset contains 1,553 enabled rules in eight complete category files,
totalling 1,337,494 bytes:

| Category file | Enabled rules | Coverage |
| --- | ---: | --- |
| `emerging-attack_response.rules` | 690 | responses returned by network services |
| `emerging-dns.rules` | 26 | DNS protocol activity |
| `emerging-ftp.rules` | 58 | FTP protocol activity |
| `emerging-icmp.rules` | 14 | ICMP protocol activity |
| `emerging-scan.rules` | 286 | network and service discovery |
| `emerging-sql.rules` | 191 | SQL protocol activity and input patterns |
| `emerging-telnet.rules` | 8 | Telnet protocol activity |
| `emerging-user_agents.rules` | 280 | HTTP user-agent patterns |

`classification.config` is included because Suricata uses its classifications
when it reports alert priority. No other category, IP reputation feed,
reference map, or metadata file from the 58,186,244-byte extracted archive is
included. In particular, this is not the complete ET Open distribution.
Several unselected upstream files also contain literal user-home paths that
the repository's unchanged privacy gate correctly refuses.

To reproduce the subset, first check the source archive's SHA-256. Treat the
archive as untrusted data: list it, then extract only the regular files named
in `SHA256SUMS` below a new output directory. Run nothing from the archive.
Finally, from this directory, run `sha256sum --check SHA256SUMS`.
