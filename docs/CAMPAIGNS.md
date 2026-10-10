# Campaigns

A campaign is a set of sessions that probably come from one operator or one botnet. Surya Kundal
groups sessions by what they share, and shows the reason for every group.

## What links two sessions

| Shared | Weight | Why it matters |
|---|---|---|
| Downloaded file hash | strong | The same payload |
| Download URL | strong | The same hosting (also an address only attempted, with egress blocked) |
| Uploaded file hash | strong | The same payload |
| Script or command sequence (after normalising addresses, numbers and temp names) | strong | The same playbook |
| Password list of 8 or more entries, same order | medium | The same wordlist |
| SSH client fingerprint (HASSH) | weak | The same tooling; common tools share it |

Two sessions join a campaign when their combined weight reaches 5. Weak features can never link
alone, and a feature shared by more than 25 sessions is ignored, because a fingerprint that common
describes a tool, not an operator.

## Using it

```
surya-kundal campaigns build        # regroup now
surya-kundal campaigns list
surya-kundal campaigns show <id>    # a unique prefix is enough
```

`surya-kundal run` regroups every 10 minutes when new sessions arrived (`--campaign-interval`).
The dashboard shows the same under Campaigns.

## Limits

Clusters are evidence, not attribution. A shared public payload (a popular miner script) can join
unrelated operators; read the "Why these sessions are grouped" table before drawing conclusions.
IDs come from the earliest session in the group, so they stay the same as a campaign grows.

## What does not link sessions

Addresses that say nothing about an operator are ignored: look-up services and popular sites
(`ifconfig.me`, `google.com` and similar), and the host part of a URL on a place anyone can publish
(github, pastebin, file-sharing and cloud-storage hosts). The full address of a file on such a host
still links sessions, because two sessions fetching the very same file are related. One shared strong
feature (the same file, address or command script) is enough to link, so two unrelated actors who
use an identical public script are grouped; read the evidence on a campaign page before treating it
as one operator.
