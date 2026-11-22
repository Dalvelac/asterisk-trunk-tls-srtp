# Submission handoff for Daniel Alves

**VoIP I · VŠB–TUO · Topic 1 · Asterisk Trunk with TLS and SRTP Support**

## Open the submission

Open the [published website](https://dalvelac.github.io/asterisk-trunk-tls-srtp/), open [the offline build](site/index.html), or serve **only** its public directory from the project root.

```sh
python3 -m http.server 8777 --bind 127.0.0.1 --directory site
```

Visit [the local preview](http://127.0.0.1:8777/) and press Ctrl+C in the server terminal to stop it. The site and its downloads work with the telephone exchanges stopped. To demonstrate a new live call, run `./lab up secure`, `./lab status`, and `./lab call`. Look for one shared Call-ID and positive TX/RX with `tls=1 srtp=1` on both PBXs. Use `./lab down` to finish.

## Assignment cross-check

The supplied assignment, `VoIP_zadani_projektu.pdf`, is dated 26 August 2024. Topic 1 is on printed page 1. The general conditions span printed pages 1 and 2. The project folder contained the PDF, lab, README, and smoke traces. No newer lecturer message or submission workflow was supplied. The assignment permits up to two students and lists a maximum mark of 40 points. The named student on this submission is Daniel Alves.

| Requirement | Where to verify it |
|---|---|
| Title, author, topic introduction | [Title and introduction](site/index.html#introduction) |
| Current state of the art | [Introduction and current practice](site/index.html#introduction), linked IETF, Asterisk and Wireshark references |
| Two Asterisk servers connected by a trunk | [Topology and configuration](site/index.html#setup), [Compose topology](compose.yaml), [matched calls](experiment/logs/) |
| TLS signaling, SRTP media | [Packet evidence](site/index.html#evidence), secure Wireshark views, paired live channel flags and [verification output](experiment/verification.txt) |
| Bandwidth difference | [Methodology](site/index.html#method), [trial table and chart](site/index.html#results) and [per-direction calculations](site/data/results.csv) |
| tcpdump and Wireshark practical demonstration | [Six full captures](experiment/captures/), [GUI images, graph and export](site/evidence/), [timestamp and filter ledger](site/data/runs.csv) |
| Assessment / own contribution, conclusion | [Assessment, contribution and conclusion](site/index.html#assessment) |
| References | [Bibliography](site/index.html#references) and the original assignment listed above |
| Website documentation and reproducibility | [Deployable HTML](site/index.html), [guide](experiment/REPRODUCE.md), [analysis source](analysis/measure.py) |
| Announce topic by email by the next (11th) exercise, obtain teacher agreement | **Administrative status unverified.** Daniel must check his own correspondence for approval and any later instructions. |
| Week 14 presentation, maximum ten minutes | **Required in the supplied brief.** Exact calendar slot and any later change are unverified. See the timed outline below. |

No later instruction changing the PDF was available. The current request authorizes the finished measurements and website in addition to the starter lab. Submission, topic approval and a presentation booking have not been performed by this project.

## Verified findings

The original, unmodified short call answered on both Asterisk servers. Its Call-ID was `8d5086e7-7cb7-437a-a02d-66d233ee2e15`. Both channels showed µ-law, positive TX/RX and plaintext flags. The lab already offered a matched TCP baseline and required SRTP. The measurement recorder changes one live dialplan timer on each server. The original configuration files still match the starter.

- Six cold calls completed in alternating order, three per mode. No measured trial was discarded. Each 50-second steady window contained exactly 2,500 packets per direction. The baseline packets were 200 IPv4 bytes each and the secure packets were 210. Combined audio averaged **160 → 168 kb/s (+5%)** in every pair. Both directional steady bitrates had zero observed between-trial variation.
- Cold signaling setup averaged **3,127 → 8,054 IPv4 bytes (+4,927 bytes, +157.56%)**. Baseline ranged from 3,123 to 3,131 bytes and secure from 8,050 to 8,058. Both sample standard deviations were 4 bytes. All six captures had zero kernel drops, zero TCP retransmission indications, and no measured steady RTP sequence gaps.
- The installed profile on both PBXs in the separate diagnostic call was `AES_CM_128_HMAC_SHA1_80`. Its 10-byte tag explains the additional 4 kb/s per direction at 50 packets/s. Both peer certificates were presented. B rejected a missing client certificate, A rejected B under an unlisted name, and B rejected a plaintext-only media offer sent over TLS. The diagnostic uses fresh PBXs for each control because a first attempt to reload A's configuration retained its previous policy. That preliminary check occurred outside the measured series.
- All six original files were opened in Wireshark. The plotted pair's marked bins sum to 1,000,000 baseline and 1,050,000 secure IPv4 bytes. Independent parsing of Ethernet and IP records agreed with the TShark results across all 18 directional and combined rows. The originals and runtime logs are downloadable from the [website](site/index.html#downloads).

The final website was checked in Chromium at desktop and phone widths, including 320 px. Navigation, both playable recordings, figures, expandable tables and downloads worked. The loopback server returned the expected file bytes. A clean extraction of the public lab source, captures and logs regenerated all five CSVs and the comparison chart byte for byte. A clean extraction of the editable project reproduced the final HTML. Both release ZIPs passed CRC checks. Public download inventories exclude private keys and runtime state.

## Evidence and rebuild

- [Run ledger](site/data/runs.csv) records UTC times, Call-IDs, port pairs, window boundaries, SHA-256 hashes and anomalies. The short starter examples in `smoke/` are separate from the six measured calls.
- [Results](site/data/results.csv), [group means and variation](site/data/summary.csv), and [absolute and relative changes](site/data/differences.csv) use IPv4 total lengths and decimal kb/s.
- [Guide](experiment/REPRODUCE.md) covers the cold-start capture loop, independent policy and certificate checks, and replay on another machine. [Measurement definitions](analysis/README.md) explain each CSV.
- [Website source](website/) contains the editable report template and generator. The public CSS, fonts and images are in `site/`. The default build reads the six recorded results. Use Python 3, TShark and Matplotlib for a full rebuild.

```sh
python3 analysis/measure.py
python3 analysis/chart.py
python3 scripts/package-submission.py
python3 website/build.py
python3 scripts/bundle-submission.py
```

The local `submission-source.zip` includes the lab, website sources, built site, captures and logs. The bundler also includes the lecturer’s PDF when it is present locally. The ready-to-serve website ZIP is attached to the [GitHub release](https://github.com/Dalvelac/asterisk-trunk-tls-srtp/releases/tag/v1.0.0).

The downloadable archives are generated from an explicit file list. The packaging script reviews the original pcaps, checks the public handshake certificate fingerprints against the diagnostic log, and packs the selected files. Local private identities in `.lab/pki/` are never inputs to those archives.

## Update GitHub Pages

GitHub Pages serves the root of the `gh-pages` branch. The project source lives on `main`. After rebuilding and committing the updated site on `main`, run these commands from the project root to publish the contents of `site/`.

```sh
git push origin main
git subtree push --prefix site origin gh-pages
```

## Nine-minute website walkthrough

| Clock | Screen and point to explain |
|---|---|
| 0:00–0:50 | Open the title and listen to the two tones. State the question about signaling setup and steady media. |
| 0:50–2:00 | Show the topology and profiles. Trace A dialing extension 200 on B, then point to the ports for sound in both directions. |
| 2:00–3:20 | Show baseline SIP/SDP and Wireshark's two RTP streams. Explain PCMU and derive 160 samples from 20 ms at 8 kHz. |
| 3:20–4:50 | Show the TLS exchange, both certificates and the secure call's two media flags. Explain what each observation establishes. |
| 4:50–6:00 | Show the capture point and window markers. Explain why summing `ip.len` across a fixed interval gives a rate and why RTCP is separate. |
| 6:00–7:30 | Compare one pair on the Wireshark graph and all six calls in the result table. Explain a packet's extra bytes and the separate cold setup cost. |
| 7:30–8:30 | Discuss variation, scope, and how reusing a TLS connection affects interpretation. |
| 8:30–9:00 | Show the original pcaps, CSV and reproduction downloads. Leave one minute for questions within the ten-minute limit. |
