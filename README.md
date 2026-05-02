# Open Source DFIR Tools Reference

> A curated reference catalog of open-source Digital Forensics & Incident Response (DFIR) tools, organized by discipline. Maintained as a living reference for practitioners, researchers, and students.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-green.svg)]()
[![DFIR](https://img.shields.io/badge/Category-DFIR-blue.svg)]()

---

## Table of Contents

1. [Artifact Collection & Triage](#1-artifact-collection--triage)
2. [Disk Imaging & Evidence Preservation](#2-disk-imaging--evidence-preservation)
3. [File System & Disk Analysis](#3-file-system--disk-analysis)
4. [Memory Forensics](#4-memory-forensics)
5. [Timeline Analysis & Visualization](#5-timeline-analysis--visualization)
6. [Windows Artifact Parsers](#6-windows-artifact-parsers)
7. [Mobile Forensics](#7-mobile-forensics)
8. [Network Forensics & SIEM](#8-network-forensics--siem)
9. [Incident Response & Orchestration](#9-incident-response--orchestration)
10. [Malware Analysis & Reverse Engineering](#10-malware-analysis--reverse-engineering)
11. [Log Analysis & Threat Detection](#11-log-analysis--threat-detection)
12. [Cloud Forensics & IR](#12-cloud-forensics--ir)
13. [Registry Analysis](#13-registry-analysis)
14. [Email & Communication Forensics](#14-email--communication-forensics)
15. [Threat Intelligence Platforms](#15-threat-intelligence-platforms)
16. [OSINT & Reconnaissance](#16-osint--reconnaissance)
17. [Forensic Distributions & Workstations](#17-forensic-distributions--workstations)
18. [Reporting & Case Management](#18-reporting--case-management)
19. [macOS Forensics](#19-macos-forensics)
20. [Browser & Internet Artifact Forensics](#20-browser--internet-artifact-forensics)
21. [Docker & Container Forensics](#21-docker--container-forensics)
22. [Steganography & Image Forensics](#22-steganography--image-forensics)
23. [Password Recovery & Decryption](#23-password-recovery--decryption)
24. [Scripting Frameworks & Lightweight IR](#24-scripting-frameworks--lightweight-ir)

---

## 1. Artifact Collection & Triage

Tools for live response, rapid triage, and forensic artifact acquisition from endpoints.

| Tool | Description | Language |
|------|-------------|----------|
| [Velociraptor](https://github.com/velocidex/velociraptor) | Endpoint visibility and collection platform using Velociraptor Query Language (VQL). Supports large-scale fleet hunting, artifact collection, and live response across Windows, Linux, and macOS. | Go |
| [KAPE](https://github.com/KrollArtifactParserExtractor/KapeConfigs) | Kroll Artifact Parser and Extractor — targets and modules for fast, structured evidence collection. Widely used for triage imaging and artifact parsing in a single pass. | PowerShell/C# |
| [UAC](https://github.com/tclahr/uac) | Unix-like Artifacts Collector — live response script for Linux, macOS, Solaris, AIX, and ESXi. Automates volatile and non-volatile artifact collection without external dependencies. | Shell |
| [CyLR](https://github.com/orlikoski/CyLR) | NTFS-aware forensic artifact collector for Windows. Bypasses file locks to collect key artifacts even from running systems. Outputs a compressed ZIP archive. | C# |
| [Hoarder](https://github.com/p0dalirius/Hoarder) | Collects and parses forensic artifacts from Windows systems. Focused on attacker-relevant artifacts for rapid compromise assessment. | Python |
| [artifactcollector](https://github.com/forensicanalysis/artifactcollector) | Customizable forensic artifact collector that runs on Windows, macOS, and Linux. Driven by ForensicArtifacts definitions for consistent, repeatable collection. | Go |
| [DFIR ORC](https://github.com/DFIR-ORC/dfir-orc) | Modular forensics artifact collection framework for Windows systems. Developed by ANSSI (French CERT). Produces structured output for downstream parsing. | C++ |
| [GRR Rapid Response](https://github.com/google/grr) | Google's remote live forensics and incident response framework. Agent-based architecture enables large-scale fleet investigation with Python-based rules. | Python |
| [CyberPipe](https://github.com/dwmetz/CyberPipe) | PowerShell-based live response script that automates memory capture and artifact collection, wrapping tools like AVML, Magnet RAM Capture, and more. | PowerShell |
| [IR-Rescue](https://github.com/diogo-fernan/ir-rescue) | Windows Batch/Bash live response script for collecting forensic artifacts during incident response. Lightweight, no dependencies. | Batch/Bash |
| [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) | Real-time artifact collector for Windows. Extracts filesystem metadata, registry data, running processes, and scheduled tasks into a structured report. | Python |

---

## 2. Disk Imaging & Evidence Preservation

Tools for acquiring forensically sound disk images and verifying evidence integrity.

| Tool | Description | Language |
|------|-------------|----------|
| [Guymager](https://github.com/freetimecreations/guymager) | Open-source forensic imager with a GTK GUI. Supports raw (dd), EWF (E01), and AFF formats with multi-threaded hashing for high-speed acquisition. | C |
| [dc3dd](https://github.com/mdegrazia/dc3dd) | U.S. DoD Cyber Crime Center enhanced fork of `dd`. Adds on-the-fly hashing, pattern wiping, and split output — purpose-built for forensic imaging. | C |
| [dcfldd](https://github.com/resurrecting-open-source-projects/dcfldd) | Enhanced `dd` from the DoD with simultaneous hashing, wiping patterns, and progress reporting. Predecessor to dc3dd. | C |
| [AFF4 Imager](https://github.com/Velocidex/c-aff4) | Implementation of the Advanced Forensic Format 4 (AFF4) standard. Supports compressed, encrypted, and logically structured forensic images. | C++ |
| [ewftools / libewf](https://github.com/libyal/libewf) | Library and tools for working with Expert Witness Format (EWF/E01) disk images. Used for verifying, splitting, and converting forensic images. | C |
| [libewf-legacy](https://github.com/libyal/libewf-legacy) | Legacy support library for older EWF image formats used in commercial forensic tooling. | C |
| [ddrescue](https://www.gnu.org/software/ddrescue/) | GNU tool for recovering data from failing drives. Maps bad sectors and retries intelligently — essential for damaged media acquisition. | C |

---

## 3. File System & Disk Analysis

Tools for parsing, browsing, and recovering data from disk images and file systems.

| Tool | Description | Language |
|------|-------------|----------|
| [Autopsy](https://github.com/sleuthkit/autopsy) | Open-source digital forensics platform built on The Sleuth Kit. Features timeline analysis, keyword search, hash lookup, registry parsing, and an extensible plugin architecture. | Java |
| [The Sleuth Kit (TSK)](https://github.com/sleuthkit/sleuthkit) | Command-line library and tools for analyzing disk images. Supports NTFS, FAT/ExFAT, Ext2-4, HFS+, ISO 9660, and YAFFS2. Core of many forensic platforms. | C |
| [Dissect](https://github.com/fox-it/dissect) | Fox-IT's DFIR framework for rapid, programmatic access to forensic artifacts from disk and file system formats. Designed for automation at scale. | Python |
| [RecuperaBit](https://github.com/Lazza/RecuperaBit) | NTFS forensic file recovery tool. Reconstructs directory structures from partial or damaged NTFS partitions. | Python |
| [TestDisk / PhotoRec](https://github.com/cgsecurity/testdisk) | TestDisk recovers lost partitions and fixes boot records. PhotoRec carves files from damaged media supporting 480+ file formats. | C |
| [Scalpel](https://github.com/machn1k/Scalpel-2.0) | High-performance file carving tool based on file header/footer signatures. Processes raw disk images without filesystem dependency. | C |
| [bulk_extractor](https://github.com/simsong/bulk_extractor) | High-speed feature extractor that identifies email addresses, URLs, credit cards, and other structured data directly from disk images without parsing the filesystem. | C++ |
| [IPED](https://github.com/sepinf-inc/IPED) | Brazilian Federal Police digital forensic tool. Full investigation platform with indexing, timeline, hash analysis, and report generation. | Java |
| [Foremost](https://github.com/jonstewart/foremost) | File carving tool using file header/footer/data structures. Config-driven with support for dozens of file types. | C |
| [extundelete](https://github.com/mschenk/extundelete) | Recover deleted files from ext3/ext4 filesystems using journal data. | C++ |
| [ntfsundelete](https://linux.die.net/man/8/ntfsundelete) | Part of ntfs-3g suite. Recovers deleted files from NTFS volumes. | C |

---

## 4. Memory Forensics

Tools for acquiring, analyzing, and extracting artifacts from volatile memory (RAM).

| Tool | Description | Language |
|------|-------------|----------|
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | The industry-standard memory forensics framework. Analyzes Windows, Linux, and macOS memory dumps. Extracts processes, network connections, injected code, registry hives, and hundreds of other artifact types. | Python |
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Mounts a memory dump as a virtual filesystem (via Dokan/FUSE). Enables native file-based access to memory artifacts — processes, DLLs, registry, handles, and more. | C |
| [Rekall](https://github.com/google/rekall) | Google's memory analysis framework (now in maintenance mode). Strong Windows and Linux kernel analysis capabilities. Legacy but still widely referenced. | Python |
| [AVML](https://github.com/microsoft/avml) | Microsoft's portable volatile memory acquisition tool for Linux. Designed for cloud VMs and containerized environments. Outputs LiME or raw format. | Rust |
| [LiME](https://github.com/504ensicsLabs/LiME) | Linux Memory Extractor — loadable kernel module (LKM) for acquiring volatile memory from Linux and Android systems over the network or to a file. | C |
| [WinPmem](https://github.com/Velocidex/WinPmem) | Windows memory acquisition driver by Velocidex. Produces raw, crashdump, or ELF core formats compatible with Volatility. | C |
| [DumpIt](https://github.com/thimbleweed/All-In-USB) | Standalone Windows memory dumper. Zero dependencies — single executable that produces full memory images. | C |
| [volatility2](https://github.com/volatilityfoundation/volatility) | Legacy Volatility 2.x — still widely used for Windows XP/7 profiles and older image analysis. | Python |

---

## 5. Timeline Analysis & Visualization

Tools for correlating, generating, and visualizing forensic timelines from multiple artifact sources.

| Tool | Description | Language |
|------|-------------|----------|
| [Plaso](https://github.com/log2timeline/plaso) | log2timeline — extracts timestamps from 200+ artifact sources (event logs, registry, browser history, filesystem metadata) and outputs a unified JSONL/CSV supertimeline. | Python |
| [Timesketch](https://github.com/google/timesketch) | Google's collaborative forensic timeline analysis platform. Ingests Plaso output (and other sources) for multi-analyst investigation with tagging, filtering, and Sigma-based detection. | Python |
| [Highlighter](https://github.com/FireEye/highlighter) | Mandiant/FireEye log highlighting and analysis tool. Enables pattern-based visualization of text logs for rapid timeline reconstruction. | Python |
| [DFTimewolf](https://github.com/log2timeline/dftimewolf) | Orchestration framework for automating forensic collection, processing, and export workflows. Integrates with GRR, Plaso, Timesketch, and cloud APIs. | Python |
| [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) | Eric Zimmerman's GUI tool for analyzing large CSV-based timelines. Optimized for loading and filtering super-timelines from Plaso/EZ Tools output. | C# |
| [mactime](https://wiki.sleuthkit.org/index.php?title=Mactime) | Part of The Sleuth Kit. Generates MAC (Modified/Accessed/Created) time timelines from TSK bodyfile format output. | Perl |

---

## 6. Windows Artifact Parsers

Specialized tools for parsing Windows-specific forensic artifacts.

| Tool | Description | Language |
|------|-------------|----------|
| [EZ Tools (ZimmermanTools)](https://github.com/EricZimmerman/ZimmermanTools) | Eric Zimmerman's suite of 20+ Windows forensic parsers — the gold standard for Windows artifact analysis. Updater script that fetches all tools. | C# |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Fast Windows event log forensics and threat hunting tool by Yamato Security. Uses Sigma and Hayabusa-native rules. Outputs timelines in CSV/JSON. | Rust |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | WithSecure Labs tool for rapid searching and hunting through Windows event logs using Sigma rules and keyword matching. | Rust |
| [EvtxECmd](https://github.com/EricZimmerman/EvtxECmd) | EZ Tool for parsing Windows EVTX event logs into structured CSV/JSON with event map support for common Event IDs. | C# |
| [MFTECmd](https://github.com/EricZimmerman/MFTECmd) | Parses NTFS Master File Table ($MFT), $LogFile, $J (USN Journal), and $Boot. Essential for filesystem artifact analysis. | C# |
| [PECmd](https://github.com/EricZimmerman/PECmd) | Prefetch file parser. Extracts execution timestamps, run counts, and file references from Windows Prefetch artifacts. | C# |
| [LECmd](https://github.com/EricZimmerman/LECmd) | LNK (Windows Shortcut) file parser. Extracts file metadata, target machine info, and access timestamps. | C# |
| [JLECmd](https://github.com/EricZimmerman/JLECmd) | Jump List parser (both AutomaticDestinations and CustomDestinations). Reveals recently accessed files and application usage. | C# |
| [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser) | Parses the Amcache.hve registry hive — provides file execution history, PE metadata, and installation artifacts. | C# |
| [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) | Parses the ShimCache (AppCompatCache) from Windows registry — execution artifact used for lateral movement analysis. | C# |
| [ShellBagsExplorer](https://github.com/EricZimmerman/ShellBagsExplorer) | GUI explorer for Windows ShellBag artifacts. Reveals folder access history even after deletion. | C# |
| [RECmd](https://github.com/EricZimmerman/RECmd) | Command-line Windows registry hive parser with batch processing and extensible plugin support. | C# |
| [WxTCmd](https://github.com/EricZimmerman/WxTCmd) | Parses the Windows 10/11 Timeline database (ActivitiesCache.db) — reveals application usage and document access. | C# |
| [SBECmd](https://github.com/EricZimmerman/SBECmd) | ShellBag Explorer command-line version for batch processing ShellBag data. | C# |
| [RegRipper](https://github.com/keydet89/RegRipper3.0) | Plugin-based Windows registry analysis framework by Harlan Carvey. 300+ plugins for extracting forensic artifacts from registry hives. | Perl |
| [RegRippy](https://github.com/airbus-cert/regrippy) | Modern Python-based registry artifact extraction framework by Airbus CERT. Structured output and plugin architecture. | Python |
| [EventLogExpert](https://github.com/microsoft/EventLogExpert) | Microsoft open-source Windows Event Log viewer designed for forensic analysis. Supports multi-log correlation and filtering. | C# |
| [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) | SANS Blue Team PowerShell module for rapid threat hunting in Windows event logs. Detects common attack patterns across Sysmon, Security, and System logs. | PowerShell |
| [ParseUSBs](https://github.com/woanware/parseusbdevices) | Extracts USB connection artifacts from offline Windows registry hives and event logs. Parses SYSTEM, SOFTWARE, and NTUSER.dat hives. | Python |
| [Zircolite](https://github.com/wagga40/Zircolite) | Standalone SIGMA-based detection tool for EVTX/JSON event log files. No SIEM required — runs Sigma rules directly against log files. | Python |

---

## 7. Mobile Forensics

Tools for acquiring and analyzing artifacts from iOS and Android devices.

| Tool | Description | Language |
|------|-------------|----------|
| [iLEAPP](https://github.com/abrignoni/iLEAPP) | iOS Logs, Events, and Plists Parser. Parses 200+ iOS artifact categories from full filesystem or iTunes-style backups. Essential for iOS investigations. | Python |
| [ALEAPP](https://github.com/abrignoni/ALEAPP) | Android Logs, Events, and Plists Parser. Parses 150+ Android artifact categories from Android filesystem extractions. | Python |
| [Andriller](https://github.com/den4uk/andriller) | Android forensic tool for non-root extraction via ADB backup. Decodes Android databases and artifacts with an integrated report generator. | Python |
| [Apple-KnowledgeC-Parser](https://github.com/mac4n6/Apple-KnowledgeC-Parser) | Parses the Apple KnowledgeC database (knowledgeC.db) — a rich source of device usage, application activity, and location data on iOS and macOS. | Python |
| [mvt (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) | Amnesty International tool for forensic detection of spyware (including Pegasus) on iOS and Android devices. | Python |
| [UFADE](https://github.com/prosch88/UFADE) | Universal Forensic Apple Device Extractor — supports iTunes-style backup, advanced logical, and full filesystem extraction from iOS/watchOS/tvOS. | Python |
| [MEAT](https://github.com/jfarley248/MEAT) | Mandiant Extensible Android Toolkit — automated Android evidence collection via ADB without root. | Python |
| [Autopsy Mobile Forensics](https://github.com/sleuthkit/autopsy) | Autopsy includes mobile artifact parsing modules for Android and iOS filesystem extractions. | Java |
| [checkra1n](https://checkra.in/) | Jailbreak tool for iOS devices (A5-A11 chips). Enables full filesystem access for forensic extraction on supported devices. | C |
| [scrcpy](https://github.com/Genymobile/scrcpy) | Android screen mirroring and control over ADB. Useful for forensic interviews and documentation of device state. | C |

---

## 8. Network Forensics & SIEM

Tools for capturing, analyzing, and hunting in network traffic and security event data.

| Tool | Description | Language |
|------|-------------|----------|
| [Wireshark](https://github.com/wireshark/wireshark) | The world's leading network protocol analyzer. Captures and dissects 1000+ protocols. Essential for PCAP analysis, stream reconstruction, and network forensics. | C |
| [NetworkMiner](https://github.com/netresec/networkminer) | Network forensic analysis tool (NFAT) for passive network sniffing and PCAP analysis. Reconstructs files, sessions, credentials, and artifacts from captured traffic. | C# |
| [Zeek](https://github.com/zeek/zeek) | Powerful network analysis framework. Generates structured logs (conn.log, dns.log, http.log, ssl.log, etc.) from live traffic or PCAPs. Foundation for many SIEM detections. | C++/Zeek |
| [Wazuh](https://github.com/wazuh/wazuh) | Open-source SIEM, XDR, and HIDS platform. Provides agent-based log collection, file integrity monitoring, vulnerability detection, and threat response. | C/Python |
| [Arkime](https://github.com/arkime/arkime) | Large-scale, full-packet capture and indexing system (formerly Moloch). Enables PCAP storage and fast searching by IP, port, protocol, and content. | C/JS |
| [Suricata](https://github.com/OISF/suricata) | Open-source network IDS/IPS/NSM engine. Processes traffic against rules (ET, custom Sigma-derived) and outputs EVE JSON logs compatible with SIEMs. | C |
| [Snort](https://github.com/snort3/snort3) | Cisco's open-source network intrusion detection system. Rule-based detection engine — version 3 with multithreading and improved performance. | C++ |
| [Malcolm](https://github.com/cisagov/Malcolm) | CISA's network traffic analysis tool suite. Combines Arkime, Zeek, Suricata, OpenSearch, and Dashboards into an integrated platform. | Python/Docker |
| [Security Onion](https://github.com/Security-Onion-Solutions/securityonion) | Linux distribution for threat hunting, enterprise security monitoring, and log management. Integrates Zeek, Suricata, Elastic Stack, and more. | Shell |
| [ntopng](https://github.com/ntop/ntopng) | Real-time network traffic monitoring and analysis. Provides flow data, host inventory, and protocol breakdown for active network visibility. | C++ |
| [Elastic Stack (ELK)](https://github.com/elastic/elasticsearch) | Elasticsearch, Logstash, and Kibana — widely used log aggregation and SIEM backbone. Supports structured log ingestion, full-text search, and dashboard visualization. | Java/Ruby |
| [OpenSearch](https://github.com/opensearch-project/OpenSearch) | AWS-led open-source fork of Elasticsearch. Drop-in replacement with community-maintained dashboards and security plugins. | Java |
| [tshark](https://github.com/wireshark/wireshark) | Command-line Wireshark. Enables scriptable PCAP parsing, protocol filtering, and field extraction — core of many automated PCAP analysis workflows. | C |
| [tcpdump](https://github.com/the-tcpdump-group/tcpdump) | Classic command-line packet capture utility. Lightweight, scriptable, and available on virtually every Unix/Linux platform. | C |
| [ngrep](https://github.com/jpr5/ngrep) | Network-level grep. Searches live traffic or PCAPs for patterns — useful for rapid IOC hunting in packet captures. | C |
| [Brim / Zed](https://github.com/brimdata/zed) | Query engine and desktop application for PCAP and Zeek log analysis. Uses the Zed language for structured log queries. | Go |

---

## 9. Incident Response & Orchestration

Platforms for managing, tracking, and automating incident response workflows.

| Tool | Description | Language |
|------|-------------|----------|
| [TheHive](https://github.com/TheHive-Project/TheHive) | Open-source Security Incident Response Platform (SIRP). Case management, task assignment, alert triage, and MISP/Cortex integration for collaborative IR teams. | Scala |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Observable analysis and active response engine. Analyzes IPs, domains, hashes, and files using 100+ analyzers and responders. Integrates with TheHive. | Scala |
| [MISP](https://github.com/MISP/MISP) | Malware Information Sharing Platform. Structured threat intelligence sharing, IOC management, and automated indicator correlation across organizations. | PHP |
| [Shuffle](https://github.com/Shuffle/Shuffle) | Open-source SOAR (Security Orchestration, Automation, and Response) platform. No-code/low-code workflow automation with 400+ integrations. | Go |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Cyber Threat Intelligence platform for organizing and operationalizing threat data. Supports STIX2, ATT&CK mapping, and connector ecosystem. | Python |
| [DFIRTrack](https://github.com/dfirtrack/dfirtrack) | Incident response tracking system with a system-centric (vs. case-centric) approach. Tracks compromise scope across hosts, tasks, and artifact evidence. | Python |
| [Cyphon](https://github.com/cyphon/cyphon) | Alert management and incident response platform. Normalizes data from multiple sources into a unified alert queue for triage. | Python |
| [Velociraptor](https://github.com/velocidex/velociraptor) | Also serves as an IR orchestration platform — deploys VQL hunts across fleets and responds with automated collection and containment actions. | Go |
| [Kolide Fleet](https://github.com/kolide/fleet) | Open-source osquery fleet manager. Enables real-time query-based IR across large endpoint fleets using SQL-like syntax. | Go |
| [osquery](https://github.com/osquery/osquery) | Facebook/Slack endpoint visibility tool. Exposes OS state as SQL tables — process trees, open sockets, file events, users, and more. | C++ |

---

## 10. Malware Analysis & Reverse Engineering

Tools for static analysis, dynamic analysis, and behavioral investigation of malicious code.

| Tool | Description | Language |
|------|-------------|----------|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's open-source reverse engineering suite. Disassembler, decompiler, and scripting engine supporting 50+ processor architectures. Industry-leading free alternative to IDA Pro. | Java |
| [Radare2](https://github.com/radareorg/radare2) | Open-source reverse engineering framework. Disassembly, debugging, binary patching, and scripting across 50+ architectures. Foundation for Cutter GUI. | C |
| [Cutter](https://github.com/rizinorg/cutter) | Qt/C++ GUI for Rizin/Radare2. Provides an intuitive interface for disassembly, decompilation (with r2ghidra plugin), and binary analysis. | C++ |
| [YARA](https://github.com/VirusTotal/yara) | VirusTotal's rule-based malware classification engine. Create pattern-matching rules against files, memory, and network streams. Essential for threat hunting and malware triage. | C |
| [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo) | Automated malware analysis system. Executes suspicious files in a sandboxed VM and reports behavioral analysis: process activity, network connections, dropped files, and screenshots. | Python |
| [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) | Extended fork of Cuckoo with malware unpacking, configuration extraction, and YARA-based classification. Active successor to Cuckoo. | Python |
| [FLARE-FLOSS](https://github.com/mandiant/flare-floss) | Mandiant FLARE Obfuscated String Solver. Automatically extracts obfuscated strings from malware binaries without execution. | Python |
| [PE-bear](https://github.com/hasherezade/pe-bear) | Portable Executable (PE) file analysis tool with a graphical interface. Inspects headers, sections, imports, exports, and detects anomalies. | C++ |
| [Detect-It-Easy (DIE)](https://github.com/horsicq/Detect-It-Easy) | Packer/compiler/linker detection tool for PE, ELF, and Mach-O files. Essential for triaging packed or obfuscated malware. | C++ |
| [x64dbg](https://github.com/x64dbg/x64dbg) | Open-source Windows debugger for x64 and x32 assembly-level analysis. Modern replacement for OllyDbg with plugin ecosystem. | C++ |
| [pestudio](https://www.winitor.com/) | Static malware analysis tool. Inspects PE characteristics, strings, imports, and VirusTotal results in a single interface. (Freeware, not fully open source) | C# |
| [oletools](https://github.com/decalage2/oletools) | Python tools for analyzing Microsoft Office documents. Detects malicious macros, VBA code, and OLE objects — critical for phishing analysis. | Python |
| [ViperMonkey](https://github.com/decalage2/ViperMonkey) | VBA macro emulator for analyzing malicious Office documents. Statically deobfuscates and emulates macro behavior without execution. | Python |
| [pdfid / pdf-parser](https://github.com/DidierStevens/DidierStevensSuite) | Didier Stevens tools for analyzing malicious PDF files. Detects embedded JavaScript, shellcode, and exploits without execution. | Python |
| [REMnux](https://remnux.org/) | Curated Linux distribution for malware analysis. Pre-installed with 100+ analysis tools including Cuckoo, FLOSS, Wireshark, Volatility, and more. | Docker/APT |
| [MalChela](https://github.com/dbissell6/MalChela) | CLI wrapper integrating YARA, strings, hash lookups, and file analysis for rapid malware triage. | Rust |
| [yarGen](https://github.com/Neo23x0/yarGen) | Automatic YARA rule generator from malware samples. Creates rules based on unique string/byte patterns while excluding false positives. | Python |
| [Speakeasy](https://github.com/mandiant/speakeasy) | Mandiant Windows kernel and user-mode emulator for shellcode and malware analysis. Runs PE files and shellcode in a virtual environment. | Python |

---

## 11. Log Analysis & Threat Detection

Tools for processing, searching, and detecting threats in security event logs.

| Tool | Description | Language |
|------|-------------|----------|
| [Sigma](https://github.com/SigmaHQ/sigma) | Generic SIEM rule format — the "YARA for logs." Write detection rules once and convert to Splunk, Elastic, QRadar, and 30+ other SIEM formats using sigmatools. | YAML/Python |
| [HELK](https://github.com/Cyb3rWard0g/HELK) | The Hunting Elastic Stack — pre-configured ELK + Kafka + Ksql stack for threat hunting. Includes ATT&CK-mapped dashboards and Jupyter notebooks. | Docker |
| [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) | Threat hunting tool for Windows event logs using 200+ detection rules. Outputs color-coded threat reports with ATT&CK technique mapping. | Python |
| [LogonTracer](https://github.com/JPCERTCC/LogonTracer) | JPCERT/CC tool for analyzing Windows Active Directory authentication logs. Visualizes lateral movement as a graph of logon relationships. | Python |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Microsoft Sysinternals system monitor. Logs process creation, network connections, registry changes, and driver loads with configurable filtering. | C |
| [sysmon-modular](https://github.com/olafhartong/sysmon-modular) | Community-maintained, modular Sysmon configuration by Olaf Hartong. Merges individual XML files into a high-fidelity detection configuration. | XML |
| [evtx-hunter](https://github.com/NVISOsecurity/evtx-hunter) | NVISO tool for hunting through Windows event logs using a SQLite backend for fast querying and filtering. | Python |
| [Sublime Platform](https://github.com/sublime-security/sublime-platform) | Open-source email security platform with detection rule DSL for hunting threats in email logs and headers. | Go |
| [Loki](https://github.com/Neo23x0/Loki) | IOC and YARA scanner by Florian Roth. Scans filesystems, memory, and processes for known malware indicators. | Python |
| [Thor Lite](https://www.nextron-systems.com/thor-lite/) | Free version of Nextron's THOR APT scanner. YARA-based scanning with thousands of pre-built rules. | Go |
| [Zircolite](https://github.com/wagga40/Zircolite) | Standalone Sigma-based detection for EVTX, JSON, and XML event log files — no SIEM required. Produces HTML and JSON reports. | Python |

---

## 12. Cloud Forensics & IR

Tools for collecting evidence and investigating incidents in cloud environments.

| Tool | Description | Language |
|------|-------------|----------|
| [Turbinia](https://github.com/google/turbinia) | Google's open-source framework for automating and scaling forensic workloads on cloud platforms (GCP, AWS, Azure). Orchestrates Plaso, Volatility, and other tools. | Python |
| [Diffy](https://github.com/Netflix-Skunkworks/diffy) | Netflix SIRT triage tool for rapidly scoping cloud compromises. Compares EC2 instance state against a known-good baseline to identify anomalies. | Python |
| [aws_ir](https://github.com/ThreatResponse/aws_ir) | Automated AWS incident response tool. Isolates compromised instances, captures evidence, and rotates credentials in response to compromise. | Python |
| [Prowler](https://github.com/prowler-cloud/prowler) | AWS, GCP, and Azure security assessment tool with 300+ checks. Used for both proactive hardening and post-incident configuration review. | Python |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | NCC Group multi-cloud security auditing tool. Assesses misconfigurations across AWS, Azure, GCP, Alibaba Cloud, and more. | Python |
| [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) | Rules-based cloud resource management. Automates policy enforcement and generates compliance reports across AWS, Azure, and GCP. | Python |
| [GCP Chronicle](https://cloud.google.com/chronicle/docs) | Google's cloud SIEM (commercial, with open APIs). Petabyte-scale threat detection aligned to UDM. | SaaS |
| [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) | Intentionally vulnerable AWS environment for testing cloud forensics and IR tooling. | Python |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | Datadog's cloud threat simulation tool. Reproduces ATT&CK techniques in AWS/Azure/GCP to test detection coverage. | Go |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS exploitation framework for red teaming. Useful for IR practitioners to understand attacker TTPs in AWS environments. | Python |
| [cloudtrail2siem](https://github.com/alphagov/cloudtrail2siem) | Ingests AWS CloudTrail logs into Elasticsearch/OpenSearch for forensic analysis. | Python |
| [AzureHound](https://github.com/BloodHoundAD/AzureHound) | BloodHound data collector for Azure Active Directory. Maps privilege escalation paths in Azure/Entra ID — useful for cloud IR scope assessment. | Go |

---

## 13. Registry Analysis

Tools for parsing and analyzing Windows registry hives offline.

| Tool | Description | Language |
|------|-------------|----------|
| [RegRipper](https://github.com/keydet89/RegRipper3.0) | Harlan Carvey's plugin-based registry artifact extraction tool. 300+ plugins covering SAM, SOFTWARE, SYSTEM, NTUSER, SECURITY hives. | Perl |
| [RegRippy](https://github.com/airbus-cert/regrippy) | Airbus CERT Python framework for structured registry hive analysis. Plugin-based with CSV/JSON output and easy extensibility. | Python |
| [RECmd](https://github.com/EricZimmerman/RECmd) | EZ Tools command-line registry hive parser. Supports batch processing with --bn (batch mode) against multiple hives simultaneously. | C# |
| [Registry Explorer](https://ericzimmerman.github.io/#!index.md) | Eric Zimmerman's GUI registry hive browser. Interactive tree view with bookmarks, search, and built-in plugin support. | C# |
| [RegistryASCII](https://github.com/nicowillis/RegistryASCII) | Text-based visualization of registry hive structure. Useful for quick inspection without a full forensic platform. | Python |
| [python-registry](https://github.com/williballenthin/python-registry) | Pure Python library for parsing Windows registry hives. Foundation for many registry forensic tools. | Python |
| [regipy](https://github.com/mkorman90/regipy) | Python library for parsing registry hives offline. Supports hive reconstruction and plugin-based artifact extraction. | Python |
| [Offline Registry Finder](https://www.nirsoft.net/utils/offline_registry_finder.html) | NirSoft tool for searching across offline registry hives. Useful when investigating hives exported during live response. | C++ |

---

## 14. Email & Communication Forensics

Tools for analyzing email artifacts and communication data.

| Tool | Description | Language |
|------|-------------|----------|
| [libpff / pffexport](https://github.com/libyal/libpff) | Library and tools for parsing Microsoft Outlook PST/OST data files. Exports mailboxes, contacts, calendar items, and attachments. | C |
| [Aid4Mail](https://www.aid4mail.com/) | Email forensics and conversion tool supporting 30+ email formats. (Freeware for basic use) | C++ |
| [mbox-tools](https://github.com/google/mbox) | Tools for working with MBOX format email archives. | Python |
| [Thunderbird Forensics](https://github.com/nicowillis/thunderbird-forensics) | Scripts for extracting forensic artifacts from Mozilla Thunderbird email client profiles. | Python |
| [Email Header Analyzer](https://github.com/andrewnez/emailhdranalysis) | Parses SMTP email headers to reconstruct routing paths, timestamps, and identify spoofing artifacts. | Python |
| [oletools](https://github.com/decalage2/oletools) | Analyzes OLE/Office documents attached to phishing emails. Extracts VBA macros, embedded objects, and URLs. | Python |
| [PhishTool](https://www.phishtool.com/) | Phishing email analysis platform. Automated header parsing, URL analysis, and attachment sandbox integration. (Free community tier) | SaaS |

---

## 15. Threat Intelligence Platforms

Tools for aggregating, managing, and operationalizing threat intelligence.

| Tool | Description | Language |
|------|-------------|----------|
| [MISP](https://github.com/MISP/MISP) | Malware Information Sharing Platform & Threat Sharing. The standard for structured CTI sharing. Supports STIX, OpenIOC, and custom taxonomies across trusted communities. | PHP |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Filigran's cyber threat intelligence platform. STIX2 native, ATT&CK-aligned, with graph visualization and connector ecosystem for automated intel enrichment. | Python |
| [IntelOwl](https://github.com/intelowlproject/IntelOwl) | Open-source threat intelligence orchestration platform. Analyzes observables (hashes, IPs, domains, URLs) across 100+ analyzers in a single API call. | Python |
| [Cortex](https://github.com/TheHive-Project/Cortex) | TheHive's observable analysis engine. Connects analyzers (VirusTotal, Shodan, AbuseIPDB, etc.) and responders for automated enrichment. | Scala |
| [TAXII / STIX tools](https://github.com/oasis-open/cti-taxii-server) | OASIS reference implementations for STIX 2.x objects and TAXII 2.x transport protocol. | Python |
| [Yeti](https://github.com/yeti-platform/yeti) | Platform for organizing and enriching threat intelligence. Tracks observables, TTPs, actors, and campaigns in a graph database. | Python |
| [OpenPhish](https://openphish.com/) | Automated phishing intelligence feed. Integrates into TIP workflows for URL-based threat correlation. | SaaS |

---

## 16. OSINT & Reconnaissance

Tools for open-source intelligence gathering to support investigations and threat attribution.

| Tool | Description | Language |
|------|-------------|----------|
| [Maltego](https://www.maltego.com/) | Visual link analysis and OSINT platform. Transforms data entities (IPs, domains, emails, persons) into relationship graphs. Community edition is free. | Java |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Automated OSINT collection across 200+ data sources. Maps attack surface, enumerates assets, and correlates intelligence. | Python |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT tool for gathering emails, subdomains, IPs, and employee names from public sources (Google, LinkedIn, Shodan, etc.). | Python |
| [Shodan](https://www.shodan.io/) | Search engine for Internet-connected devices. Essential for identifying exposed infrastructure and mapping attack surface. (Free API tier available) | SaaS |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | Full-featured OSINT reconnaissance framework with a Metasploit-style module interface and 60+ data collection modules. | Python |
| [Photon](https://github.com/s0md3v/Photon) | Fast OSINT web crawler. Extracts URLs, emails, social media accounts, files, and JavaScript endpoints from target domains. | Python |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username enumeration tool. Searches 300+ social networks for accounts matching a target username. | Python |
| [holehe](https://github.com/megadose/holehe) | Checks if an email address is registered on 120+ websites without sending emails. Useful for account enumeration and identity attribution. | Python |
| [OSINT Framework](https://osintframework.com/) | Web-based directory of OSINT tools organized by category. Reference for investigators building collection workflows. | HTML |
| [exiftool](https://github.com/exiftool/exiftool) | Metadata extraction tool supporting 100+ file formats. Extracts GPS coordinates, device identifiers, authorship, and timestamps from files. | Perl |
| [unfurl](https://github.com/obsidianforensics/unfurl) | URL analysis tool. Decodes and visualizes encoding layers in complex URLs — useful for tracking parameters and campaign attribution. | Python |

---

## 17. Forensic Distributions & Workstations

Pre-built Linux distributions and frameworks bundling DFIR toolsets.

| Tool | Description |
|------|-------------|
| [SIFT Workstation](https://github.com/teamdfir/sift) | SANS Institute's forensic workstation. Built on Ubuntu, includes Volatility, Plaso, The Sleuth Kit, Autopsy, RegRipper, and 50+ tools. Industry-standard training environment. |
| [REMnux](https://remnux.org/) | Linux toolkit for malware analysis. Pre-configured with Cuckoo, FLOSS, Wireshark, Volatility, Ghidra, and 100+ analysis tools. Community-maintained. |
| [CAINE (Computer Aided INvestigative Environment)](https://www.caine-live.net/) | Italian forensics distribution. Bootable live environment with write-blocking, evidence preservation tools, and GUI forensic applications. |
| [Tsurugi Linux](https://tsurugi-linux.org/) | Italian DFIR distribution with extensive OSINT, memory forensics, and disk analysis tooling. Supports both live and installed modes. |
| [Kali Linux](https://github.com/kalilinux) | Offensive security distribution with significant forensics tooling including Volatility, Wireshark, Autopsy, and bulk_extractor. |
| [Paladin](https://sumuri.com/software/paladin/) | SUMURI's forensic-focused Ubuntu derivative. Bootable triage tool with a curated toolset and PALADIN Toolbox GUI. |
| [DEFT Linux (Digital Evidence & Forensic Toolkit)](http://www.deftlinux.net/) | Italian DFIR-focused distribution optimized for live forensics, OSINT, and network analysis. |
| [BUSCADOR](https://inteltechniques.com/buscador/) | Michael Bazzell's OSINT-focused VM. Pre-installed with Maltego, SpiderFoot, theHarvester, and 100+ OSINT tools. |

---

## 18. Reporting & Case Management

Tools for documenting investigations, tracking case progress, and generating forensic reports.

| Tool | Description | Language |
|------|-------------|----------|
| [DFIRTrack](https://github.com/dfirtrack/dfirtrack) | System-centric incident response tracking platform. Tracks compromise scope per host, maps evidence to artifacts, and generates case documentation. | Python |
| [Dradis CE](https://github.com/dradis/dradis-ce) | Collaboration and reporting framework for security assessments. Supports custom report templates and evidence management. | Ruby |
| [Faraday](https://github.com/infobyte/faraday) | Collaborative penetration testing and vulnerability management platform. Useful for tracking IR findings and evidence chains. | Python |
| [Autopsy](https://github.com/sleuthkit/autopsy) | Includes built-in HTML/Excel report generation from investigation findings, tagged artifacts, and keyword search results. | Java |
| [Plaso + Timesketch](https://github.com/google/timesketch) | Timesketch includes export and report generation from annotated timeline analysis results. | Python |
| [TheHive](https://github.com/TheHive-Project/TheHive) | Case management with built-in report templates, timeline views, and MITRE ATT&CK tagging for post-incident documentation. | Scala |

---

## 19. macOS Forensics

Tools for collecting and analyzing forensic artifacts from macOS systems — an underserved category in most IR toolkits.

| Tool | Description | Language |
|------|-------------|----------|
| [mac_apt](https://github.com/ydkhatri/mac_apt) | macOS (& iOS) Artifact Parsing Tool by Yogesh Khatri. Plugin-based framework that processes full disk images or live macs, extracting Safari history, network interfaces, recently accessed files, plist data, and 60+ artifact types. | Python |
| [OSXCollector](https://github.com/Yelp/osxcollector) | Yelp's forensic evidence collection and analysis toolkit for macOS. Collects system info, browser history, accounts, processes, and packages — outputs normalized JSON for downstream analysis. | Python |
| [Aftermath](https://github.com/jamf/aftermath) | Jamf's open-source macOS post-compromise forensics tool. Collects volatile and non-volatile system state for rapid incident scoping — focused on speed and low footprint. | Swift |
| [APOLLO](https://github.com/mac4n6/APOLLO) | Apple Pattern of Life Lazy Output'er by Sarah Edwards (mac4n6). Queries the KnowledgeC, PowerLog, and other Apple databases to reconstruct user activity timelines on macOS and iOS. | Python |
| [MacRipper](https://github.com/Recruit-CSIRT/MacRipper) | Recruit-CSIRT's macOS artifact parsing tool. Extracts and structures key forensic artifacts from offline macOS images. | Python |
| [osxcollector-output-filters](https://github.com/Yelp/osxcollector) | Post-processing filters for OSXCollector output. Enriches results with VirusTotal, OpenDNS, and other threat intel sources for rapid triage. | Python |
| [mac_robber](https://github.com/sleuthkit/mac_robber) | Part of The Sleuth Kit. Collects MAC (Modified/Accessed/Changed) time data from live macOS filesystems for timeline generation. | C |
| [macOS-Artifact-Parsing](https://github.com/mac4n6/APOLLO) | Collection of scripts from the mac4n6 project for parsing Apple-specific plist, database, and log artifact formats. | Python |

---

## 20. Browser & Internet Artifact Forensics

Tools for recovering and analyzing web browsing history, cache, cookies, and internet artifacts across all major browsers.

| Tool | Description | Language |
|------|-------------|----------|
| [hindsight](https://github.com/obsidianforensics/hindsight) | Chrome/Chromium history forensics tool by Obsidian Forensics. Parses URLs, downloads, cache records, bookmarks, autofill, saved passwords, extensions, cookies, and Local Storage from Chrome profiles — outputs CSV, SQLite, or XLSX. | Python |
| [dumpzilla](https://github.com/Busindre/dumpzilla) | Firefox forensics tool. Extracts history, downloads, bookmarks, cookies, form data, saved passwords, add-ons, and cache from Firefox/Thunderbird profiles. | Python |
| [BrowserHistory](https://github.com/browser-history/browser-history) | Cross-browser Python library and CLI for extracting unified history from Chrome, Firefox, Safari, Edge, Opera, and Brave — outputs JSON/CSV. | Python |
| [unfurl](https://github.com/obsidianforensics/unfurl) | URL forensics tool that decodes and visualizes encoding layers, timestamps, and tracking parameters embedded in complex URLs — useful for campaign attribution and URL artifact triage. | Python |
| [ChromeCache](https://github.com/nicowillis/chromecache) | Extracts and decodes Google Chrome's network cache files. Recovers cached web pages, scripts, and images from Chrome cache directories. | Python |
| [firefoxforensics](https://github.com/libyal/dtformats/blob/main/documentation/Mozilla%20Firefox%20Places.asciidoc) | Documentation and format specifications for parsing Mozilla Firefox Places (places.sqlite) — core browser history database. | Docs |
| [bstrings](https://github.com/EricZimmerman/bstrings) | EZ Tools string extraction utility. Useful for pulling URLs, email addresses, and other artifacts from browser database blobs and cache files. | C# |

---

## 21. Docker & Container Forensics

Tools for investigating incidents involving containerized environments and Docker host systems.

| Tool | Description | Language |
|------|-------------|----------|
| [dof (Docker Forensics Toolkit)](https://github.com/docker-forensics-toolkit/toolkit) | Extracts and interprets forensic artifacts from disk images of Docker Host systems. Parses container metadata, image layers, volumes, and network configuration. | Python |
| [docker-explorer](https://github.com/google/docker-explorer) | Google's tool for offline forensic analysis of Docker filesystems. Mounts and traverses container overlay filesystems to recover files and metadata without a running Docker daemon. | Python |
| [whaler](https://github.com/P3GLEG/Whaler) | Reverse-engineers Docker images back to approximate Dockerfiles. Useful for identifying malicious images and understanding container build history. | Go |
| [dive](https://github.com/wagoodman/dive) | Tool for exploring Docker image layers. Identifies what changed between layers — useful for detecting malicious layer injections or data exfiltration staged in image layers. | Go |
| [Trivy](https://github.com/aquasecurity/trivy) | Aqua Security's container vulnerability and misconfiguration scanner. Scans container images, filesystems, and Kubernetes clusters for CVEs, secrets, and SBOM data during IR. | Go |
| [Falco](https://github.com/falcosecurity/falco) | CNCF runtime security tool for containers and Kubernetes. Detects anomalous behavior (unexpected processes, file access, network activity) in real time using eBPF/kernel module sensors. | C++ |

---

## 22. Steganography & Image Forensics

Tools for detecting hidden data in files and performing forensic analysis of digital images.

| Tool | Description | Language |
|------|-------------|----------|
| [StegoVeritas](https://github.com/bannsec/stegoVeritas) | Automated steganography analysis tool. Runs a battery of stego detection techniques against images — LSB extraction, metadata analysis, color channel manipulation, and more. | Python |
| [zsteg](https://github.com/zed-0xff/zsteg) | Detects LSB (Least Significant Bit) steganography in PNG and BMP files. Supports multiple bit planes and channel combinations — standard tool for CTF and investigation. | Ruby |
| [steghide](https://github.com/StefanoDeVuono/steghide) | Embeds and extracts hidden data in JPEG, BMP, WAV, and AU files. Commonly used by threat actors — relevant for detecting covert exfiltration channels. | C++ |
| [stegsolve](https://github.com/zardus/ctf-tools/tree/master/stegsolve) | Java-based image steganography tool. Applies bitplane and color channel filters to reveal hidden content. Widely used in CTF and image forensics workflows. | Java |
| [Ghiro](https://github.com/Ghirensics/ghiro) | Automated digital image forensics platform. Analyzes images for metadata, GPS coordinates, EXIF anomalies, hash lookups, error level analysis (ELA), and steganographic content via a web UI. | Python |
| [sherloq](https://github.com/GuidoBartoli/sherloq) | Open-source digital photographic image forensic toolset. Covers metadata analysis, compression artifacts, noise analysis, cloning detection, and ELA — designed for image authenticity investigations. | Python/C++ |
| [exiftool](https://github.com/exiftool/exiftool) | Comprehensive metadata extraction tool supporting 100+ file formats. Extracts GPS, device identifiers, authorship, timestamps, and embedded data from photos, documents, and media files. | Perl |
| [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit) | Docker image bundling 20+ steganography tools (steghide, outguess, jsteg, zsteg, etc.) for analysis and extraction — popular CTF and forensics environment. | Docker |
| [outguess](https://github.com/crorvick/outguess) | Universal steganographic tool that hides data in JPEG images while preserving statistical properties to resist detection. | C |

---

## 23. Password Recovery & Decryption

Tools for recovering passwords and decrypting artifacts commonly encountered during DFIR investigations.

| Tool | Description | Language |
|------|-------------|----------|
| [hashcat](https://github.com/hashcat/hashcat) | World's fastest GPU-accelerated password recovery tool. Supports 300+ hash types including NTLM, Kerberos, bcrypt, and disk encryption keys (LUKS, VeraCrypt, BitLocker). Essential for credential triage. | C |
| [John the Ripper](https://github.com/openwall/john) | Classic open-source password cracker. CPU-optimized with support for 100+ hash formats. Jumbo community edition adds ZIP, RAR, PDF, Office, and disk image password cracking. | C |
| [CyberChef](https://github.com/gchq/CyberChef) | GCHQ's "Cyber Swiss Army Knife." 300+ operations for encoding, decoding, encryption, compression, hashing, and data transformation — essential for decoding obfuscated artifacts without writing code. | JavaScript |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Credential recovery tool for Windows, Linux, and macOS. Extracts stored passwords from browsers, email clients, databases, Git, WiFi, and 80+ applications — mirrors attacker credential harvesting. | Python |
| [mimikatz](https://github.com/gentilkiwi/mimikatz) | Windows credential extraction tool. Dumps LSASS memory for plaintext passwords, NTLM hashes, and Kerberos tickets. Core to understanding credential-based lateral movement during IR. | C |
| [impacket](https://github.com/fortra/impacket) | Fortra's Python library for working with Windows network protocols. Includes secretsdump.py for remote/offline SAM and NTDS.dit extraction — critical for AD compromise investigations. | Python |
| [VeraCrypt](https://github.com/veracrypt/VeraCrypt) | Open-source disk encryption. Relevant for DFIR practitioners encountering encrypted volumes — supports mounting with recovered keys/passwords for forensic access. | C/C++ |
| [bitlocker-decryptor](https://github.com/libyal/libbde) | libyal's BitLocker Drive Encryption library. Enables mounting and decrypting BitLocker volumes using recovery keys, passwords, or BEK files during forensic analysis. | C |

---

## 24. Scripting Frameworks & Lightweight IR

Modular scripting frameworks and lightweight scanners for rapid, low-dependency IR at scale.

| Tool | Description | Language |
|------|-------------|----------|
| [Kansa](https://github.com/davehull/Kansa) | Dave Hull's modular PowerShell incident response framework. Collects and analyzes data across Windows environments — process trees, autoruns, network connections, and event log parsing at fleet scale. | PowerShell |
| [rastrea2r](https://github.com/rastrea2r/rastrea2r) | Cross-platform YARA-based IOC scanner for disks and memory. Runs on Windows, Linux, and macOS — supports scanning remote systems via REST API for distributed IR. | Python |
| [Fenrir](https://github.com/Neo23x0/Fenrir) | Florian Roth's simple bash IOC scanner for Linux/macOS/Unix. No dependencies — scans for file hashes, strings, and filename patterns from a plain-text IOC list. | Bash |
| [CHIRP](https://github.com/cisagov/CHIRP) | CISA's IOC Detection Tool. Built in response to SolarWinds/SUNBURST to scan Windows systems for attacker TTPs across registry, filesystem, event logs, and WMI subscriptions. | Python |
| [CIRTkit](https://github.com/opensourcesec/CIRTKit) | Framework for unifying Incident Response and forensics investigation workflows. Provides a modular, extensible base for building organization-specific IR automation. | Python |
| [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) | Extracts common Windows forensic artifacts from source images and VSCs (Volume Shadow Copies) in a structured, automated manner. | Python |
| [Loki](https://github.com/Neo23x0/Loki) | IOC and YARA scanner by Florian Roth. Scans filesystems, processes, and memory dumps for known malware indicators, suspicious file names, and hacker tools across Windows, Linux, and macOS. | Python |
| [IRIS-web](https://github.com/dfir-iris/iris-web) | DFIR-IRIS collaborative investigation platform. Provides case management, timeline reconstruction, IOC tracking, and evidence management — designed for multi-analyst IR engagements. | Python |
| [Kuiper](https://github.com/DFIRKuiper/Kuiper) | DFIR investigation platform with built-in timeline analysis, case management, and artifact parsing across collected evidence. Complements TheHive for large-scale investigations. | Python |
| [FLARE VM](https://github.com/mandiant/flare-vm) | Mandiant's Windows-based malware analysis and reverse engineering distribution. Complements REMnux — installs 70+ tools (x64dbg, Ghidra, FLOSS, PE-bear, Wireshark) on a Windows VM via Chocolatey. | PowerShell |

---

## Contributing

Pull requests are welcome. When adding a tool, please include:

- Tool name with GitHub/official link
- One-line description covering what it does and why it matters
- Primary language/platform
- Correct category placement

## Disclaimer

Tools in this repository are intended for **lawful forensic investigations, incident response, threat research, and academic study**. Always obtain proper authorization before deploying collection or analysis tools in production environments. Compliance with applicable laws (CFAA, GDPR, state regulations) is the responsibility of the practitioner.

---

*Maintained by [Bryan Ambrose](https://github.com/bryan-ambrose) | Cybersecurity | Security Engineer II, AWS | GCFA · GCFR · OSCP*

*Last updated: April 2026 | v2.0 — expanded to 24 categories*
