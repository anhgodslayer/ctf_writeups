<div align="center">

# Cybersecurity Research & CTF Writeups

### Penetration Testing · Binary Exploitation · Active Directory · Web Security

**A practical portfolio of security labs, capture-the-flag challenges, and documented exploitation techniques.**

[![GitHub Profile](https://img.shields.io/badge/GitHub-anhgodslayer-181717?logo=github)](https://github.com/anhgodslayer)
[![Hack The Box](https://img.shields.io/badge/Hack%20The%20Box-Writeups-9FEF00?logo=hackthebox&logoColor=black)](./HTB/)
[![Markdown](https://img.shields.io/badge/Documentation-Markdown-000000?logo=markdown)](./)

</div>

---

## About This Repository

Welcome! This repository documents my hands-on cybersecurity learning through **Capture the Flag (CTF)** challenges, **Hack The Box (HTB)** machines, and **binary exploitation** exercises.

My goal is to turn each lab into a reproducible technical writeup: documenting the attack surface, explaining the reasoning behind each step, and capturing lessons that transfer to real-world security assessments.

> **Focus:** Methodology over shortcuts — understand *why* an exploit works, not just which command to run.

## Explore the Portfolio

| Area | What you'll find | Browse |
| --- | --- | --- |
| **Hack The Box** | Machine writeups covering enumeration, initial access, privilege escalation, and post-exploitation | [HTB/](./HTB/) |
| **CTF Challenges** | Challenge notes and solutions across security topics | [CTF/](./CTF/) |
| **PWN101** | Binary exploitation practice and vulnerability analysis | [PWN101/](./PWN101/) |

> Folder links assume these directories are present on the default branch. If your HTB folder has not been pushed yet, that link will work once it is added.

## Technical Focus

| Discipline | Topics explored |
| --- | --- |
| **Network & Service Enumeration** | Port scanning, service fingerprinting, attack-surface mapping |
| **Web Application Security** | Web enumeration, authentication weaknesses, injection concepts |
| **Linux & Windows Security** | Local enumeration, misconfigurations, privilege escalation |
| **Active Directory** | Domain enumeration, authentication, lateral-movement concepts |
| **Binary Exploitation** | Memory corruption, debugging, exploit development fundamentals |
| **Security Reporting** | Evidence collection, step-by-step writeups, remediation-minded analysis |

These are areas of study and lab practice, not claims of professional certification or production assessment experience.

## Tools & Workflow

Tools commonly used in these learning areas include **Nmap**, **Burp Suite**, **Gobuster/ffuf**, **Wireshark**, **GDB**, **Python**, and standard Linux command-line utilities. Individual writeups document the tools actually used for each exercise.

A typical machine writeup follows:

```text
Reconnaissance → Enumeration → Vulnerability Analysis
       → Initial Access → Privilege Escalation → Lessons Learned
```

## Selected Hack The Box Writeups

Browse the collection by difficulty:

- **Easy:** [Active](./HTB/Easy/Active%20%5BEasy%5D.md) · [Forest](./HTB/Easy/Forest%20%5BEasy%5D.md) · [Sauna](./HTB/Easy/Sauna%20%5BEasy%5D.md)
- **Medium:** [Monteverde](./HTB/Medium/Monteverde%20%5BMedium%5D.md) · [Administrator](./HTB/Medium/Administrator%20%5BMedium%5D.md) · [Escape](./HTB/Medium/Escape%20%5BMedium%5D.md)
- **Hard:** [Blackfield](./HTB/Hard/Blackfield%20%5BHard%5D.md) · [Flight](./HTB/Hard/Flight%20%5BHard%5D.md)

*These links follow the machine filenames in my local HTB notes tree. They will resolve after those files are uploaded under `HTB/`.*

## Documentation Principles

- **Reproducibility:** Commands, relevant outputs, and supporting evidence where appropriate.
- **Clear reasoning:** Explain the vulnerability and how each finding informed the next step.
- **Responsible disclosure:** Share only content permitted by the relevant lab or challenge platform.
- **Continuous improvement:** Revise notes as techniques and understanding develop.

## Responsible Use

All techniques documented here are intended for **authorized labs, CTF environments, and educational security research**. Do not use them against systems without explicit permission. Credentials, flags, and sensitive information should be redacted where required; platform rules take precedence over publication.

## Connect

**GitHub:** [@anhgodslayer](https://github.com/anhgodslayer)

I use this repository as an evolving record of practical learning and technical problem-solving in cybersecurity.

---

<div align="center">
<sub>Built through practice, documented for clarity.</sub>
</div>
