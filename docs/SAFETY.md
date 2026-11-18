# Safety Guide

This tool performs **static analysis**: it reads a file's bytes and never runs the file. That is much safer than executing a sample, but good habits still matter.

## 1. Start with a harmless executable

Practice on something known and safe, such as `notepad.exe` or `calc.exe` on Windows, or a program you compiled yourself. Learn what normal output looks like first.

## 2. Use an isolated, disposable VM for malware

If you handle real malware samples:

- Work only inside a virtual machine dedicated to analysis.
- Keep it disposable, so you can delete it if something goes wrong.
- Use host-only or no networking unless your analysis requires otherwise.

## 3. Take a VM snapshot

Snapshot the clean VM before you copy a sample in. Revert to it when you finish.

## 4. Disable shared folders and clipboard integration

Shared folders and a shared clipboard can create a path between a sample and your host system. Turn them off for the analysis VM.

## 5. Never execute the sample

Do not double-click it, run it from a terminal, or "just test it quickly". This analyzer only reads the file. Keep samples non-executable where possible (for example, store them in password-protected archives and extract them only in the VM).

## 6. Do not commit malware samples to GitHub

Never add samples, extracted payloads, or sample archives to your repository. The `.gitignore` in this project excludes common executable and archive types, but always check `git status` before committing.

## 7. Only analyze files you are authorized to examine

Analyze files you own, files you have permission to examine, or samples from legitimate research sources. Respect the law and the policies of your organization.

Back to the [README](../README.md).
