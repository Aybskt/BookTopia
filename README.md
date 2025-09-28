
---

# 🚀 Cybersecurity Fundamentals: Revision Sheet

This document summarizes the fundamental concepts of cybersecurity. It's an essential foundation for understanding the risks and defense mechanisms of the digital world.

---

## 🛡️ The Pillars of Information Security (The CIA Triad +1)

Information security (IS) is based on four fundamental pillars that ensure data protection.

* **Confidentiality**: Ensuring that only authorized individuals can access information.
    * *Methods*: Encryption, access control lists (ACLs), strong authentication.

* **Integrity**: Guaranteeing that information is accurate, complete, and has not been altered in an unauthorized manner.
    * *Methods*: Hashing (e.g., `SHA-256`), digital signatures.

* **Availability**: Ensuring that information and services are accessible to legitimate users when they need them.
    * *Methods*: Redundancy (server clusters, RAID), Anti-DDoS protection.

* **Proof (Non-repudiation)**: Making it possible to prove the identity of the person who performed an action, preventing them from denying it.
    * *Context*: Essential for online contracts, financial transactions, and compliance (GDPR).

---

## 🧪 The Risk Formula

To assess and prioritize a cybersecurity threat, a simple formula is used to break down risk into three factors.

> **Risk = Threat × Vulnerability × Impact**

* **Threat**: The potential source of danger. Who or what can attack?
    * *Examples*: A hacker group, malware, a disgruntled employee, a natural disaster.

* **Vulnerability**: The weakness that could be exploited by the threat.
    * *Examples*: A weak password, un-updated software, a lack of a firewall.

* **Impact**: The negative consequences if the vulnerability is exploited.
    * *Examples*: Theft of customer data, financial loss, production shutdown, damage to reputation.

---

## 💥 Common Threats and Attacks

It's crucial to be able to identify the most common cyberattacks to better protect against them.

### Ransomware
Malicious software that **encrypts the files** of a user or a company and demands a ransom payment in exchange for the decryption key.
* **Famous Example**: `WannaCry`, which exploited the `EternalBlue` vulnerability to spread massively in 2017.

### Phishing 🎣
A social engineering technique aimed at **deceiving a user** via a fraudulent email, SMS, or message. The goal is to trick them into revealing sensitive information (usernames, passwords, credit card numbers) by impersonating a trusted source (bank, government, online service).

### Classic Web Attacks
* **SQL Injection**: Consists of inserting malicious SQL code into a query via a web form to manipulate the site's database (read confidential data, modify or delete information).
* **XSS (Cross-Site Scripting)**: Involves injecting a malicious script (often JavaScript) into a web page viewed by other users. This script then runs in their browser and can steal their session cookies or redirect them to a fraudulent site.
* **CSRF (Cross-Site Request Forgery)**: Forces an authenticated user's browser to perform an unwanted action on a web application. For example, making a bank transfer or changing a password without the user's knowledge.

---

## 👨‍💻 Key Actors and Tools

The cybersecurity ecosystem relies on well-defined roles, technologies, and standards.

* **SOC (Security Operations Center) Analyst**: The "guardian of the temple." This professional monitors event logs and security alerts in real-time to detect, analyze, and respond to security incidents.

* **SIEM (Security Information and Event Management)**: The "control tower" of the SOC. It's a software platform that **centralizes, correlates, and analyzes logs** from all sources in the information system (servers, firewalls, applications) to identify suspicious activities or potential threats.

* **Vulnerability Scan**: An automated process that inspects a network, server, or application to **search for known security flaws** (CVEs). It's an essential proactive audit to fix weaknesses before they are exploited.

* **ISO 27001 Standard**: An international certification that establishes the requirements for an **Information Security Management System (ISMS)**. Obtaining this certification proves that an organization has implemented a structured and effective approach to managing information security risks.
