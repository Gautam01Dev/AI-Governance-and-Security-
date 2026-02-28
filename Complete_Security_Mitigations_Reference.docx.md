

**COMPLETE SECURITY**

**MITIGATIONS REFERENCE**

  **All Types  |  Detailed Impact Analysis  |  Implementation Guidance**


*Covering: Preventive  |  Detective  |  Corrective  |  Compensating  |  Deterrent  |  Recovery  |  Directive*

Application Security  |  Cloud Security  |  API Security  |  Identity  |  Network  |  AI/LLM  |  Data  |  Supply Chain

| PART | DOMAIN | MITIGATION TYPES COVERED |
| :---- | :---- | :---- |
| Part 1 | Core Mitigation Taxonomy | 7 types with definitions, mechanisms & impact ratings |
| Part 2 | Authentication & Identity | MFA, OAuth, RBAC, PAM, SSO, Zero Trust |
| Part 3 | Application Security | Input validation, CSRF, XSS, SQLi, SSRF, headers |
| Part 4 | API Security | Rate limiting, BOLA, JWT, versioning, schema validation |
| Part 5 | Cloud Security | IAM, network, storage, workload, CSPM, supply chain |
| Part 6 | Data Protection | Encryption, masking, DLP, key management, backups |
| Part 7 | Network Security | Segmentation, TLS, WAF, DDoS, firewall, DNS |
| Part 8 | AI & LLM Security | Prompt injection, RAG, output validation, agent controls |
| Part 9 | Operational & Process | SIEM, patching, SecSDLC, IR, threat intel, awareness |
| Part 10 | Mitigation Selection Guide | When to use what, layering strategy, impact matrix |

# **PART 1 — CORE MITIGATION TAXONOMY**

Security mitigations are organized into 7 functional types. Every control you implement falls into one or more of these categories. Understanding the type helps you build layered defense: no single type is sufficient on its own.

| Type | Definition | Timing | Security Goal | Impact If Absent |
| :---- | :---- | :---- | :---- | :---- |
| Preventive | Stops an attack before it can succeed. The most valuable type — eliminates the threat entirely. | Before attack | Reduce likelihood to near zero | Attack succeeds on first attempt with no friction |
| Detective | Identifies that an attack is occurring or has occurred. Cannot stop it but enables response. | During/after attack | Reduce time-to-detect (MTTD) | Breaches go unnoticed for weeks/months — dwell time explodes |
| Corrective | Restores a system to a known-good state after a compromise or failure. | After attack | Reduce time-to-recover (MTTR) | Long downtime; data loss; no recovery path from breach |
| Compensating | An alternative control used when the primary control cannot be implemented. Accepts higher residual risk. | Before attack | Reduce likelihood via alternative means | Unmitigated risk if no primary control exists and no compensating control defined |
| Deterrent | Discourages attackers by increasing perceived cost or risk of attacking. Psychological/legal effect. | Before attack | Reduce attacker motivation | Low-sophistication attackers proceed freely; harder to prosecute |
| Recovery | Restores business operations and data after an incident. Broader than corrective — covers full business continuity. | After attack | Minimize business impact duration | Catastrophic operational failure; data permanently lost; business continuity failure |
| Directive | Policies, standards, procedures, and training that guide human behavior. Foundation for all technical controls. | Before attack | Reduce human error and insider risk | Technical controls undermined by untrained users; no legal basis for enforcement |

## **Defense-in-Depth: Why All 7 Types Are Required**

No single mitigation type is sufficient. A system protected only by preventive controls has no way to detect novel attacks that bypass them. A system with only detective controls will see attacks but cannot stop them. The professional standard is layering:

| Layer | Primary Type | Example | What Happens If This Layer Fails |
| :---- | :---- | :---- | :---- |
| Outer | Deterrent | Legal notice, login warning banners, visible security posture | Attacker proceeds — next layer activates |
| Entry | Preventive | MFA, WAF, input validation, strong authentication | Attack enters the system — detection activates |
| Detection | Detective | SIEM, IDS/IPS, anomaly detection, audit logs | Attack is invisible — dwell time maximized, damage scope unknown |
| Containment | Preventive (secondary) | Network segmentation, least privilege, microsegmentation | Lateral movement possible — full environment compromise |
| Response | Corrective | Incident response playbooks, automated remediation, isolation | Recovery delayed — damage scope increases |
| Recovery | Recovery | Backups, DR site, BCP, data restoration procedures | Business permanently impacted; data loss permanent |
| Foundation | Directive | Security policies, training, awareness, standards | All other layers weakened by human error and non-compliance |

# **PART 2 — AUTHENTICATION & IDENTITY MITIGATIONS**

## **1\. Multi-Factor Authentication (MFA)**

**\[CRITICAL IMPACT\]** MFA alone prevents 99.9% of automated account takeover attacks (Microsoft data). It is the highest ROI single control in identity security.

MFA requires a user to prove identity using two or more factors from different categories: something you know (password), something you have (hardware token, authenticator app), or something you are (biometric).

| MFA Type | Security Strength | Phishing Resistant? | Best For | Weaknesses |
| :---- | :---- | :---- | :---- | :---- |
| SMS OTP | Low-Medium | No | Legacy systems only; broad user base | SS7 interception, SIM swap, real-time phishing relay |
| TOTP App (Authy, Google Auth) | Medium | Partially | Most web applications | Real-time phishing can relay the TOTP before expiry |
| Push Notification (Duo, Okta Verify) | Medium-High | Partially | Enterprise SSO, VPN | MFA fatigue attacks — attacker spams push until user approves |
| Hardware Token (YubiKey FIDO2) | Very High | Yes | Admin accounts, privileged users, high-risk systems | Cost, device loss risk; requires modern browser support |
| Passkeys (FIDO2/WebAuthn) | Very High | Yes | Consumer apps, modern enterprise | Not universally supported; recovery if device lost needs planning |

**Impact of Implementing MFA:**

* Eliminates credential stuffing attacks — stolen username/password combos become useless

* Eliminates brute force and password spray attacks as primary attack vectors

* Forces attacker to social engineer the second factor — dramatically higher attacker cost

* Required for most compliance frameworks: PCI-DSS, SOC 2, ISO 27001, HIPAA

## **2\. Role-Based Access Control (RBAC) & Least Privilege**

**\[HIGH IMPACT\]** Over-privileged accounts are involved in the majority of data breaches. Least privilege limits the blast radius of any compromised credential to the minimum possible.

| Principle | What It Means | Implementation | Business Impact |
| :---- | :---- | :---- | :---- |
| Least Privilege | Every user/service has only the minimum permissions needed to perform their function — nothing more | Granular roles; no wildcard permissions; time-bound elevated access | Breach limited to compromised account's scope; reduces insider threat impact |
| Need-to-Know | Access to data is granted only when there is a legitimate business need, not by default | Attribute-based access control; data classification \+ role matching | PII/sensitive data exposure drastically reduced even in authenticated breach |
| Separation of Duties | No single person can complete a sensitive operation alone (e.g., approve \+ execute a payment) | 4-eyes principle; dual authorization for critical actions | Fraud prevention; insider threat deterrence; compliance requirement |
| Just-in-Time (JIT) Access | Privileged access is granted temporarily on request, automatically revoked after session | PAM tools: CyberArk, BeyondTrust, HashiCorp Vault | Standing privileged accounts eliminated; attack window reduced to minutes |

## **3\. Zero Trust Architecture**

**\[HIGH IMPACT\]** Zero Trust eliminates the 'trusted network perimeter' assumption — the root cause behind most lateral movement attacks in breaches.

Zero Trust principle: Never trust, always verify. Every access request is authenticated and authorized regardless of network location, device, or previous trust. Assumes breach.

| Zero Trust Pillar | Traditional Model | Zero Trust Model | Mitigation Impact |
| :---- | :---- | :---- | :---- |
| Identity | Trust users inside the network perimeter | Verify every user via MFA \+ risk signals on every request | Eliminates lateral movement via stolen session on internal network |
| Device | Trust any device on the corporate network | Device health check (MDM compliance) before granting access | Compromised unmanaged devices cannot access corporate resources |
| Network | Castle-and-moat: internal \= trusted | Microsegmentation; encrypt all traffic including internal | Attacker who breaches perimeter cannot move laterally between segments |
| Applications | VPN gives access to all internal apps | Per-app access grants with continuous re-verification | Single compromised credential does not unlock all internal applications |
| Data | Flat access to all data once inside | Data classification \+ access control \+ DLP on egress | Data exfiltration requires multiple controls to be bypassed simultaneously |

# **PART 3 — APPLICATION SECURITY MITIGATIONS**

## **1\. Input Validation & Sanitization**

**\[CRITICAL IMPACT\]** The root cause of injection attacks (SQLi, XSS, Command Injection, SSRF, XXE) is trusting user input. Input validation is the single most impactful application security control.

| Mitigation | Threat Addressed | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Allowlist Input Validation | All injection attacks | Define expected format (regex, schema, enum); reject anything that doesn't match | Eliminates entire class of injection attacks at entry point |
| Parameterized Queries / ORM | SQL Injection | Never concatenate user input into SQL; use prepared statements or ORM | Eliminates SQLi — no code path from user input to raw SQL execution |
| Output Encoding | XSS (Stored, Reflected, DOM) | HTML-encode all user-controlled data before rendering; context-aware encoding | Prevents injected scripts from executing in victim's browser |
| Content Security Policy (CSP) | XSS (defense-in-depth) | HTTP header defining trusted script sources; block inline scripts | Reduces XSS impact even if input encoding is missed in one place |
| SSRF Protection | SSRF leading to metadata theft or internal network access | URL allowlist for outbound requests; block private IP ranges; DNS rebinding protection | Prevents cloud metadata access, internal service enumeration, and lateral movement via SSRF |
| XXE Prevention | XML External Entity attacks | Disable external entity processing in XML parsers; use JSON where possible | Eliminates file read, SSRF, and RCE via malicious XML documents |

## **2\. Security HTTP Headers**

**\[MEDIUM IMPACT\]** Security headers are low-effort, high-impact controls. Most can be set in one line of configuration and reduce the attack surface for entire classes of browser-based attacks.

| Header | Threat Addressed | Recommended Value | Impact |
| :---- | :---- | :---- | :---- |
| Content-Security-Policy | XSS, clickjacking, data injection | default-src 'self'; script-src 'self'; object-src 'none' | High — restricts what scripts can execute even if XSS payload injected |
| Strict-Transport-Security (HSTS) | SSL stripping, downgrade attacks | max-age=31536000; includeSubDomains; preload | High — forces HTTPS; prevents MITM via HTTP downgrade |
| X-Frame-Options | Clickjacking | DENY or SAMEORIGIN | Medium — prevents embedding in iframes for UI redress attacks |
| X-Content-Type-Options | MIME sniffing attacks | nosniff | Low-Medium — prevents browser from interpreting files as different MIME type |
| Referrer-Policy | Information leakage via Referer header | strict-origin-when-cross-origin | Low — prevents sensitive URL paths from leaking to third parties |
| Permissions-Policy | Unauthorized access to browser APIs | camera=(), microphone=(), geolocation=() | Medium — restricts browser feature access by embedded content |

## **3\. CSRF, Session, and Authentication Controls**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| CSRF Tokens | Cross-Site Request Forgery | Unique, unpredictable per-session token in all state-changing requests; validate server-side | High — attacker cannot forge valid requests from another origin |
| SameSite Cookies | CSRF (defense-in-depth) | SameSite=Strict or Lax on session cookies | High — browser blocks cross-site cookie submission automatically |
| Secure \+ HttpOnly Cookies | Session hijacking, XSS token theft | Set Secure (HTTPS only) and HttpOnly (no JS access) on all session cookies | High — session tokens cannot be stolen via XSS or plain HTTP |
| Session Regeneration | Session fixation attacks | Regenerate session ID on login, logout, and privilege change | Medium-High — invalidates any pre-auth session ID the attacker may have fixed |
| Absolute Session Timeout | Session persistence after user leaves | Hard expiry of 8-24h regardless of activity; re-auth for sensitive actions | Medium — limits window for session token reuse after theft |

# **PART 4 — API SECURITY MITIGATIONS**

## **1\. Authorization Controls (BOLA / BFLA)**

**\[CRITICAL IMPACT\]** BOLA is OWASP API \#1. Over 90% of APIs tested in enterprise audits have at least one object-level authorization failure. It requires zero technical skill to exploit.

| Mitigation | Addresses | Implementation Detail | Impact |
| :---- | :---- | :---- | :---- |
| Server-side Object Ownership Check | BOLA (Broken Object Level Auth) | Every API endpoint: query DB with both object\_id AND current\_user\_id. Never trust object ID alone. | Critical — eliminates horizontal privilege escalation entirely if applied consistently |
| Non-Sequential Object IDs | BOLA (reduces enumerability) | Use UUIDs v4 (random) instead of sequential integers as public-facing IDs | Medium — harder to enumerate but NOT a security control alone; must pair with ownership check |
| Function-Level Authorization | BFLA (Broken Function Level Auth) | Explicitly check user role before every function call; deny by default if role not in allowlist | High — prevents vertical privilege escalation via HTTP method or endpoint manipulation |
| Centralized Authorization Library | Inconsistent authz logic | Single shared library enforces all authorization; never duplicate per-endpoint | High — eliminates gaps from inconsistent implementation across 100s of endpoints |
| Field-Level Authorization | Excessive Data Exposure (API3) | Allowlist exactly which fields are returned per role; never return full DB object | Medium-High — limits data leakage even in partial authorization bypass |

## **2\. Rate Limiting & Throttling**

**\[HIGH IMPACT\]** Missing rate limiting is OWASP API \#4. It enables credential stuffing, enumeration, scraping, DDoS, and API cost fraud. It is one of the cheapest controls to implement with highest defensive value.

| Rate Limit Type | Threat Addressed | Algorithm | Impact |
| :---- | :---- | :---- | :---- |
| Per-User Rate Limit | Account takeover via credential stuffing | Token bucket: user gets N requests per window; Redis counter per user\_id | High — makes credential stuffing 10,000x slower; effectively blocks automated attacks |
| Per-IP Rate Limit | Unauthenticated brute force, scanner bots | Sliding window counter per IP; differentiate authenticated vs unauthenticated | High — blocks mass scanning; less effective against distributed attacks (add CAPTCHA) |
| Per-Endpoint Rate Limit | Targeted abuse of expensive operations | Tighter limits on: /login, /register, /password-reset, /send-sms, /pay | Critical — prevents SMS bombing, OTP brute force, payment replay attacks |
| Global Rate Limit | API-level DDoS, cost explosion | Circuit breaker on total RPS across all users; return 503 gracefully at threshold | Medium — protects availability and cloud cost; graceful degradation preferred |
| Adaptive Rate Limiting | Sophisticated attackers who stay under static thresholds | ML-based anomaly detection on request patterns; dynamic threshold adjustment | High — catches slow-and-low attacks that evade fixed rate limits |

## **3\. JWT & Token Security**

| Mitigation | JWT Attack Prevented | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Enforce RS256/ES256 Algorithm | alg:none attack, HS256 weak secret brute-force | Server-side: whitelist RS256 or ES256; reject tokens with any other alg including 'none' | Critical — eliminates the two most common JWT attacks in one line of code |
| Validate All Claims | Expired token replay, cross-service token use, issuer spoofing | Validate: exp (expiry), nbf (not before), iss (issuer), aud (audience) on every request | High — prevents token replay and cross-tenant attacks |
| Short Token Lifetime \+ Refresh Rotation | Stolen token reuse | Access token: 15min TTL. Refresh token: 7 days, rotate on use, revoke on logout | High — stolen access token expires quickly; refresh token rotation detects theft |
| Token Revocation List | Logout invalidation, stolen token response | Maintain Redis revocation set; check on every request; critical for high-security endpoints | Medium-High — adds latency cost but enables immediate token invalidation |
| Secure kid Handling | SQL injection via kid header | Validate kid against static allowlist of known key IDs; never use kid in database queries | High — eliminates SQLi/path traversal via kid parameter |

# **PART 5 — CLOUD SECURITY MITIGATIONS**

## **1\. IAM & Privilege Management**

**\[CRITICAL IMPACT\]** IAM misconfiguration is the \#1 root cause of cloud breaches. An over-permissive role attached to one compromised workload can expose an entire AWS organization.

| Mitigation | Threat Addressed | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Least Privilege IAM Policies | Lateral movement, privilege escalation via compromised workload | Specific actions (s3:GetObject not s3:\*) on specific resources (arn:aws:s3:::bucket-name/\*); no wildcard Resource | Critical — compromised workload limited to its exact function; cannot pivot |
| IMDSv2 Enforcement | SSRF to cloud metadata credential theft | Require PUT token request before metadata access; SSRF cannot follow redirect chain for token | Critical — eliminates the SSRF-to-credential-theft attack chain entirely |
| IAM Access Analyzer | Unintended public or cross-account resource access | Enable AWS IAM Access Analyzer; alerts on public S3, public KMS keys, cross-account roles | High — automated continuous detection of access policy misconfigurations |
| Service Control Policies (SCPs) | Account-level policy drift, rogue resource creation | Org-level SCPs deny dangerous actions (iam:CreateUser, s3:DeleteBucket) regardless of account-level policy | High — prevents even compromised admin credentials from taking certain destructive actions |
| Workload Identity (IRSA/WIF) | Hardcoded credentials in code, long-lived access keys | AWS IRSA / GCP Workload Identity: pods/functions get short-lived creds from IAM role; no static keys | Critical — eliminates class of secret leakage incidents; credentials rotate automatically |

## **2\. Network & Infrastructure**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| VPC Network Segmentation | Lateral movement after initial breach | Separate VPCs/subnets per tier (web, app, DB); NACLs \+ Security Groups deny cross-tier by default | High — attacker who breaches web tier cannot directly reach DB tier |
| Private Subnets \+ NAT Gateway | Direct internet access to internal resources | App and DB tiers in private subnets; internet egress via NAT; no public IPs on workloads | High — internal resources not directly addressable from internet |
| VPC Endpoint (PrivateLink) | Traffic routing over public internet to AWS services | S3/DynamoDB/other services accessed via VPC Endpoint; traffic never leaves AWS network | Medium — eliminates exposure of AWS API traffic to internet interception |
| Security Group Least Privilege | Unnecessary port/service exposure | Explicit allow rules only; deny all by default; no 0.0.0.0/0 inbound except port 443 on load balancer | High — reduces attack surface to only required service ports |
| Block 169.254.169.254 at Firewall | SSRF to metadata service (defense-in-depth) | WAF rule or iptables rule blocking egress to 169.254.0.0/16 from web-facing workloads | High — defense-in-depth against SSRF metadata attacks alongside IMDSv2 |

## **3\. Storage & Data Security**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Block Public Access Setting | Public S3 bucket exposure | AWS S3 Block Public Access: enable at account AND bucket level; enforce via SCP | Critical — single setting prevents entire class of public exposure misconfigs |
| S3 Bucket Policy Review | Overly permissive bucket policies | Deny Principal:\* without conditions; require specific principal ARNs; enable Access Analyzer | High — prevents data access from unintended accounts or public |
| Encryption at Rest (SSE-KMS) | Data exposure if storage media compromised | Server-side encryption with customer-managed KMS keys; enforce via bucket policy Deny if not encrypted | High — data unreadable without KMS key access even with raw storage access |
| Access Logging \+ CloudTrail | Undetected data exfiltration | S3 server access logging; CloudTrail data events for S3 GetObject/DeleteObject; ship to SIEM | High — enables detection of unusual access patterns; evidence for incident response |
| Object Versioning \+ MFA Delete | Ransomware, accidental/malicious deletion | Enable versioning; require MFA for delete operations on critical buckets | High — ransomware cannot permanently destroy data; recovery from any deletion |

# **PART 6 — DATA PROTECTION MITIGATIONS**

## **1\. Encryption Controls**

**\[CRITICAL IMPACT\]** Encryption is the last line of defense when all other controls fail. Data encrypted with modern algorithms remains protected even when the storage medium or transmission is compromised.

| Mitigation | Use Case | Standard / Algorithm | Impact |
| :---- | :---- | :---- | :---- |
| Encryption in Transit | Data interception during transmission (MITM) | TLS 1.2+ minimum; TLS 1.3 preferred; enforce via HSTS; disable SSL 3.0, TLS 1.0/1.1 | Critical — renders network sniffing useless; required for all external \+ internal service traffic |
| Encryption at Rest | Physical storage compromise, backup theft | AES-256-GCM for symmetric; customer-managed keys via KMS/HSM; encrypt DB, volumes, backups | High — data unreadable without key access; satisfies GDPR, HIPAA, PCI-DSS at-rest requirements |
| Password Hashing | Password database breach | Argon2id (preferred) or bcrypt with cost factor ≥12; never MD5/SHA1/SHA256 for passwords | Critical — stolen password hash database cannot be cracked in reasonable time |
| Field-Level Encryption | Insider threat, partial DB compromise | Encrypt specific sensitive fields (SSN, card number, health data) with separate keys per field or tenant | High — compromised DB query access cannot read sensitive fields without field-specific key |
| End-to-End Encryption (E2EE) | Service provider access to user data | Keys held only by end users; server never has plaintext; Signal Protocol for messaging | Critical (for privacy) — eliminates server-side data exposure; limits what operator can access or disclose |

## **2\. Key Management**

**\[HIGH IMPACT\]** Encryption is only as strong as key management. Keys stored alongside encrypted data, or in code, negate the entire benefit of encryption.

| Mitigation | Threat Addressed | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Hardware Security Module (HSM) | Key extraction from software | Store master keys in FIPS 140-2 Level 3 HSM; cryptographic operations performed inside HSM | Critical — private keys physically cannot be extracted; highest assurance for PKI and signing |
| Cloud KMS (AWS KMS, GCP Cloud KMS) | Hardcoded keys, key storage in code/config | Managed key service; automatic rotation; IAM-controlled access; CloudTrail logs all key use | High — eliminates hardcoded key class; all key operations auditable; auto-rotation |
| Secret Manager (Vault, AWS Secrets Manager) | Secrets in environment variables, config files | Secrets injected at runtime via API; automatic rotation; lease-based access; no static secrets in code | High — eliminates secrets-in-code/config; rotation without deployment; fine-grained access |
| Key Rotation Policy | Compromise of old keys used indefinitely | Automatic rotation: KMS keys annually; TLS certificates quarterly; API keys on staff change; session keys per-session | Medium-High — limits the window during which a compromised key is valid |

## **3\. Data Loss Prevention (DLP)**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Egress DLP Scanning | Intentional/accidental data exfiltration | Inspect outbound traffic/email/uploads for PII patterns (regex for SSN, card numbers, health IDs); block or alert | High — catches accidental leakage and some insider threats before data leaves |
| Data Classification | Uncontrolled handling of sensitive data | Label all data: Public/Internal/Confidential/Restricted; enforce different controls per classification | High — foundation for all data security decisions; reduces over-protection of low-value data |
| Data Masking / Tokenization | Sensitive data exposure in non-prod environments | Replace real PII with realistic fake data in dev/test; tokenize card numbers with vault-backed tokens | High — data breaches in dev/test environments expose no real user data; PCI-DSS requirement |
| Right-to-Erasure Controls | GDPR/privacy compliance, persistent sensitive data | Logical delete: mark as deleted \+ purge after retention period; cascade deletes; backup deletion policy | Medium-High — ensures compliance; reduces breach scope; limits liability for old data |

# **PART 7 — NETWORK SECURITY MITIGATIONS**

## **1\. Web Application Firewall (WAF)**

**\[HIGH IMPACT\]** A WAF provides a detective and preventive layer at the edge — blocking known attack patterns before they reach application code. It is not a substitute for secure coding but is a critical defense-in-depth layer.

| WAF Capability | Threat Addressed | Rule Type | Impact |
| :---- | :---- | :---- | :---- |
| OWASP Core Rule Set (CRS) | SQLi, XSS, RFI, command injection, path traversal | Signature-based blocking of known attack patterns | High — blocks script-kiddie and automated scanner attacks; reduces noise to allow focus on novel threats |
| IP Reputation Blocking | Known malicious IPs, TOR exit nodes, botnet IPs | Block/challenge requests from threat intelligence IP feeds | Medium — stops known-bad actors but attackers rotate IPs; combine with rate limiting |
| Geo-blocking | Attacks from unexpected regions | Block or challenge traffic from countries not in expected user base | Low-Medium — reduces attack surface; may cause false positives for VPN/travel users |
| Rate Limiting at WAF | DDoS, credential stuffing at scale | Per-IP request rate limits; per-path rate limits; burst protection | High — first line of rate limiting before traffic reaches backend |
| Custom Rules for Business Logic | Application-specific abuse (e.g., coupon stacking, bulk account creation) | Pattern rules matching application-specific abuse: unusual parameter combinations, automation signals | Medium — context-specific protection that generic WAF rules cannot provide |

## **2\. DDoS Protection**

| Mitigation Layer | Attack Type | Mechanism | Impact |
| :---- | :---- | :---- | :---- |
| Volumetric DDoS Protection (CDN/Cloud Shield) | Layer 3/4 volumetric floods (UDP, ICMP, SYN) | Anycast routing absorbs traffic at CDN edge before reaching origin; scrubbing centers | Critical — protects against multi-Gbps/Tbps volumetric attacks that overwhelm on-prem links |
| L7 DDoS Mitigation (WAF \+ Challenge) | HTTP flood, slowloris, application exhaustion | Rate limiting \+ CAPTCHA/JS challenge on suspicious request patterns | High — distinguishes bots from real users; protects against application-layer exhaustion |
| Auto-Scaling | Resource exhaustion under legitimate-looking load | Horizontal scaling on load metrics; scale-out before capacity exhaustion | Medium — not a security control but maintains availability under attack; cost risk in auto-scale |
| Circuit Breakers | Cascading failure from downstream overwhelm | Stop sending requests to unhealthy downstream service; return cached/degraded response | Medium — prevents one overwhelmed service from bringing down entire system |

## **3\. DNS & TLS Mitigations**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| DNSSEC | DNS spoofing, cache poisoning | Cryptographically signed DNS records; resolvers validate signatures before accepting records | High — eliminates DNS cache poisoning; requires registrar and resolver support |
| DNS CAA Records | Unauthorized SSL certificate issuance | CAA record limits which CAs can issue certificates for your domain | High — prevents rouge CA from issuing certificates for your domain to enable MITM |
| Certificate Transparency (CT) Monitoring | Unauthorized certificate issuance detection | Monitor CT logs for any certificate issued for your domain; alert on unexpected issuance | High — detects MITM certificate issuance even if CAA bypassed; enables rapid response |
| HSTS Preloading | SSL stripping, first-visit MITM | Submit domain to browser HSTS preload list; browsers enforce HTTPS before first connection | High — eliminates first-visit vulnerability where attacker can downgrade to HTTP before HSTS header received |
| TLS 1.3 \+ Strong Cipher Suites | Downgrade attacks, weak cipher exploitation | Enforce TLS 1.3; disable RC4, 3DES, CBC-mode ciphers; require PFS (ECDHE key exchange) | High — eliminates weak cipher exploitation; forward secrecy protects past sessions if key compromised |

# **PART 8 — AI & LLM SECURITY MITIGATIONS**

## **1\. Prompt Injection Mitigations**

**\[CRITICAL IMPACT\]** Prompt injection is OWASP LLM \#1. In agentic AI systems where the LLM can take actions (call APIs, write files, send messages), a successful injection can result in data exfiltration, unauthorized actions, or complete agent hijacking.

| Mitigation | Injection Type Addressed | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Input Sanitization Layer | Direct prompt injection | Pre-process user input: strip meta-instructions; validate against expected schema; flag role-override attempts | Medium — reduces obvious injections; determined attackers find obfuscation; must combine with other controls |
| Structured Input Schemas | Direct injection via free-text fields | Use structured input forms (JSON schema, form fields) instead of free-text; LLM receives only expected data types | High — eliminates injection via free-text fields; restricts the injection surface significantly |
| Separate System Prompt from User Data | Direct injection contaminating system context | Use API message roles correctly (system/user/assistant); never concatenate user input into system prompt string | High — architectural separation makes it much harder for user input to override system-level instructions |
| Output Validation Before Action | Indirect injection causing malicious agent actions | Parse LLM output through a validation layer; check all tool calls against allowlist before executing | Critical — even if injection succeeds in manipulating LLM output, the action is blocked before execution |
| Indirect Injection — Content Sanitization | Indirect injection via documents, web pages, emails | Sanitize all external content before RAG injection or LLM processing; strip hidden instructions | Medium-High — reduces indirect injection but determined attackers can craft prompts that survive sanitization |

## **2\. Agent Security (Least Privilege for AI)**

**\[HIGH IMPACT\]** LLM agents that can take actions (tool use) dramatically expand the attack surface. Least privilege for AI agents limits blast radius when prompt injection or hallucination causes unintended actions.

| Mitigation | Threat Addressed | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| Minimal Tool Permissions | Excessive agency, injection-driven unauthorized actions | Give agent only the specific tools needed; read-only where possible; separate agents per function | High — compromised agent limited to its specific capability; cannot pivot to other systems |
| Human-in-the-Loop for High-Risk Actions | Irreversible/high-impact agent actions | Require human approval before: delete, send email, payment, admin operations, external calls | Critical — prevents irreversible damage from injection or hallucination; accept latency cost |
| Action Allowlisting | Injection causing agent to call unexpected tools | Agent can only call tools from an explicit allowlist; any tool not on list is blocked | High — injection that adds new tool calls is blocked at the action validation layer |
| Audit Logging All Agent Actions | Undetected agent misuse or drift | Log every tool call with: user, prompt, tool, parameters, result, timestamp; ship to SIEM | High — enables detection of injection, misuse, and drift; essential for incident response |

## **3\. RAG & Data Pipeline Security**

| Mitigation | Threat | Implementation | Impact |
| :---- | :---- | :---- | :---- |
| RAG Source Authorization | Cross-user data leakage via retrieval | Filter retrieved documents by user's access permissions before injecting into context; multi-tenant RAG must enforce tenant isolation | Critical — prevents users from retrieving documents they don't have access to via semantic query |
| Vector DB Input Sanitization | Embedding poisoning / RAG poisoning | Validate and sanitize documents before embedding; review sources before adding to knowledge base; limit who can add documents | High — prevents attacker from injecting malicious instructions into the knowledge base |
| Retrieval Result Validation | LLM acting on poisoned retrieved content | Post-retrieval: check documents against content policy before injection; flag anomalous instructions in retrieved text | Medium — additional defense layer against poisoned documents that passed initial sanitization |
| Context Window Isolation | Cross-session context leakage | Never share context windows between users or sessions; clear context completely on session end | High — prevents user A's conversation from leaking into user B's context |

# **PART 9 — OPERATIONAL & PROCESS MITIGATIONS**

## **1\. Logging, Monitoring & Detection**

**\[HIGH IMPACT\]** Without detection controls, every other mitigation becomes reactive. Average breach dwell time without detection controls: 200+ days. With mature SIEM and alerting: hours to days.

| Mitigation | What It Detects | Implementation | Impact on Dwell Time |
| :---- | :---- | :---- | :---- |
| Centralized SIEM | Correlated multi-source attacks, lateral movement, anomalous patterns | Splunk, Elastic, Microsoft Sentinel, Chronicle; ingest: auth logs, network flows, app logs, cloud trail | Transforms isolated log entries into attack narratives; reduces MTTD from months to hours |
| Structured Logging Standards | Inability to query and correlate events | JSON log format with mandatory fields: timestamp, request\_id, user\_id, IP, action, resource, result, latency | Enables reliable alerting and forensics; without structure, logs are noise not signal |
| Security Alerting Rules | Specific attack patterns in real-time | Alerts on: N failed auth in M minutes; new admin account created; data export \>threshold; privileged command at unusual time | Reduces MTTD for known attack patterns to minutes; false positive tuning is ongoing investment |
| User Entity Behavior Analytics (UEBA) | Insider threats, compromised accounts doing unusual actions | Baseline normal behavior per user; alert on deviations: unusual hours, unusual data access, bulk downloads | High — detects compromised accounts behaving differently from their baseline pattern |
| Honeytokens / Canary Files | Data exfiltration detection | Place fake high-value files (fake DB credentials, fake customer list); alert on any access | High — zero false positives; any access to a honeytoken indicates compromise or reconnaissance |

## **2\. Vulnerability Management & Patching**

| Mitigation | Threat | SLA / Target | Impact |
| :---- | :---- | :---- | :---- |
| SCA / Dependency Scanning | Vulnerable open-source components (e.g. Log4Shell, Spring4Shell) | Scan on every commit; block PRs with Critical CVEs unacknowledged; automate Dependabot/Renovate | Critical — catches known vulnerable dependencies before they reach production |
| SAST (Static Application Security Testing) | Code-level vulnerabilities (SQLi, hardcoded secrets, insecure functions) | Run in CI pipeline on every PR; SemGrep, CodeQL, Checkmarx, Snyk Code | High — catches vulnerability classes at code review stage; cheap to fix vs post-deployment |
| DAST (Dynamic Application Security Testing) | Runtime vulnerabilities, authentication issues, server config | Weekly automated scan of staging; OWASP ZAP, Burp Suite Pro; before each major release | High — finds issues that only manifest at runtime; cannot be caught by SAST |
| Patch SLA Policy | Extended exposure window for known CVEs | Critical: 24h. High: 72h. Medium: 30 days. Low: next maintenance window. Enforce via policy and tooling | High — structured SLA eliminates informal prioritization; reduces exposure window for known exploited CVEs |
| Asset Inventory (CSPM / CMDB) | Unknown assets with unpatched vulnerabilities | Continuous cloud asset discovery; CSPM for cloud, CMDB for on-prem; alert on new unmanaged assets | High — cannot patch what you don't know exists; inventory is the foundation of vulnerability management |

## **3\. Incident Response & Recovery**

| Mitigation | Impact Addressed | Key Components | Outcome |
| :---- | :---- | :---- | :---- |
| IR Playbooks | Slow, inconsistent response to incidents | Pre-defined steps for each incident type: ransomware, data breach, account takeover, DDoS; roles assigned | Reduces MTTR; ensures legal/compliance steps not missed; enables junior staff to respond effectively |
| Tabletop Exercises | Untested response plans, gaps in coordination | Quarterly simulation of breach scenario; all stakeholders: security, engineering, legal, comms, exec | Surfaces gaps before real incident; builds muscle memory; identifies communication failures |
| Backup & Recovery Testing | Data loss from ransomware or accidental deletion | 3-2-1 rule: 3 copies, 2 media types, 1 offsite; test restoration quarterly; air-gapped backups for critical | Critical — verified backups are the only guaranteed defense against ransomware data loss |
| Chain of Custody / Forensics | Inability to investigate or prosecute after incident | Preserve logs before remediation; forensic image of compromised systems; maintain evidence integrity | Legal and regulatory requirement; enables root cause analysis; supports law enforcement if needed |

# **PART 10 — MITIGATION SELECTION GUIDE & IMPACT MATRIX**

## **1\. Choosing Mitigations by Threat Category**

| Threat (STRIDE) | Primary Mitigation Type | Top 3 Controls | Security Layer |
| :---- | :---- | :---- | :---- |
| Spoofing | Preventive | MFA, certificate-based auth, FIDO2/passkeys | Identity |
| Tampering | Preventive \+ Detective | Input validation, HMAC signing, immutable audit logs | Application |
| Repudiation | Detective \+ Directive | Write-once audit logs, digital signatures, SIEM | Operational |
| Information Disclosure | Preventive \+ Corrective | Encryption at rest & transit, access controls, DLP | Data |
| Denial of Service | Preventive \+ Corrective | Rate limiting, WAF, DDoS protection, circuit breakers | Network/App |
| Elevation of Privilege | Preventive | RBAC/least privilege, server-side authz, JIT access | Identity/App |

## **2\. Cost vs Impact Matrix — Where to Invest First**

This matrix shows relative implementation cost vs security impact. Prioritize low-cost/high-impact controls first. They give the best ROI.

| Mitigation | Cost to Implement | Security Impact | Priority |
| :---- | :---- | :---- | :---- |
| MFA on all accounts | Low | Critical | P0 — Do immediately |
| Security HTTP headers | Very Low | High | P0 — Single config change |
| IMDSv2 enforcement | Very Low | Critical | P0 — One API call to enable |
| Block Public S3 Access | Very Low | Critical | P0 — Single account-level setting |
| HSTS \+ TLS 1.3 | Low | High | P0 — Config change; deploy |
| Rate limiting on login/API | Low-Medium | High | P1 — Redis \+ middleware |
| RBAC \+ least privilege audit | Medium | High | P1 — Ongoing; audit quarterly |
| Centralized SIEM | Medium-High | High | P1 — Foundational detection |
| Parameterized queries | Low (refactor cost) | Critical | P0 — Fix in next sprint for new code |
| Encryption at rest (KMS) | Low-Medium | High | P1 — Enable on new resources |
| WAF deployment | Medium | High | P1 — Managed WAF (AWS/Cloudflare) |
| Hardware tokens (FIDO2) | High (per user cost) | Critical | P1 — For admins/privileged users first |
| HSM for key management | Very High | Critical | P2 — For high-security / regulated workloads |
| Zero Trust network rearch | Very High | Critical | P2 — Multi-year program; phase by phase |
| Full UEBA / anomaly detection | High | High | P2 — After basic SIEM is mature |

## **3\. Mitigation Layering — The 5-Layer Defense Model**

Apply mitigations in layers so that a failure in any one layer does not result in a breach. Each layer should operate independently.

| Layer | Controls at This Layer | What Happens If This Layer Fails Alone |
| :---- | :---- | :---- |
| Layer 1 — Perimeter | WAF, DDoS protection, IP reputation, geo-fencing, TLS enforcement | Attacker reaches application layer — authentication required next |
| Layer 2 — Authentication | MFA, FIDO2, brute-force protection, account lockout, login anomaly detection | Attacker is authenticated — authorization required for every action |
| Layer 3 — Authorization | RBAC, BOLA checks, server-side ownership validation, least privilege | Attacker accesses only what their compromised account is permitted — data protection next |
| Layer 4 — Data | Field encryption, tokenization, DLP egress, data classification, masking | Attacker can see data labels/structure but sensitive fields remain encrypted — detection next |
| Layer 5 — Detection & Response | SIEM, UEBA, honeytokens, IR playbooks, forensics, backup recovery | Even if attacker exfiltrates data — the breach is detected quickly; evidence preserved; systems recovered |

  **CORE PRINCIPLE: No single mitigation is sufficient. Layer preventive \+ detective \+ corrective controls across every tier.**  