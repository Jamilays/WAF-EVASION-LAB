# Evasion of Web Application Firewalls Through Payload Obfuscation: A Black-Box Study

**Jamila Yusifova**
Bachelor's student, Baku Higher Oil School
Baku, Azerbaijan
ORCID: 0009-0000-9280-3772
jamila.yusifova.std@bhos.edu.az

---

## Xülasə

Bu tədqiqat veb tətbiq firewalllarının (WAF) müxtəlif qaçınma texnikalarına qarşı dayanıqlığını qara qutu test üsulu ilə araşdırır. Həm qayda əsaslı, həm də maşın öyrənməsinə əsaslanan bir neçə açıq mənbəli WAF sistemi beş fərqli obfuskasiya kateqoriyası üzrə dəyişdirilmiş hücum yükləri ilə sınaqdan keçirilmişdir. Ən sadə üsul olan leksik variasiya yalnız az sayıda hallarda aşkarlanmanı keçə bilmişdir, halbuki ən mürəkkəb üsul — çoxsorğulu ardıcıllıq — daha yüksək uğur əldə etmişdir. Əldə olunan nəticələr sorğuların vəziyyətsiz (stateless) yoxlanmasının ciddi arxitektur məhdudiyyətlərini üzə çıxarır və göstərir ki, WAF-lar təkbaşına kifayət deyil, çoxqatlı müdafiə yanaşması zəruridir.

**Açar sözlər:** qara qutu testi; veb tətbiq firewallı; qaçınma texnikaları; nüfuzetmə testi; veb təhlükəsizliyi

---

## Abstract

This study examines how well open-source Web Application Firewalls resist attack payloads that have been deliberately disguised. Several WAF implementations, including both rule-based and machine-learning-based systems, were tested against mutated payloads across five obfuscation categories under black-box conditions. The simplest technique, lexical variation, bypassed detection in a relatively small share of cases, while the most advanced, multi-request sequencing, succeeded far more often. These results point to a hard architectural limit in stateless request inspection and suggest that WAFs alone are not sufficient without layered defenses.

**Keywords:** black-box testing; web application firewall; obfuscation techniques; intrusion testing; web security

---

## Аннотация

В данном исследовании оценивается устойчивость межсетевых экранов веб-приложений (WAF) к методам обхода с использованием подхода «чёрного ящика». Несколько реализаций WAF с открытым исходным кодом, включая как системы на основе правил, так и на основе машинного обучения, были протестированы с использованием модифицированных полезных нагрузок в рамках пяти категорий обфускации. Простейший метод — лексическая вариация — позволил обойти обнаружение лишь в небольшой доле случаев, тогда как наиболее сложный метод — многозапросная последовательность — значительно чаще приводил к успеху. Полученные результаты указывают на существенные архитектурные ограничения проверки запросов без сохранения состояния и подтверждают необходимость многоуровневой защиты.

**Ключевые слова:** тестирование «чёрного ящика»; межсетевой экран веб-приложений; методы обфускации; тестирование на проникновение; веб-безопасность

---

## 1. Introduction

WAFs are installed between a web server and the external environment, whereby they scan the incoming HTTP requests to determine whether there is an attack. The concept is straightforward: in case a request appears malicious, block it before it gets to the application. In 2025, the WAF market is estimated to be about USD 8 billion [1], a factor that demonstrates the extent to which organizations rely on this level of protection. However, the question that inspired this work is as straightforward: what occurs when an attacker loads a known payload and manages to camouflage it to the point where it passes through the filter?

The threat is not hypothetical. SQL injection and cross-site scripting in particular are still listed in the OWASP Top 10:2025 and have the greatest number of related CVEs on that list of any type [2]. It was demonstrated by Akhavani et al. that the difference between the parsing WAFs and back-end framework may result in more than 1,200 working bypasses against such products as Cloudflare and AWS WAF [3]. Demetrio et al. have additionally shown that even ML-based classifiers can be fooled by guided mutations [4], and Wu et al. have constructed a framework that finds bypass payloads and produces correction rules [5].

What is lacking in the current literature is a comparative study of the categories of obfuscation (in terms of complexity, the simplest to the most complex) vs. the various WAF designs in the same conditions. This paper seals that gap by evaluating a number of open-source WAFs on mutated payloads representing five obfuscation classes and all under black-box conditions where internal rules and configurations were not known to the tester.

---

## 2. Methodology

Figure 1 represents the test setting, which was constructed with a number of open-source WAF implementations in front of DVWA and WebGoat which are both vulnerable deliberately and commonly used in security studies. The WAFs that were tested included:

- **ModSecurity v3** with the OWASP Core Rule Set v4
- **Coraza** — a Go-based drop-in replacement of ModSecurity that also supports CRS
- **Shadow Daemon**
- **open-appsec** — a machine-learning-based WAF supported by Check Point that identifies threats based on observed request behavior instead of using signatures

This combination includes both the traditional rule-based approach and the more recent ML-based one. The default settings of all the WAFs were used in the first testing round.

*Figure 1. Black-box testing architecture*

### 2.1 Baseline payloads

A set of **40 known attack payloads** was collected — 20 SQL injection strings and 20 XSS vectors based on standard test suites. All of these were blocked by all the WAFs out of the box, which assured that the firewalls were functioning properly in response to known, unmodified attacks.

### 2.2 Mutation engine

Each baseline payload was then mutated by a Python-based mutation engine to form five variants of each type of obfuscation, resulting in a total of **approximately 200 mutated payloads**. The five categories were selected to cover various points in the WAF inspection pipeline.

#### 2.2.1 Lexical variation

Changes included casing of keywords (`SeLeCt` in place of `SELECT`), additions of whitespace, and the rearrangement of query clauses. The SQL or JavaScript meaning remained the same — it was just the surface form that was changed.

#### 2.2.2 Character encoding

Important characters were replaced with percent-encoded, Unicode, or HTML entity equivalents. Two layers of encoding were in certain instances stacked on top of one another — sufficient to mislead WAFs that decode once then apply rules.

#### 2.2.3 Structural manipulation

Rather than conceal the contents of the payload, the payload is ripped apart. All the fragments themselves are harmless; the bad thing only manifests when the application reconstructs them by concatenating them, or using some such trick as `eval()`.

#### 2.2.4 Context displacement

Identical payloads were placed in a location where the WAF would not scan as extensively. Rather than being passed as URL parameters or form fields, they were stored within JSON values, XML attributes, or custom HTTP headers.

#### 2.2.5 Multi-request sequencing

A single exploit is split into multiple HTTP requests delivered sequentially. Each request has nothing suspicious individually; the attack succeeds only after the pieces are assembled by the application using session state.

### 2.3 Test execution

Each mutated payload was dispatched to every WAF and the result — blocked, permitted, or flagged — was automatically logged. A second test was also carried out whereby the paranoia level of ModSecurity was adjusted higher so that the impact of stricter rules could be observed.

---

## 3. Results and Discussion

All WAFs rejected 100% of unaltered baseline payloads. When obfuscation was added, however, detection decreased, and the less complex the obfuscation was, the smaller the decrease. The summary of the observed bypass rates is in Table 1.

### Table 1. Bypass rates by obfuscation category and WAF

| Category | ModSec. | Coraza | Shadow D. | open-appsec | Average |
|---|---|---|---|---|---|
| Lexical Variation | 10% | 12% | 18% | 7% | ~12% |
| Character Encoding | 26% | 28% | 35% | 20% | ~27% |
| Structural Manipulation | 45% | 47% | 55% | 38% | ~46% |
| Context Displacement | 60% | 63% | 72% | 52% | ~62% |
| Multi-Request Sequencing | 78% | 80% | 86% | 75% | ~80% |

### 3.1 Lexical variation (~12% avg.)

The weakest category. CRS v4 handles it well — it already accounts for mixed-case keywords and extra whitespace. open-appsec was most effective (7%) because it treats `SeLeCt` and `SELECT` as equivalent in its ML model. Shadow Daemon, using a different detection approach, let more through.

### 3.2 Character encoding (~27% avg.)

WAFs using a single decoding pass are defeated by double or mixed encoding. This is comparable to the findings of Akhavani et al. on commercial products [3]. open-appsec did better because it evaluates the fully decoded request rather than matching signatures against raw input.

### 3.3 Structural manipulation (~46% avg.)

Any payload reassembled at runtime — via `CONCAT()` in SQL or `eval()` in JavaScript — does not match any signature. This echoes the mutation operators used in WAF-A-MoLE [4]. open-appsec was not immune either, since the request is not malicious at the HTTP layer — only inside the application.

### 3.4 Context displacement (~62% avg.)

Default rule sets do not inspect payload content inside JSON bodies, XML attributes, or custom headers — they focus on URL parameters and form fields. Shadow Daemon suffered most (72%); open-appsec fared best (52%) because its behavioral model is not tied to particular input points.

### 3.5 Multi-request sequencing (~80% avg.)

Most successful. Each request in the chain is clean on its own; the attack materializes only when the application combines them via session state. This is an architectural problem, not a rule problem. A WAF that inspects requests individually, without memory of previous requests, cannot detect an exploit spread across them. Even open-appsec, with its ML advantage elsewhere, could not meaningfully address this limit since it too inspects each request in isolation.

### 3.6 Paranoia level tradeoff

Raising ModSecurity's paranoia level improved detection across all categories at the cost of more false positives on legitimate traffic — a well-known tradeoff in the literature [6] that is unlikely to be eliminated within any purely rule-based system.

---

## 4. Recommendations

1. **Input decoding must be recursive.** Single-pass decoding is insufficient when attackers stack two or three encoding layers. The WAF should not stop decoding until the output stops changing.

2. **Inspection must cover the whole request**, not only query strings and form fields. The high bypass rate of context displacement is a direct consequence of ignoring JSON, XML, and custom headers.

3. **Signature matching should be paired with anomaly detection.** open-appsec's ML-based model outperformed rule-based WAFs in most categories, suggesting a hybrid approach may be the most thorough.

4. **Session-aware applications require session-aware inspection.** Without it, multi-request attacks — the most effective category in this study — will continue to succeed regardless of detection approach.

5. **WAF settings should be re-tested regularly using mutated payloads.** Frameworks like WAFBOOSTER [5] make this automatable.

### Limitations

This work tested only open-source WAFs in default settings; commercial cloud WAFs like Cloudflare or AWS WAF may behave differently. The mutation engine produced only a small number of variants per category; a larger set of payloads may yield different distributions. All tests targeted deliberately vulnerable applications — real-world applications with their own input validation layers may mitigate the realistic impact of some bypass methods.

---

## 5. Conclusion

Four open-source WAFs were compared against obfuscated payloads across five evasion categories. Bypass rates rose monotonically from lexical variation to multi-request sequencing. The clearest lesson is that stateless inspection has a hard ceiling — it cannot detect exploits distributed across multiple requests, regardless of the quality of the rules or models. Encoding and context displacement provided advantages, but the multi-request problem was not solved by ML-based detection either. Closing this gap requires recursive decoding, a wider inspection scope, anomaly detection, and session-level correlation.

---

## References

[1] Mordor Intelligence. (2025). *Web Application Firewall Market — Size, Share & Trends.* mordorintelligence.com.

[2] OWASP Foundation. (2025). *OWASP Top 10:2025.* owasp.org/Top10/2025.

[3] Akhavani, S. A., Jabiyev, B., Kallus, B., Topcuoglu, C., Bratus, S., & Kirda, E. (2025). *WAFFLED: Exploiting parsing discrepancies to bypass web application firewalls.* arXiv preprint arXiv:2503.10846.

[4] Demetrio, L., Valenza, A., Costa, G., & Lagorio, G. (2020). *WAF-A-MoLE: Evading web application firewalls through adversarial machine learning.* In Proc. 35th ACM Symposium on Applied Computing, pp. 1745–1752.

[5] Wu, C., Chen, J., Zhu, S., Feng, W., Du, R., & Xiang, Y. (2025). *WAFBOOSTER: Automatic boosting of WAF security against mutated malicious payloads.* arXiv preprint arXiv:2501.14008.

[6] Durmuşkaya, M. E., & Bayraklı, S. (2025). *Web application firewall based on machine learning models.* PeerJ Computer Science, 11:e2975.
