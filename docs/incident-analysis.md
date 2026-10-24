# Incident analysis: repeated login failures followed by success

**Case:** Arif — simulated log data  
**Initial status:** Needs investigation; compromise is not confirmed  
**Input:** `data/sample_log.csv`

## Observed facts

- The sample records five failed login attempts for Arif from `203.0.113.77` between `09:14:03` and `09:14:23`, a span of 20 seconds.
- At `09:14:31`, the sample records a successful login for the same account and source IP, eight seconds after the last failure.
- The sample contains no `account_locked` event for Arif. This describes only the records in this sample; it does not prove that no lockout occurred outside the available logs.

## Initial assessment

The rapid series of failed attempts followed by a successful login is consistent with password guessing that eventually succeeded, so the activity should be reviewed. It could also have benign explanations, such as repeated typing errors, an incorrectly autofilled password, or multiple people sharing a network address.

The available logs are not enough to conclude that the account was compromised. For initial triage, this case receives higher priority than a similar burst without a subsequent successful login. That priority is a triage choice, not proof of malicious activity.

## Follow-up questions

1. Is this source IP expected for Arif, based on known login history and network context?
2. What device and user agent were used for the successful login? These fields are not present in the sample.
3. What did the account do after `09:14:31`? Review for unusual data access, password or MFA changes, and new token creation.
4. Did this source IP attempt logins for other usernames during the same period? That could indicate password spraying, a pattern this user-and-IP rule may not detect.
5. Was MFA used, and what was its result? The sample does not include MFA events.
6. Can Arif confirm whether the login attempt was expected?
7. Are the relevant logs complete and using consistent timestamps?

## Scope and limitations

This is a simulated training case, not evidence from a real system. The sample includes only timestamp, username, source IP, and event type. It does not include device identity, user agent, MFA results, account activity after login, or a complete authentication history.
