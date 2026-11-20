# Sending Securegent events to a SIEM

`securegent-siem` turns the audit log into standard security events, so blocked agent
actions show up next to the rest of your alerts.

```
securegent-siem --format ecs                         # convert the whole log, print it
securegent-siem --format ecs --output ecs.jsonl --follow       # live, to a file a shipper reads
securegent-siem --format cef --syslog siem.example.com:514 --follow   # live, over syslog (UDP)
securegent-siem --format ecs --follow --min-severity 5          # only blocked calls
```

| Format | Use it for |
|---|---|
| `ecs` | Elastic Common Schema JSON, one event per line. Elastic/OpenSearch as is; Wazuh and Splunk as JSON. |
| `cef` | Common Event Format. Splunk, QRadar, ArcSight, usually over syslog. |

## Severity

| Severity | Meaning |
|---|---|
| 1 | allowed |
| 3 | allowed after a human approved it |
| 5 | unknown tool, or tool outside the token's scope |
| 6 | denied by policy, or a human refused approval |
| 7 | bad, expired or revoked credential, or kill switch on |
| 8 | denied because of tainted data: likely prompt injection or exfiltration |

Taint findings carry MITRE ATLAS technique ids: untrusted data steering a call is
`AML.T0051.001` (indirect prompt injection), confidential data leaving is `AML.T0057`
(LLM data leakage). In ECS they are in `threat.technique.id`; in CEF in `cs5` ("atlas").

## Main ECS fields

`@timestamp`, `message`, `event.action` (tool), `event.outcome` (success/failure),
`event.reason`, `event.severity`, `event.id`, `rule.id`, `user.name` (the human the agent
acts for), `threat.*`, and `securegent.*`: `agent_id`, `decision`, `stage` (tool, auth,
scope, policy, approval), `task`, `args` (JSON string), `approved_by_human`, `tainted`,
`taint_labels`, `taint`.

## Wazuh

1. `securegent-siem --format ecs --output /var/log/securegent/ecs.jsonl --follow`
2. In the agent's `ossec.conf`:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/securegent/ecs.jsonl</location>
   </localfile>
   ```
3. Copy [`wazuh-securegent-rules.xml`](wazuh-securegent-rules.xml) to
   `/var/ossec/etc/rules/securegent_rules.xml` on the manager and restart it.

The rules: any Securegent event (level 2), blocked call (7), human approval (5), credential
or kill-switch failure (9), tainted data (10), and **the same agent blocked 5 times in 2
minutes (12)**, a strong sign it has been hijacked. Test them with `wazuh-logtest` by
pasting an exported line.

## Elastic (Filebeat)

```yaml
filebeat.inputs:
  - type: filestream
    id: securegent
    paths: [/var/log/securegent/ecs.jsonl]
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
```

## Splunk

JSON file: monitor `ecs.jsonl` with `sourcetype = _json` (or a custom sourcetype with
`KV_MODE = json`, `TIME_PREFIX = "@timestamp":"`). CEF over syslog: point `--syslog` at a
syslog input or Splunk Connect for Syslog and use the CEF add-on.

```
index=securegent event.outcome=failure | stats count by securegent.agent_id, event.action, event.reason
```
