#!/usr/bin/env python3
"""Фильтрация Kubernetes audit.log: поиск подозрительных событий.

Использование:
    python3 filter-audit.py audit.log -o audit-extract.json
    python3 filter-audit.py audit.log --since 2026-11-13T12:00:00Z   # только события после указанного времени

Что ищет:
    secrets-access      чтение секретов (get/list/watch), особенно от сервисных аккаунтов и через подмену
    privileged-pod      поды с privileged: true, hostPID/hostNetwork/hostIPC или hostPath
    pod-exec            kubectl exec/attach/port-forward, особенно в kube-system
    rbac-binding        создание и изменение RoleBinding/ClusterRoleBinding, особенно на cluster-admin
    audit-policy        изменение или удаление политики аудита и kube-apiserver
    impersonation       действия от чужого имени (kubectl --as)

Штатные действия системных компонентов (контроллеры kube-system, kubelet) в выжимку не попадают:
иначе ее засоряют системные поды с hostNetwork и privileged (kube-proxy, CNI).

В выжимку не попадают значения секретов: responseObject удаляется, requestObject сокращается
до полей, нужных для анализа. Только стандартная библиотека Python 3.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

PRIVILEGED_ROLES = {"cluster-admin", "admin", "edit"}
# Системные компоненты кластера. Их собственные обращения к секретам и подам - штатная работа.
SYSTEM_PREFIXES = ("system:kube-controller-manager", "system:kube-scheduler", "system:apiserver",
                   "system:node:", "system:serviceaccount:kube-system:", "system:kube-proxy",
                   "system:volume-scheduler")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def load_events(path, since=None):
    events, skipped = [], 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                skipped += 1          # строки klog и прочий вывод kube-apiserver
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if ev.get("kind") != "Event":
                continue
            # у одного запроса несколько стадий, берем итоговую
            if ev.get("stage") not in ("ResponseComplete", "Panic"):
                continue
            # метки времени в журнале в UTC в формате RFC 3339, их можно сравнивать как строки
            if since and ev.get("requestReceivedTimestamp", "") < since:
                continue
            events.append(ev)
    return events, skipped


def actor(ev):
    user = ev.get("user", {}).get("username", "?")
    imp = ev.get("impersonatedUser", {}).get("username")
    return user, imp


def effective_user(ev):
    user, imp = actor(ev)
    return imp or user


def is_system(name):
    return name.startswith(SYSTEM_PREFIXES)


def pod_spec_risks(spec):
    risks = []
    for kind in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(kind) or []:
            sc = c.get("securityContext") or {}
            if sc.get("privileged"):
                risks.append(f"{c.get('name')}: privileged: true")
            if sc.get("allowPrivilegeEscalation"):
                risks.append(f"{c.get('name')}: allowPrivilegeEscalation: true")
            if sc.get("runAsUser") == 0:
                risks.append(f"{c.get('name')}: runAsUser: 0")
    for flag in ("hostPID", "hostNetwork", "hostIPC"):
        if spec.get(flag):
            risks.append(f"{flag}: true")
    for v in spec.get("volumes") or []:
        if "hostPath" in v:
            risks.append(f"hostPath: {v['hostPath'].get('path')}")
    return risks


def slim_request(ev):
    """Оставляем из requestObject только то, что нужно для разбора, без секретных данных."""
    obj = ev.get("requestObject")
    if not isinstance(obj, dict):
        return None
    res = ev.get("objectRef", {}).get("resource")
    if res == "pods":
        spec = obj.get("spec", {})
        return {
            "metadata": {k: obj.get("metadata", {}).get(k) for k in ("name", "namespace")},
            "spec": {
                "serviceAccountName": spec.get("serviceAccountName"),
                "hostPID": spec.get("hostPID"),
                "hostNetwork": spec.get("hostNetwork"),
                "containers": [
                    {"name": c.get("name"), "image": c.get("image"), "command": c.get("command"),
                     "securityContext": c.get("securityContext")}
                    for c in spec.get("containers") or []
                ],
                "volumes": [v for v in spec.get("volumes") or [] if "hostPath" in v],
            },
        }
    if res in ("rolebindings", "clusterrolebindings"):
        return {"roleRef": obj.get("roleRef"), "subjects": obj.get("subjects")}
    if res == "secrets":
        return {"metadata": {k: obj.get("metadata", {}).get(k) for k in ("name", "namespace")},
                "data": "<скрыто>"}
    return {"kind": obj.get("kind")}


def slim_event(ev):
    out = {k: ev.get(k) for k in ("auditID", "stageTimestamp", "verb", "requestURI", "user",
                                  "impersonatedUser", "sourceIPs", "userAgent", "objectRef")}
    out = {k: v for k, v in out.items() if v is not None}
    out["responseStatus"] = {k: ev.get("responseStatus", {}).get(k) for k in ("code", "reason", "message")
                             if ev.get("responseStatus", {}).get(k) is not None}
    out["annotations"] = ev.get("annotations", {})
    req = slim_request(ev)
    if req is not None:
        out["requestObject"] = req
    return out


def classify(ev):
    """Возвращает список (категория, критичность, причина) для события."""
    found = []
    ref = ev.get("objectRef", {}) or {}
    res, sub, ns, name = ref.get("resource"), ref.get("subresource"), ref.get("namespace"), ref.get("name")
    verb = ev.get("verb")
    code = ev.get("responseStatus", {}).get("code")
    user, imp = actor(ev)
    who = effective_user(ev)
    ok = code is not None and code < 400
    status = "успешно" if ok else f"отказ {code}"

    if imp and res:  # discovery-запросы (/api, /apis) без ресурса не интересны
        found.append(("impersonation", "medium",
                      f"{user} выполняет {verb} {res or ev.get('requestURI')} от имени {imp} ({status})"))

    if res == "secrets" and verb in ("get", "list", "watch") and not is_system(who):
        if who.startswith("system:serviceaccount:"):
            sev = "high"
            why = f"сервисный аккаунт {who} запрашивает секреты в {ns}"
        elif ns == "kube-system":
            sev = "high"
            why = f"{who} читает секреты системного namespace kube-system"
        else:
            sev = "medium"
            why = f"{who} читает секреты в {ns}"
        found.append(("secrets-access", sev, f"{why} ({status})"))

    if res == "pods" and sub is None and verb in ("create", "update", "patch") and not is_system(who):
        risks = pod_spec_risks((ev.get("requestObject") or {}).get("spec", {}))
        if risks:
            found.append(("privileged-pod", "critical",
                          f"{who} создает под {ns}/{name} с опасными настройками: {', '.join(risks)} ({status})"))

    if res == "pods" and sub in ("exec", "attach", "portforward") and verb in ("create", "get"):
        sev = "critical" if ns == "kube-system" else "high"
        found.append(("pod-exec", sev, f"{who}: {sub} в под {ns}/{name} ({status})"))

    if res in ("rolebindings", "clusterrolebindings") and verb in ("create", "update", "patch"):
        role = ((ev.get("requestObject") or {}).get("roleRef") or {}).get("name")
        if role in PRIVILEGED_ROLES:
            found.append(("rbac-binding", "critical",
                          f"{who} привязывает роль {role} через {res[:-1]} {ns or ''}/{name} ({status})"))
        elif role:
            found.append(("rbac-binding", "medium", f"{who} создает {res[:-1]} {name} на роль {role} ({status})"))
        else:
            found.append(("rbac-binding", "high",
                          f"{who} создает {res[:-1]} {ns or ''}/{name}; roleRef не записан (уровень Metadata), "
                          f"проверить объект в кластере ({status})"))

    uri = ev.get("requestURI", "")
    if verb in ("create", "update", "patch", "delete") and (
            "audit-policy" in (name or "") or "audit-policy" in uri or
            (ns == "kube-system" and res == "pods" and (name or "").startswith("kube-apiserver"))):
        found.append(("audit-policy", "critical", f"{who} выполняет {verb} над {res}/{name} ({status})"))

    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit_log")
    ap.add_argument("-o", "--output", default="audit-extract.json")
    ap.add_argument("--since", metavar="ВРЕМЯ",
                    help="учитывать события не раньше этого времени, UTC: 2026-11-13T12:00:00Z")
    args = ap.parse_args()

    events, skipped = load_events(args.audit_log, args.since)
    extract = []
    raw_audit_mentions = 0
    for ev in events:
        if "audit-policy" in json.dumps(ev, ensure_ascii=False):
            raw_audit_mentions += 1
        for category, severity, reason in classify(ev):
            extract.append({"category": category, "severity": severity, "reason": reason, "event": slim_event(ev)})

    extract.sort(key=lambda x: (x["event"].get("stageTimestamp", ""), SEVERITY_ORDER[x["severity"]]))
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(extract, f, ensure_ascii=False, indent=2)

    print(f"Событий ResponseComplete: {len(events)}, пропущено строк не-JSON: {skipped}")
    print(f"Подозрительных записей: {len(extract)} -> {args.output}\n")
    by_cat = Counter(x["category"] for x in extract)
    for cat in ("secrets-access", "privileged-pod", "pod-exec", "rbac-binding", "audit-policy", "impersonation"):
        print(f"  {cat:15} {by_cat.get(cat, 0)}")
    print()
    for x in sorted(extract, key=lambda x: SEVERITY_ORDER[x["severity"]]):
        print(f"[{x['severity']:8}] {x['category']:15} {x['event'].get('stageTimestamp', '')}  {x['reason']}")

    who = defaultdict(Counter)
    for x in extract:
        who[x["event"]["user"]["username"]][x["category"]] += 1
    print("\nКто инициировал:")
    for u, c in who.items():
        print(f"  {u}: " + ", ".join(f"{k}={v}" for k, v in c.items()))

    if not by_cat.get("audit-policy"):
        print("\nИзменений политики аудита через API не найдено.")
        print(f"Строк с упоминанием 'audit-policy': {raw_audit_mentions} "
              "(обычно это аргументы kube-apiserver в ответах API, а не изменение политики).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
