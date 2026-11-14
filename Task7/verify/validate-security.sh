#!/usr/bin/env bash
# Проверка состояния защиты:
#  - PodSecurity Admission включен и на audit-zone стоит профиль restricted;
#  - Gatekeeper работает, шаблоны и ограничения созданы и действуют в режиме deny;
#  - у запущенных подов audit-zone безопасный securityContext;
#  - нарушения, найденные аудитом Gatekeeper в уже существующих подах.
set -uo pipefail

NS=audit-zone
PASS=0
FAIL=0
ok()  { echo "  [OK]   $*"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

echo "1. PodSecurity Admission"
level="$(kubectl get ns "${NS}" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
[ "${level}" = "restricted" ] && ok "${NS}: enforce=restricted" || bad "${NS}: enforce='${level}'"
probe="$(kubectl run psa-probe -n "${NS}" --image=nginx --dry-run=server \
  --overrides='{"spec":{"containers":[{"name":"psa-probe","image":"nginx","securityContext":{"privileged":true}}]}}' 2>&1)"
case "${probe}" in
  *"violates PodSecurity"*) ok "admission-плагин PodSecurity отклоняет privileged-под" ;;
  *) bad "PodSecurity не сработал: ${probe}" ;;
esac

echo
echo "2. OPA Gatekeeper"
for d in gatekeeper-controller-manager gatekeeper-audit; do
  ready="$(kubectl get deploy "${d}" -n gatekeeper-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null)"
  [ -n "${ready}" ] && [ "${ready}" -gt 0 ] && ok "${d}: готовых реплик ${ready}" || bad "${d} не готов"
done
for t in k8spspprivilegedcontainer k8spsphostpathvolume k8spsprunasnonroot; do
  created="$(kubectl get constrainttemplate "${t}" -o jsonpath='{.status.created}' 2>/dev/null)"
  [ "${created}" = "true" ] && ok "ConstraintTemplate ${t} создан" || bad "ConstraintTemplate ${t}: created='${created}'"
done
for c in k8spspprivilegedcontainer/deny-privileged-containers k8spsphostpathvolume/deny-hostpath-volumes \
         k8spsprunasnonroot/require-nonroot-readonly-rootfs; do
  action="$(kubectl get "${c}" -o jsonpath='{.spec.enforcementAction}' 2>/dev/null)"
  enforced="$(kubectl get "${c}" -o jsonpath='{.status.byPod[*].enforced}' 2>/dev/null)"
  if [ "${action}" = "deny" ] && [[ "${enforced}" == *true* ]]; then
    ok "${c}: enforcementAction=deny, применяется"
  else
    bad "${c}: action='${action}', enforced='${enforced}'"
  fi
done

echo
echo "3. Запущенные поды ${NS}"
pods="$(kubectl get pods -n "${NS}" -o name)"
[ -n "${pods}" ] || bad "в ${NS} нет подов, сначала запустите verify-admission.sh"
for p in ${pods}; do
  spec="$(kubectl get "${p}" -n "${NS}" -o json)"
  check="$(printf '%s' "${spec}" | python3 -c '
import json, sys
pod = json.load(sys.stdin)
spec = pod["spec"]
psc = spec.get("securityContext", {})
problems = []
for c in spec.get("containers", []) + spec.get("initContainers", []):
    sc = c.get("securityContext", {})
    if sc.get("privileged"):
        problems.append(c["name"] + ": privileged")
    if sc.get("runAsNonRoot", psc.get("runAsNonRoot")) is not True:
        problems.append(c["name"] + ": нет runAsNonRoot")
    if sc.get("runAsUser", psc.get("runAsUser")) == 0:
        problems.append(c["name"] + ": runAsUser 0")
    if sc.get("readOnlyRootFilesystem") is not True:
        problems.append(c["name"] + ": нет readOnlyRootFilesystem")
for v in spec.get("volumes", []):
    if "hostPath" in v:
        problems.append("hostPath " + v["name"])
print("; ".join(problems))
')"
  phase="$(printf '%s' "${spec}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"].get("phase"))')"
  [ -z "${check}" ] && ok "${p}: ${phase}, securityContext соответствует политике" || bad "${p}: ${check}"
done

echo
echo "4. Нарушения, найденные аудитом Gatekeeper (существующие ресурсы)"
kubectl get constraints -o custom-columns='CONSTRAINT:.metadata.name,ACTION:.spec.enforcementAction,VIOLATIONS:.status.totalViolations' 2>/dev/null

echo
echo "Итог: успешно ${PASS}, ошибок ${FAIL}"
[ "${FAIL}" -eq 0 ]
