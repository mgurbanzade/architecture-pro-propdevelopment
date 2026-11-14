#!/usr/bin/env bash
# Проверка admission-контроля:
#  1. В audit-zone небезопасные поды отклоняются (сначала срабатывает PodSecurity restricted).
#  2. Gatekeeper отклоняет те же поды сам по себе: проверяем в namespace gatekeeper-check,
#     где PodSecurity выключен (privileged), а метка Gatekeeper включена.
#  3. Безопасные поды проходят в audit-zone и запускаются.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS=audit-zone
CHECK_NS=gatekeeper-check
PASS=0
FAIL=0

ok()  { echo "  [OK]   $*"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

expect_denied() {  # описание файл-или-stdin
  local desc="$1" out
  if out="$(kubectl apply -f - 2>&1 < "$2")"; then
    bad "${desc}: принят, а должен быть отклонен"
    kubectl delete -f - --ignore-not-found --wait=false < "$2" >/dev/null 2>&1
  else
    local who="?"
    case "${out}" in
      *"violates PodSecurity"*) who="PodSecurity" ;;
      *"gatekeeper"*)           who="Gatekeeper" ;;
    esac
    ok "${desc}: отклонен (${who})"
    echo "${out}" | head -6 | cut -c1-240 | sed 's/^/           /'
  fi
}

kubectl apply -f "${ROOT}/01-create-namespace.yaml" >/dev/null

echo "1. Небезопасные манифесты в ${NS} (PodSecurity restricted + Gatekeeper)"
for f in "${ROOT}"/insecure-manifests/*.yaml; do
  expect_denied "$(basename "${f}")" "${f}"
done

echo
echo "2. Те же манифесты в ${CHECK_NS}: PodSecurity выключен, работает только Gatekeeper"
kubectl create namespace "${CHECK_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "${CHECK_NS}" --overwrite \
  pod-security.kubernetes.io/enforce=privileged security.pd/gatekeeper=enforce >/dev/null
sleep 5   # Gatekeeper должен увидеть метку нового namespace
tmp="$(mktemp)"
for f in "${ROOT}"/insecure-manifests/*.yaml; do
  sed "s/namespace: ${NS}/namespace: ${CHECK_NS}/" "${f}" > "${tmp}"
  expect_denied "$(basename "${f}")" "${tmp}"
done
rm -f "${tmp}"
kubectl delete namespace "${CHECK_NS}" --wait=false >/dev/null

echo
echo "3. Безопасные манифесты в ${NS} должны быть приняты и запущены"
for f in "${ROOT}"/secure-manifests/*.yaml; do
  if out="$(kubectl apply -f "${f}" 2>&1)"; then
    ok "$(basename "${f}"): принят (${out})"
  else
    bad "$(basename "${f}"): отклонен: ${out}"
  fi
done
if kubectl wait --for=condition=Ready pod -l app=secure-demo -n "${NS}" --timeout="${WAIT_TIMEOUT:-180s}" >/dev/null 2>&1; then
  ok "все безопасные поды в состоянии Ready"
else
  bad "не все безопасные поды стали Ready"
fi
kubectl get pods -n "${NS}" -o wide

echo
echo "Итог: успешно ${PASS}, ошибок ${FAIL}"
[ "${FAIL}" -eq 0 ]
