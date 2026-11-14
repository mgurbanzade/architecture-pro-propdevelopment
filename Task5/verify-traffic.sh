#!/usr/bin/env bash
# Проверка сетевых политик задания 5.
# Для каждой роли создается клиентский под alpine с меткой role=<роль>, плюс один под без метки.
# Из каждого клиента запрашиваются все четыре сервиса, результат сравнивается с ожидаемым.
#
# Клиент с меткой role=<роль> подходит под селектор сервиса <роль>-app, и Kubernetes добавил бы его
# в endpoints этого сервиса: часть запросов к сервису уходила бы в alpine, где порт 80 никто не слушает
# (Connection refused). Поэтому у клиентов проверка готовности, которая никогда не проходит:
# неготовые поды в endpoints не попадают, а exec в них работает.
#
#   bash verify-traffic.sh        # после применения non-admin-api-allow.yaml: доступ только внутри пар
#   bash verify-traffic.sh open   # до применения политик: доступ есть отовсюду
set -uo pipefail

NS="${NS:-default}"
MODE="${1:-policy}"
ATTEMPTS="${ATTEMPTS:-2}"
CLIENTS="front-end back-end-api admin-front-end admin-back-end-api none"
SERVICES="front-end-app back-end-api-app admin-front-end-app admin-back-end-api-app"

expected() {  # роль-клиента сервис
  if [ "${MODE}" = "open" ]; then echo OK; return; fi
  case "$1:$2" in
    front-end:back-end-api-app | back-end-api:front-end-app | \
    admin-front-end:admin-back-end-api-app | admin-back-end-api:admin-front-end-app) echo OK ;;
    *) echo BLOCKED ;;
  esac
}

delete_clients() {
  for c in ${CLIENTS}; do
    kubectl delete pod "tc-${c}" -n "${NS}" --ignore-not-found --grace-period=1 --wait=true >/dev/null 2>&1
  done
}
DETAILS_FILE="$(mktemp)"
trap 'delete_clients; rm -f "${DETAILS_FILE}"' EXIT

# Клиентские поды. Старые удаляем полностью, иначе можно попасть в под, который еще завершается.
delete_clients
for c in ${CLIENTS}; do
  role_label=""
  [ "${c}" != "none" ] && role_label="role: ${c}"
  kubectl apply -n "${NS}" -f - >/dev/null <<EOF || exit 2
apiVersion: v1
kind: Pod
metadata:
  name: tc-${c}
  labels:
    app: traffic-client
    ${role_label}
spec:
  restartPolicy: Never
  containers:
    - name: client
      image: alpine
      command: ["sleep", "900"]
      readinessProbe:
        exec:
          command: ["false"]
        periodSeconds: 3600
EOF
done
for c in ${CLIENTS}; do
  if ! kubectl wait --for=jsonpath='{.status.phase}'=Running "pod/tc-${c}" -n "${NS}" --timeout=180s >/dev/null; then
    echo "клиентский под tc-${c} не запустился" >&2
    exit 2
  fi
done

# Прогрев: ждем, пока сеть нового пода настроена (Calico) и работает DNS.
for c in ${CLIENTS}; do
  ready=0
  for _ in $(seq 1 30); do
    if kubectl exec -n "${NS}" "tc-${c}" -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 2
  done
  [ "${ready}" -eq 1 ] || echo "предупреждение: у tc-${c} не работает DNS" >&2
done

probe() {  # клиент сервис -> печатает OK или BLOCKED, причину отказа пишет в DETAILS_FILE
  # вызывается через $(...), то есть в подоболочке: переменные отсюда не вернуть, поэтому файл
  local out reason=""
  for _ in $(seq 1 "${ATTEMPTS}"); do
    out="$(kubectl exec -n "${NS}" "tc-$1" -- sh -c \
      "wget -q -O /dev/null -T 3 http://$2 2>&1 && echo RESULT:OK || echo RESULT:FAIL" 2>&1)"
    case "${out}" in
      *RESULT:OK*) echo OK; return ;;
      *RESULT:FAIL*) reason="$(printf '%s\n' "${out}" | grep -v RESULT | tail -1)" ;;
      *) reason="ошибка kubectl exec: $(printf '%s\n' "${out}" | tail -1)" ;;
    esac
    sleep 1
  done
  echo "  tc-$1 -> $2: ${reason:-нет ответа} (попыток: ${ATTEMPTS})" >> "${DETAILS_FILE}"
  echo BLOCKED
}

FAIL=0
MISMATCHES=""
printf '%-26s' "client \\ service"
for s in ${SERVICES}; do printf '%-24s' "${s}"; done
echo
for c in ${CLIENTS}; do
  if [ "${c}" = "none" ]; then printf '%-26s' "(no role label)"; else printf '%-26s' "role=${c}"; fi
  for s in ${SERVICES}; do
    got="$(probe "${c}" "${s}")"
    want="$(expected "${c}" "${s}")"
    if [ "${got}" = "${want}" ]; then
      printf '%-24s' "${got}"
    else
      printf '%-24s' "${got}!"
      FAIL=$((FAIL + 1))
      MISMATCHES="${MISMATCHES}  tc-${c} -> ${s}: получено ${got}, ожидалось ${want}
"
    fi
  done
  echo
done

echo
echo "Режим: ${MODE}. ! - расхождение с ожидаемым."
if [ -s "${DETAILS_FILE}" ]; then
  echo "Причины отказов:"
  cat "${DETAILS_FILE}"
fi
if [ "${FAIL}" -eq 0 ]; then
  echo "Итог: все 20 проверок совпали с ожидаемыми"
else
  echo "Итог: расхождений ${FAIL}"
  printf '%s' "${MISMATCHES}"
fi
[ "${FAIL}" -eq 0 ]
