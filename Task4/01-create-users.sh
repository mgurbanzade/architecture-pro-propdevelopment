#!/usr/bin/env bash
# Создание пользователей кластера по клиентским сертификатам.
# Имя пользователя - CN сертификата, группа - O. Группы потом связываются с ролями (03-bind-roles.sh).
# Сертификат подписывает сам кластер через CertificateSigningRequest API.
# Запускать под администратором кластера (текущий контекст kubectl).
set -euo pipefail

CERT_DIR="${CERT_DIR:-$(dirname "$0")/certs}"
CERT_TTL_SECONDS="${CERT_TTL_SECONDS:-7776000}"   # 90 дней

# пользователь|группа
USERS=(
  "platform-devops|pd:platform-engineers"   # DevOps-инженер платформенной команды: настраивает кластер
  "ib-specialist|pd:security"               # специалист по ИБ: привилегированный просмотр, включая секреты
  "ops-engineer|pd:viewers"                 # инженер по эксплуатации: только просмотр
  "housing-devops|pd:housing-devops"        # DevOps-инженер команды ЖКУ: деплой и секреты в namespace ЖКУ
  "housing-dev|pd:housing-developers"       # разработчик команды ЖКУ: просмотр и логи в namespace ЖКУ
  "sales-dev|pd:sales-developers"           # разработчик команды продаж: просмотр и логи в namespace продаж
)

CLUSTER="$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')"
echo "Кластер: ${CLUSTER}"
mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

for entry in "${USERS[@]}"; do
  user="${entry%%|*}"
  group="${entry#*|}"
  echo "==> ${user} (группа ${group})"

  openssl genrsa -out "${CERT_DIR}/${user}.key" 2048 2>/dev/null
  chmod 600 "${CERT_DIR}/${user}.key"
  openssl req -new -key "${CERT_DIR}/${user}.key" -out "${CERT_DIR}/${user}.csr" -subj "/CN=${user}/O=${group}"

  kubectl delete csr "${user}" --ignore-not-found >/dev/null
  cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${user}
spec:
  request: $(base64 < "${CERT_DIR}/${user}.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: ${CERT_TTL_SECONDS}
  usages: ["client auth"]
EOF
  kubectl certificate approve "${user}" >/dev/null

  cert=""
  for _ in $(seq 1 20); do
    cert="$(kubectl get csr "${user}" -o jsonpath='{.status.certificate}')"
    [ -n "${cert}" ] && break
    sleep 1
  done
  if [ -z "${cert}" ]; then
    echo "Сертификат для ${user} не выпущен" >&2
    exit 1
  fi
  printf '%s' "${cert}" | base64 --decode > "${CERT_DIR}/${user}.crt"

  kubectl config set-credentials "${user}" \
    --client-certificate="${CERT_DIR}/${user}.crt" \
    --client-key="${CERT_DIR}/${user}.key" \
    --embed-certs=true >/dev/null
  kubectl config set-context "${user}@${CLUSTER}" --cluster="${CLUSTER}" --user="${user}" >/dev/null
  kubectl delete csr "${user}" >/dev/null
  echo "    контекст ${user}@${CLUSTER} добавлен в kubeconfig"
done

echo
echo "Готово. Пока роли не привязаны, у пользователей нет прав, например:"
echo "  kubectl --context=ops-engineer@${CLUSTER} get pods -A   # Forbidden"
