#!/usr/bin/env bash
# Связывание групп пользователей с ролями из 02-create-roles.sh и проверка прав.
# Права выдаются группам (O в сертификате), а не отдельным людям: при переходе в другую команду
# достаточно перевыпустить сертификат с новой группой.
set -euo pipefail

# --- кластерные роли: ClusterRoleBinding -------------------------------------------------
bind_cluster() {  # имя-привязки роль группа
  kubectl create clusterrolebinding "$1" --clusterrole="$2" --group="$3" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label clusterrolebinding "$1" app.kubernetes.io/part-of=pd-rbac --overwrite >/dev/null
  echo "ClusterRoleBinding $1: $3 -> $2"
}

bind_cluster pd-platform-admins     cluster-admin        pd:platform-admins
bind_cluster pd-security-auditors   pd-security-auditor  pd:security
bind_cluster pd-platform-operators  pd-cluster-operator  pd:platform-engineers
bind_cluster pd-platform-viewers    pd-cluster-viewer    pd:platform-engineers
bind_cluster pd-viewers             pd-cluster-viewer    pd:viewers

# --- доменные роли: RoleBinding только в namespace домена ---------------------------------
# namespace|группа-команды
DOMAIN_NAMESPACES=(
  "sales|sales"
  "housing|housing"
  "smart-home|housing"
  "finance|finance"
  "data|data"
)

for entry in "${DOMAIN_NAMESPACES[@]}"; do
  ns="${entry%%|*}"
  team="${entry#*|}"
  for pair in "developer|developers" "deployer|devops"; do
    role="pd-domain-${pair%%|*}"
    group="pd:${team}-${pair#*|}"
    kubectl create rolebinding "${role}" --clusterrole="${role}" --group="${group}" -n "${ns}" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    echo "RoleBinding ${ns}/${role}: ${group} -> ${role}"
  done

  # сервисный аккаунт CI/CD: деплоит сервисы домена вместо людей
  kubectl create serviceaccount ci-deployer -n "${ns}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl create rolebinding ci-deployer --clusterrole=pd-domain-deployer \
    --serviceaccount="${ns}:ci-deployer" -n "${ns}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "RoleBinding ${ns}/ci-deployer: serviceaccount ${ns}:ci-deployer -> pd-domain-deployer"
done

# --- проверка ----------------------------------------------------------------------------
# kubectl auth can-i с подменой пользователя (--as/--as-group) работает от имени администратора.
echo
echo "Проверка прав (yes - разрешено, no - запрещено):"
check() {  # пользователь группа описание аргументы-can-i...
  local user="$1" group="$2" desc="$3"
  shift 3
  local res
  res="$(kubectl auth can-i "$@" --as="${user}" --as-group="${group}" 2>/dev/null || true)"
  printf '  %-4s %-16s %s\n' "${res}" "${user}" "${desc}"
}

check ops-engineer   pd:viewers               "смотреть поды во всех namespace"   list pods -A
check ops-engineer   pd:viewers               "читать секреты"                    get secrets -n housing
check ops-engineer   pd:viewers               "удалять поды"                      delete pods -n housing
check platform-devops pd:platform-engineers   "создавать namespace"               create namespaces
check platform-devops pd:platform-engineers   "менять узлы (cordon)"              patch nodes
check platform-devops pd:platform-engineers   "менять сетевые политики"           create networkpolicies -n sales
check platform-devops pd:platform-engineers   "читать секреты"                    get secrets -n kube-system
check platform-devops pd:platform-engineers   "создавать ClusterRoleBinding"      create clusterrolebindings
check ib-specialist  pd:security              "читать секреты в любом namespace"  get secrets -n kube-system
check ib-specialist  pd:security              "смотреть RBAC"                     list clusterrolebindings
check ib-specialist  pd:security              "менять секреты"                    update secrets -n housing
check housing-devops pd:housing-devops        "деплоить в housing"                create deployments -n housing
check housing-devops pd:housing-devops        "читать секреты housing"            get secrets -n housing
check housing-devops pd:housing-devops        "exec в поды housing"               create pods --subresource=exec -n housing
check housing-devops pd:housing-devops        "читать секреты finance"            get secrets -n finance
check housing-devops pd:housing-devops        "создавать RoleBinding"             create rolebindings -n housing
check housing-dev    pd:housing-developers    "смотреть логи в smart-home"        get pods --subresource=log -n smart-home
check housing-dev    pd:housing-developers    "читать секреты housing"            get secrets -n housing
check housing-dev    pd:housing-developers    "exec в поды housing"               create pods --subresource=exec -n housing
check sales-dev      pd:sales-developers      "смотреть поды sales"               list pods -n sales
check sales-dev      pd:sales-developers      "смотреть поды housing"             list pods -n housing
