#!/usr/bin/env bash
# Создание namespace по доменам компании и ролей RBAC из таблицы roles.md.
# Кластерные роли (pd-cluster-*, pd-security-auditor) действуют во всем кластере.
# Доменные роли (pd-domain-*) описаны как ClusterRole один раз, а выдаются через RoleBinding
# только в namespace своего домена (03-bind-roles.sh).
set -euo pipefail

# namespace|домен
NAMESPACES=(
  "sales|sales"            # группа сервисов для продаж
  "housing|housing"        # группа сервисов ЖКУ
  "smart-home|housing"     # сервисы "Умный дом" (задание 3), команда ЖКУ
  "finance|finance"        # финансы
  "data|data"              # хранилище, BI, отчетность
  "integration|platform"   # API-шлюз внешних интеграций и Vault (задание 3), платформенная команда
)

for entry in "${NAMESPACES[@]}"; do
  ns="${entry%%|*}"
  domain="${entry#*|}"
  kubectl create namespace "${ns}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "${ns}" --overwrite \
    pd/domain="${domain}" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/warn=restricted >/dev/null
  echo "namespace ${ns} (домен ${domain})"
done

kubectl apply -f - <<'EOF'
# Только просмотр ресурсов кластера. Секретов нет.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pd-cluster-viewer
  labels: {app.kubernetes.io/part-of: pd-rbac}
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "services", "endpoints", "configmaps", "persistentvolumeclaims",
              "persistentvolumes", "nodes", "namespaces", "events", "resourcequotas", "limitranges",
              "serviceaccounts", "replicationcontrollers"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses", "ingressclasses", "networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods", "nodes"]
  verbs: ["get", "list"]
---
# Настройка кластера: namespace, узлы, хранилища, квоты, сетевые политики.
# Права на просмотр эта группа получает отдельно, через pd-cluster-viewer.
# Нет доступа к секретам, RBAC, admission-вебхукам и exec в поды - это закрывает пути повышения привилегий.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pd-cluster-operator
  labels: {app.kubernetes.io/part-of: pd-rbac}
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["persistentvolumes", "resourcequotas", "limitranges"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses", "volumeattachments", "csidrivers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingressclasses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["scheduling.k8s.io"]
  resources: ["priorityclasses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
---
# Привилегированный просмотр для ИБ: секреты, RBAC, политики безопасности, вебхуки, аудит изменений.
# Только чтение - изменения вносят администраторы по заявке.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pd-security-auditor
  labels: {app.kubernetes.io/part-of: pd-rbac}
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps", "serviceaccounts", "pods", "services", "namespaces", "nodes", "events",
              "endpoints", "persistentvolumes", "persistentvolumeclaims"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations",
              "validatingadmissionpolicies", "validatingadmissionpolicybindings"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps", "batch"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["templates.gatekeeper.sh", "constraints.gatekeeper.sh"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
---
# Разработчик домена: просмотр своих сервисов и логов. Деплой - через CI/CD, секретов и exec нет.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pd-domain-developer
  labels: {app.kubernetes.io/part-of: pd-rbac}
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "services", "endpoints", "configmaps", "events", "persistentvolumeclaims"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses", "networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch"]
---
# DevOps-инженер домена: деплой и управление секретами своего домена.
# Привилегированная роль: секреты и exec разрешены только в namespace домена, все действия пишутся в аудит.
# RBAC, сетевые политики и квоты менять нельзя.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pd-domain-deployer
  labels: {app.kubernetes.io/part-of: pd-rbac}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch", "delete"]
- apiGroups: [""]
  resources: ["pods/log", "events", "endpoints", "serviceaccounts"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/exec", "pods/portforward"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["services", "configmaps", "persistentvolumeclaims", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments/scale", "statefulsets/scale"]
  verbs: ["update", "patch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF

echo
kubectl get clusterroles -l app.kubernetes.io/part-of=pd-rbac
