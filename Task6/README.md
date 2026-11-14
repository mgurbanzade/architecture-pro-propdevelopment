# Задание 6. Аудит активности пользователей

| Файл | Что это |
| --- | --- |
| [analysis.md](analysis.md) | Отчет по выявленным событиям |
| [audit-extract.json](audit-extract.json) | Выжимка подозрительных событий из audit.log, без значений секретов |
| [filter-audit.py](filter-audit.py) | Скрипт фильтрации audit.log (Python 3, без зависимостей) |
| [audit-policy.yaml](audit-policy.yaml) | Политика аудита. Политика из задания исправлена: с ней kube-apiserver не стартует, подробности в комментариях файла |
| [simulate-incident.sh](simulate-incident.sh) | Скрипт симуляции из задания, без изменений |

## Как получен журнал

В minikube нельзя править `kube-apiserver.yaml` внутри узла: файл генерируется заново. Поэтому политика кладется на хосте в `~/.minikube/files/etc/ssl/certs/`. minikube копирует ее на узел, а каталог `/etc/ssl/certs` уже смонтирован в контейнер kube-apiserver.

Каталог `/var/log` узла в контейнер kube-apiserver не смонтирован, и все смонтированные каталоги доступны только на чтение. Поэтому записать журнал в файл на узле без правки манифеста нельзя. Журнал пишется в stdout kube-apiserver (`audit-log-path=-`) и выгружается в файл `audit.log`.

```bash
mkdir -p ~/.minikube/files/etc/ssl/certs
cp audit-policy.yaml ~/.minikube/files/etc/ssl/certs/audit-policy.yaml

# отдельный профиль, чтобы не трогать существующий кластер minikube
minikube start -p propdev --cni=calico \
  --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml \
  --extra-config=apiserver.audit-log-path=-

START=$(date -u +%Y-%m-%dT%H:%M:%SZ)      # начало симуляции
bash simulate-incident.sh
kubectl config set-context --current --namespace=default   # скрипт переключает namespace

kubectl logs -n kube-system -l component=kube-apiserver --tail=-1 | grep '"kind":"Event"' > audit.log
python3 filter-audit.py audit.log --since "$START" -o audit-extract.json
```

`--since` отсекает события запуска кластера: при старте minikube сам создает привязки к `cluster-admin` и системные поды, и без фильтра они попадают в выжимку.

Сам `audit.log` в репозиторий не кладется (`.gitignore`): в нем есть служебные данные кластера.

## Самопроверка из задания

```bash
jq 'select(.objectRef.resource=="secrets" and (.verb=="get" or .verb=="list"))' audit.log
jq 'select((.verb=="create" or .verb=="get") and .objectRef.subresource=="exec")' audit.log
jq 'select(.objectRef.resource=="pods" and .requestObject.spec.containers[]?.securityContext.privileged==true)' audit.log
jq 'select(.objectRef.resource=="rolebindings" and .requestObject.roleRef.name=="cluster-admin")' audit.log
grep -i 'audit-policy' audit.log
```

Отличия от команд в задании:
- секреты запрашиваются через `list`, а не `get`: в Kubernetes 1.24+ нет секретов `default-token-*`, и имя секрета в скрипте получается пустым;
- у exec verb зависит от версии kubectl: `get` при подключении по WebSocket (kubectl 1.31+), `create` при SPDY. При прогоне с kubectl 1.36 записан `get` с кодом 101;
- проверка привилегированных подов находит еще поды `kube-proxy` и `calico-node` (их создает `daemon-set-controller` при старте кластера): это штатные системные компоненты, `filter-audit.py` их действия пропускает;
- `grep audit-policy` находит только описание пода kube-apiserver с аргументом `--audit-policy-file`, событий удаления политики нет (подробнее в отчете).

## Результат прогона

minikube v1.39.0, Kubernetes v1.37.0, kubectl v1.36.1 (macOS). В журнале 1892 записи, после начала сценария завершено 135 запросов, подозрительных записей 7:

```text
[critical] privileged-pod  09:22:34.208  minikube-user создает под secure-ops/privileged-pod с опасными настройками: pwn: privileged: true (успешно)
[critical] pod-exec        09:22:34.290  minikube-user: exec в под kube-system/coredns-559f6c778d-2xvfk (успешно)
[critical] rbac-binding    09:22:34.351  minikube-user привязывает роль cluster-admin через rolebinding secure-ops/escalate-binding (успешно)
[high    ] secrets-access  09:22:34.122  minikube-user читает секреты системного namespace kube-system (успешно)
[high    ] secrets-access  09:22:34.153  сервисный аккаунт system:serviceaccount:secure-ops:monitoring запрашивает секреты в kube-system (отказ 403)
[medium  ] impersonation   09:22:34.090  minikube-user выполняет create selfsubjectaccessreviews от имени system:serviceaccount:secure-ops:monitoring (успешно)
[medium  ] impersonation   09:22:34.153  minikube-user выполняет list secrets от имени system:serviceaccount:secure-ops:monitoring (отказ 403)
```

"Успешно" у exec означает, что API разрешил подключение к поду. Сама команда `cat` в поде CoreDNS не выполнилась: в образе ее нет. Аудит этого не показывает, разбор - в [analysis.md](analysis.md).
