# Задание 7. PodSecurity Admission и OPA Gatekeeper

Защита построена в два слоя:
1. **PodSecurity Admission** - встроенный admission-контроллер Kubernetes. На namespace `audit-zone` стоит профиль `restricted` в режимах `enforce`, `audit` и `warn`.
2. **OPA Gatekeeper** - собственные правила компании поверх стандартного профиля, с аудитом уже существующих ресурсов. Правила действуют в namespace с меткой `security.pd/gatekeeper=enforce`.

Если один слой отключат или ослабят (например, сменят метку PodSecurity), второй все равно не пропустит небезопасный под.

Ограничение: вебхук Gatekeeper по умолчанию установлен с `failurePolicy: Ignore`. Если Gatekeeper недоступен, запросы проходят без его проверки. Поэтому основной слой - PodSecurity (встроен в kube-apiserver), а доступность Gatekeeper нужно мониторить.

## Структура

| Файл | Назначение |
| --- | --- |
| `01-create-namespace.yaml` | Namespace `audit-zone`: PodSecurity `restricted` (enforce, audit, warn) и метка для Gatekeeper |
| `insecure-manifests/01-privileged-pod.yaml` | Под с `privileged: true` |
| `insecure-manifests/02-hostpath-pod.yaml` | Под с томом `hostPath: /` |
| `insecure-manifests/03-root-user-pod.yaml` | Под с `runAsUser: 0` |
| `secure-manifests/01-secure.yaml` | Исправленный 01: `nginxinc/nginx-unprivileged` (UID 101), без privileged |
| `secure-manifests/02-secure.yaml` | Исправленный 02: `emptyDir` вместо `hostPath` |
| `secure-manifests/03-secure.yaml` | Исправленный 03: UID 1000, `runAsNonRoot: true` |
| `gatekeeper/constraint-templates/privileged.yaml` | Шаблон `K8sPSPPrivilegedContainer`: запрет `privileged: true` (containers, initContainers, ephemeralContainers) |
| `gatekeeper/constraint-templates/hostpath.yaml` | Шаблон `K8sPSPHostPathVolume`: запрет томов `hostPath` |
| `gatekeeper/constraint-templates/runasnonroot.yaml` | Шаблон `K8sPSPRunAsNonRoot`: обязательные `runAsNonRoot: true` и `readOnlyRootFilesystem: true`, запрет `runAsUser: 0` |
| `gatekeeper/constraints/*.yaml` | Ограничения по шаблонам, `enforcementAction: deny` |
| `verify/verify-admission.sh` | Проверка admission: небезопасные поды отклоняются, безопасные проходят |
| `verify/validate-security.sh` | Проверка состояния: PodSecurity включен, Gatekeeper работает, у подов безопасный securityContext |
| `audit-policy.yaml` | Политика аудита: попытки создать поды (в том числе отклоненные) и попытки ослабить защиту |

Требование `readOnlyRootFilesystem: true` проверяется в шаблоне `runasnonroot.yaml`, чтобы сохранить структуру файлов из задания. Шаблон проверяет требования к пользователю и файловой системе контейнера.

## Как требования покрыты слоями

| Требование | PodSecurity `restricted` | Gatekeeper |
| --- | --- | --- |
| Нельзя `privileged: true` | да | `deny-privileged-containers` |
| Только `runAsNonRoot: true` | да | `require-nonroot-readonly-rootfs` |
| Запрет UID 0 | да | `require-nonroot-readonly-rootfs` |
| `readOnlyRootFilesystem: true` | **нет** (в профиль не входит) | `require-nonroot-readonly-rootfs` |
| `hostPath` запрещен | да | `deny-hostpath-volumes` |

`readOnlyRootFilesystem` закрывает только Gatekeeper, поэтому второй слой нужен не только для подстраховки.

## Запуск

```bash
# 1. Кластер (тот же, что в заданиях 4-6, или новый)
minikube start -p propdev

# 2. Namespace с PodSecurity restricted
kubectl apply -f 01-create-namespace.yaml

# 3. Небезопасные манифесты - должны быть отклонены PodSecurity
kubectl apply -f insecure-manifests/   # Error from server (Forbidden): ... violates PodSecurity "restricted:latest"

# 4. Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.23.1/deploy/gatekeeper.yaml
kubectl -n gatekeeper-system rollout status deploy/gatekeeper-controller-manager
kubectl -n gatekeeper-system rollout status deploy/gatekeeper-audit

kubectl apply -f gatekeeper/constraint-templates/
kubectl wait --for=condition=established --timeout=60s \
  crd/k8spspprivilegedcontainer.constraints.gatekeeper.sh \
  crd/k8spsphostpathvolume.constraints.gatekeeper.sh \
  crd/k8spsprunasnonroot.constraints.gatekeeper.sh
kubectl apply -f gatekeeper/constraints/

# 5. Проверки
bash verify/verify-admission.sh
bash verify/validate-security.sh
```

## Результат прогона

minikube v1.39.0, Kubernetes v1.37.0, Gatekeeper v3.23.1.

`verify/verify-admission.sh` - успешно 10, ошибок 0:

```text
1. Небезопасные манифесты в audit-zone (PodSecurity restricted + Gatekeeper)
  [OK]   01-privileged-pod.yaml: отклонен (PodSecurity)
           ... pods "pod-privileged" is forbidden: violates PodSecurity "restricted:latest": privileged (container "nginx" must not set securityContext.privileged=true), ...
  [OK]   02-hostpath-pod.yaml: отклонен (PodSecurity)
  [OK]   03-root-user-pod.yaml: отклонен (PodSecurity)

2. Те же манифесты в gatekeeper-check: PodSecurity выключен, работает только Gatekeeper
  [OK]   01-privileged-pod.yaml: отклонен (Gatekeeper)
           ... admission webhook "validation.gatekeeper.sh" denied the request: [deny-privileged-containers] контейнер nginx: privileged: true запрещен
           [require-nonroot-readonly-rootfs] контейнер nginx: требуется readOnlyRootFilesystem: true
           [require-nonroot-readonly-rootfs] контейнер nginx: требуется runAsNonRoot: true
  [OK]   02-hostpath-pod.yaml: отклонен (Gatekeeper)
           ... denied the request: [require-nonroot-readonly-rootfs] контейнер busybox: требуется readOnlyRootFilesystem: true
           [require-nonroot-readonly-rootfs] контейнер busybox: требуется runAsNonRoot: true
           [deny-hostpath-volumes] том host-root: hostPath (/) запрещен
  [OK]   03-root-user-pod.yaml: отклонен (Gatekeeper)
           ... denied the request: [require-nonroot-readonly-rootfs] контейнер busybox: запуск от root (runAsUser: 0) запрещен
           [require-nonroot-readonly-rootfs] контейнер busybox: требуется readOnlyRootFilesystem: true
           [require-nonroot-readonly-rootfs] контейнер busybox: требуется runAsNonRoot: true

3. Безопасные манифесты в audit-zone должны быть приняты и запущены
  [OK]   01-secure.yaml: принят (pod/pod-secure-nginx created)
  [OK]   02-secure.yaml: принят (pod/pod-secure-storage created)
  [OK]   03-secure.yaml: принят (pod/pod-secure-user created)
  [OK]   все безопасные поды в состоянии Ready
```

В разделе 1 срабатывает PodSecurity: встроенный admission-плагин проверяет запрос раньше вебхука Gatekeeper. Раздел 2 показывает, что Gatekeeper отклоняет те же поды и без PodSecurity.

`verify/validate-security.sh` - успешно 13, ошибок 0:

```text
1. PodSecurity Admission
  [OK]   audit-zone: enforce=restricted
  [OK]   admission-плагин PodSecurity отклоняет privileged-под
2. OPA Gatekeeper
  [OK]   gatekeeper-controller-manager: готовых реплик 3
  [OK]   gatekeeper-audit: готовых реплик 1
  [OK]   ConstraintTemplate k8spspprivilegedcontainer создан
  [OK]   ConstraintTemplate k8spsphostpathvolume создан
  [OK]   ConstraintTemplate k8spsprunasnonroot создан
  [OK]   k8spspprivilegedcontainer/deny-privileged-containers: enforcementAction=deny, применяется
  [OK]   k8spsphostpathvolume/deny-hostpath-volumes: enforcementAction=deny, применяется
  [OK]   k8spsprunasnonroot/require-nonroot-readonly-rootfs: enforcementAction=deny, применяется
3. Запущенные поды audit-zone
  [OK]   pod/pod-secure-nginx: Running, securityContext соответствует политике
  [OK]   pod/pod-secure-storage: Running, securityContext соответствует политике
  [OK]   pod/pod-secure-user: Running, securityContext соответствует политике
4. Нарушения, найденные аудитом Gatekeeper (существующие ресурсы)
CONSTRAINT                        ACTION   VIOLATIONS
deny-hostpath-volumes             deny     0
deny-privileged-containers        deny     0
require-nonroot-readonly-rootfs   deny     0
```

## Аудит

`audit-policy.yaml` подключается так же, как в задании 6 (`~/.minikube/files/etc/ssl/certs/` и `--extra-config=apiserver.audit-policy-file=...`). Для отклоненного пода в журнале будут:
- `requestObject` с запрошенным `securityContext`;
- `responseStatus.code: 403`;
- аннотации `pod-security.kubernetes.io/enforce-policy: restricted:latest` и `pod-security.kubernetes.io/audit-violations` с перечнем нарушений.

Отказы Gatekeeper видны по сообщению `validation.gatekeeper.sh` в `responseStatus`. Попытка ослабить защиту видна как изменение меток namespace или объектов `templates.gatekeeper.sh` / `constraints.gatekeeper.sh`.

## Как проверялось

- Весь сценарий из раздела "Запуск" выполнен на minikube v1.39.0 (Kubernetes v1.37.0), результат выше.
- Правила Gatekeeper дополнительно проверены утилитой `gator test` (v3.23.1) на граничных случаях: `runAsNonRoot` только на уровне пода - проходит; контейнер переопределяет `runAsNonRoot: false` - отклоняется; привилегированный initContainer - отклоняется; под в namespace без метки `security.pd/gatekeeper` - не проверяется.
- Записи политики аудита (`requestObject`, код 403, аннотации PodSecurity) проверены на kube-apiserver v1.31.
