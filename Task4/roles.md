# Ролевая модель доступа к Kubernetes

## Из чего исходит модель

- **Структура компании.** Четыре домена (продажи, ЖКУ, финансы, данные), в каждом продуктовые команды: владелец продукта, бизнес-аналитики, разработчики, инженеры по эксплуатации, DevOps-инженер. Специалист по ИБ один на компанию. У каждого домена свой namespace, у ЖКУ дополнительно `smart-home` для сервисов из задания 3. Платформенные компоненты (API-шлюз, Vault) - в `integration`.
- **Выводы заданий 1-3.** Нарушен контроль доступа к данным, секреты интеграций хранятся без единых политик, решения не доходят до ИБ. Поэтому секреты видят только ИБ и DevOps своего домена, изменения RBAC делают только администраторы, специалист по ИБ видит все, но ничего не меняет.
- **Минимальные привилегии.** Права выдаются группам. Доменные роли действуют только в namespace домена через RoleBinding. Ролей с `*` в verbs нет.
- **Аутентификация.** В скриптах пользователи создаются по клиентским сертификатам: это работает в пустом minikube без внешних систем. У сертификатов есть недостаток: их нельзя отозвать до истечения срока, поэтому срок ограничен 90 днями. В рабочем кластере вход нужно перевести на OIDC через корпоративный Keycloak с MFA. Группы `pd:*` тогда приходят из каталога, а роли и привязки остаются теми же.

## Роли

| Роль | Права роли | Группы пользователей |
| --- | --- | --- |
| `cluster-admin` (встроенная ClusterRole, ClusterRoleBinding) | Полный доступ ко всем ресурсам кластера, включая RBAC, секреты и admission-вебхуки. **Привилегированная.** Используется только для аварийных работ и изменения RBAC по заявке, все действия в аудит-логе | `pd:platform-admins` - 1-2 ведущих инженера платформенной команды |
| `pd-security-auditor` (ClusterRole, ClusterRoleBinding) | Чтение во всех namespace: **секреты**, configmaps, serviceaccounts, поды, RBAC (roles, rolebindings, clusterroles, clusterrolebindings), сетевые политики, admission-вебхуки, CSR, ограничения Gatekeeper. Изменять ничего нельзя. **Привилегированная:** просмотр секретов | `pd:security` - специалист по ИБ |
| `pd-cluster-operator` (ClusterRole, ClusterRoleBinding) | **Настройка кластера:** создание и изменение namespace, cordon/drain узлов (patch nodes, pods/eviction), PersistentVolume, StorageClass, квоты и LimitRange, сетевые политики, IngressClass, PriorityClass, CRD. Нет доступа к секретам, RBAC, вебхукам и exec в поды, чтобы роль нельзя было использовать для повышения привилегий | `pd:platform-engineers` - DevOps-инженеры платформенной команды. Получают еще и `pd-cluster-viewer` |
| `pd-cluster-viewer` (ClusterRole, ClusterRoleBinding) | **Только просмотр** во всех namespace: поды и их логи, deployments, statefulsets, daemonsets, jobs, сервисы, ingress, configmaps, PVC, PV, узлы, namespace, события, квоты, HPA, метрики. **Секреты не видны.** Изменять ничего нельзя | `pd:viewers` - инженеры по эксплуатации всех доменов. По заявке владельцы продуктов и бизнес-аналитики, которым нужно видеть состояние сервисов. `pd:platform-engineers` |
| `pd-domain-deployer` (ClusterRole, RoleBinding в namespace домена) | В своем namespace: создание, изменение и удаление deployments, statefulsets, jobs, cronjobs, сервисов, ingress, HPA, PDB, configmaps, PVC; удаление подов; **управление секретами**; exec и port-forward в поды. Сетевые политики только на чтение, RBAC и квоты недоступны. **Привилегированная в пределах домена:** секреты и exec | `pd:<домен>-devops` - DevOps-инженер функциональной команды домена (`pd:sales-devops`, `pd:housing-devops`, `pd:finance-devops`, `pd:data-devops`). Сервисный аккаунт `ci-deployer` в каждом доменном namespace - для CI/CD |
| `pd-domain-developer` (ClusterRole, RoleBinding в namespace домена) | В своем namespace только просмотр: поды и логи, deployments, statefulsets, jobs, сервисы, ingress, сетевые политики, configmaps, события, HPA. Секретов и exec нет. Деплой идет через CI/CD, а не руками | `pd:<домен>-developers` - разработчики функциональной команды домена (`pd:sales-developers`, `pd:housing-developers` и т. д.) |

Кому доступ к кластеру не нужен: менеджерам операционных команд и бухгалтерам. Они работают с бизнес-приложениями, а не с инфраструктурой.

## Соответствие требованиям задания

| Требование | Как выполнено |
| --- | --- |
| Привилегированные действия (просмотр секретов) - только определенным группам | Секреты видят `pd:security` (все namespace, только чтение), `pd:<домен>-devops` (только свой namespace), `pd:platform-admins` |
| Группа только для просмотра | `pd:viewers` -> `pd-cluster-viewer` |
| Группа, которая настраивает кластер | `pd:platform-engineers` -> `pd-cluster-operator` + `pd-cluster-viewer` |
| Разграничение по оргструктуре | Доменные роли выдаются через RoleBinding только в namespace своего домена. Разработчик ЖКУ не видит namespace продаж |

## Скрипты

| Файл | Что делает |
| --- | --- |
| `01-create-users.sh` | Создает 6 пользователей: ключ, CSR, подпись через Kubernetes CSR API (срок 90 дней), контекст в kubeconfig. Группа задается полем O сертификата |
| `02-create-roles.sh` | Создает namespace доменов (с метками `pd/domain` и PodSecurity) и ClusterRole из таблицы |
| `03-bind-roles.sh` | Создает ClusterRoleBinding и RoleBinding для групп, сервисные аккаунты `ci-deployer` и печатает проверку прав через `kubectl auth can-i` |

Тестовые пользователи:

| Пользователь | Группа | Кто это |
| --- | --- | --- |
| `platform-devops` | `pd:platform-engineers` | DevOps-инженер платформенной команды |
| `ib-specialist` | `pd:security` | Специалист по ИБ |
| `ops-engineer` | `pd:viewers` | Инженер по эксплуатации |
| `housing-devops` | `pd:housing-devops` | DevOps-инженер команды ЖКУ |
| `housing-dev` | `pd:housing-developers` | Разработчик команды ЖКУ |
| `sales-dev` | `pd:sales-developers` | Разработчик команды продаж |

### Запуск

```bash
minikube start -p propdev        # или общий кластер из корневого README
bash 01-create-users.sh
bash 02-create-roles.sh
bash 03-bind-roles.sh
```

Закрытые ключи пользователей сохраняются в `Task4/certs/` и в репозиторий не попадают (`.gitignore`).

Проверка от имени пользователя:

```bash
kubectl --context=ops-engineer@propdev get pods -A                 # можно
kubectl --context=ops-engineer@propdev get secrets -n kube-system  # Forbidden
kubectl --context=housing-devops@propdev get secrets -n housing    # можно
kubectl --context=housing-devops@propdev get secrets -n finance    # Forbidden
```

Результат прогона на minikube v1.39.0 (Kubernetes v1.37.0). Проверка из `03-bind-roles.sh`:

```text
  yes  ops-engineer     смотреть поды во всех namespace
  no   ops-engineer     читать секреты
  no   ops-engineer     удалять поды
  yes  platform-devops  создавать namespace
  yes  platform-devops  менять узлы (cordon)
  yes  platform-devops  менять сетевые политики
  no   platform-devops  читать секреты
  no   platform-devops  создавать ClusterRoleBinding
  yes  ib-specialist    читать секреты в любом namespace
  yes  ib-specialist    смотреть RBAC
  no   ib-specialist    менять секреты
  yes  housing-devops   деплоить в housing
  yes  housing-devops   читать секреты housing
  yes  housing-devops   exec в поды housing
  no   housing-devops   читать секреты finance
  no   housing-devops   создавать RoleBinding
  yes  housing-dev      смотреть логи в smart-home
  no   housing-dev      читать секреты housing
  no   housing-dev      exec в поды housing
  yes  sales-dev        смотреть поды sales
  no   sales-dev        смотреть поды housing
```

Запросы по сертификатам пользователей, без подмены через `--as`:

```text
$ kubectl --context=ops-engineer@propdev get secrets -n kube-system
Error from server (Forbidden): secrets is forbidden: User "ops-engineer" cannot list resource "secrets" in API group "" in the namespace "kube-system"

$ kubectl --context=ib-specialist@propdev get secrets -n kube-system
NAME                     TYPE                            DATA   AGE
bootstrap-token-7dqk9c   bootstrap.kubernetes.io/token   6      58s

$ kubectl --context=housing-devops@propdev get secrets -n finance
Error from server (Forbidden): secrets is forbidden: User "housing-devops" cannot list resource "secrets" in API group "" in the namespace "finance"

$ kubectl --context=platform-devops@propdev get nodes
NAME      STATUS   ROLES           AGE   VERSION
propdev   Ready    control-plane   59s   v1.37.0

$ kubectl --context=sales-dev@propdev get pods -n housing
Error from server (Forbidden): pods is forbidden: User "sales-dev" cannot list resource "pods" in API group "" in the namespace "housing"
```
