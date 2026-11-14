# Задание 5. Сетевые политики

Решение - [non-admin-api-allow.yaml](non-admin-api-allow.yaml):
1. `default-deny-ingress` запрещает весь входящий трафик к подам namespace. Поэтому любой новый под по умолчанию изолирован от остальных.
2. Четыре разрешающие политики открывают трафик в обе стороны только внутри пар `front-end <-> back-end-api` и `admin-front-end <-> admin-back-end-api`.

## Запуск

```bash
# CNI с поддержкой NetworkPolicy (стандартный CNI minikube политики не применяет).
# Подойдет общий кластер из корневого README.
minikube start -p propdev --cni=calico

kubectl run front-end-app          --image=nginx --labels role=front-end          --expose --port 80
kubectl run back-end-api-app       --image=nginx --labels role=back-end-api       --expose --port 80
kubectl run admin-front-end-app    --image=nginx --labels role=admin-front-end    --expose --port 80
kubectl run admin-back-end-api-app --image=nginx --labels role=admin-back-end-api --expose --port 80

bash verify-traffic.sh open        # до политик: доступ есть отовсюду
kubectl apply -f non-admin-api-allow.yaml
bash verify-traffic.sh             # после политик: доступ только внутри пар
```

Ручная проверка, например из пода с ролью front-end:

```bash
kubectl run test-$RANDOM --rm -i -t --image=alpine --labels role=front-end -- sh
/ # wget -qO- --timeout=2 http://back-end-api-app         # ответ nginx
/ # wget -qO- --timeout=2 http://admin-back-end-api-app   # wget: download timed out
```

Временный под с меткой `role=front-end` подходит под селектор сервиса `front-end-app` и на время своей работы становится его endpoint. Запросы к другим сервисам это не затрагивает, но запрос к самому `front-end-app` может попасть в alpine, где порт 80 никто не слушает (`Connection refused`).

По той же причине у клиентских подов в `verify-traffic.sh` проверка готовности, которая никогда не проходит: неготовый под в endpoints сервиса не попадает, а команды в нем выполнять можно. Скрипт создает по клиенту на каждую роль и один без метки, из каждого запрашивает все четыре сервиса и сравнивает результат с ожидаемым.

## Результат прогона

minikube v1.39.0, Kubernetes v1.37.0, Calico.

До применения политик:

```text
client \ service          front-end-app           back-end-api-app        admin-front-end-app     admin-back-end-api-app
role=front-end            OK                      OK                      OK                      OK
role=back-end-api         OK                      OK                      OK                      OK
role=admin-front-end      OK                      OK                      OK                      OK
role=admin-back-end-api   OK                      OK                      OK                      OK
(no role label)           OK                      OK                      OK                      OK

Итог: все 20 проверок совпали с ожидаемыми
```

После `kubectl apply -f non-admin-api-allow.yaml`:

```text
client \ service          front-end-app           back-end-api-app        admin-front-end-app     admin-back-end-api-app
role=front-end            BLOCKED                 OK                      BLOCKED                 BLOCKED
role=back-end-api         OK                      BLOCKED                 BLOCKED                 BLOCKED
role=admin-front-end      BLOCKED                 BLOCKED                 BLOCKED                 OK
role=admin-back-end-api   BLOCKED                 BLOCKED                 OK                      BLOCKED
(no role label)           BLOCKED                 BLOCKED                 BLOCKED                 BLOCKED

Итог: все 20 проверок совпали с ожидаемыми
```

Во всех случаях BLOCKED причина одна: `wget: download timed out`. Calico отбрасывает пакеты, и соединение не устанавливается.
