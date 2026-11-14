# architecture-pro-propdevelopment

Проектная работа 5-го спринта: подготовка PropDevelopment к комплексному аудиту безопасности. Классификация данных, проверочный лист, безопасные внешние интеграции, защита кластера Kubernetes.

| Задание | Что внутри |
| :- | :- |
| [Task1](Task1) | Mindmap "Безопасность данных": 4 категории по ISO/IEC 27001/27002, данные компании, риски с оценкой и обоснованием (draw.io + PNG) |
| [Task2](Task2/security-checklist.md) | Проверочный лист для бизнес-систем: обзор систем, обоснование выбора разделов, заполненная таблица, главные выводы |
| [Task3](Task3/integration-requirements.md) | "Умный дом" (домофон и шлагбаум): C4 Context (PlantUML), обновленная C4 Container (draw.io), требования к безопасности, протоколы, схема взаимодействия |
| [Task4](Task4/roles.md) | Ролевая модель Kubernetes: таблица ролей, скрипты создания пользователей, ролей и привязок |
| [Task5](Task5) | Сетевые политики: default deny и разрешение трафика только в парах front-end/back-end |
| [Task6](Task6/analysis.md) | Аудит: исправленная audit-policy, скрипт фильтрации audit.log, выжимка и отчет |
| [Task7](Task7/README_FOR_REVIEWER.md) | PodSecurity `restricted` + OPA Gatekeeper, небезопасные и исправленные манифесты, скрипты проверки |

## Окружение для заданий 4-7

Один кластер minikube подходит для всех заданий: Calico нужен для сетевых политик, флаги аудита - для задания 6. Кластер создается в отдельном профиле `propdev`, чтобы не трогать уже существующий кластер minikube.

```bash
mkdir -p ~/.minikube/files/etc/ssl/certs
cp Task6/audit-policy.yaml ~/.minikube/files/etc/ssl/certs/audit-policy.yaml

minikube start -p propdev --cni=calico \
  --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml \
  --extra-config=apiserver.audit-log-path=-
```

Задания 4-7 проверены на minikube v1.39.0 (Kubernetes v1.37.0, Calico, Gatekeeper v3.23.1), результаты прогона - в README заданий.

После запуска текущим контекстом kubectl становится `propdev`. Порядок запуска описан в README каждого задания. Удалить кластер после проверки: `minikube delete -p propdev`.
