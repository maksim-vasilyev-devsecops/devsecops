## Установка Falco в Kubernetes (Helm)
Добавляем репозиторий
```shell
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Установка Falco:
```shell
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.jsonOutput=true \
  --set falco.logLevel=info
```

Проверка:
```shell
kubectl get pods -n falco
```

## Добавление Falco rule: чтение /proc/1/environ
custom-rule-environ.yaml
```yaml
- rule: Read proc 1 environ after process start
  desc: >
    Detects read access to /proc/1/environ inside a container.
    Indicates possible secrets harvesting or post-exploitation.
  condition: >
    container
    and evt.type in (open, openat)
    and fd.name = "/proc/1/environ"
    and evt.is_open_read = true
  output: >
    RUNTIME ALERT: /proc/1/environ read detected
    user=%user.name
    command=%proc.cmdline
    container=%container.name
    image=%container.image.repository
    namespace=%k8s.ns.name
    pod=%k8s.pod.name
  priority: CRITICAL
  tags: [container, procfs, secrets, rce]
```

Подключаем rule к Falco:
```bash
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --set-file rulesFile[0]=custom-rule-environ.yaml
```

Проверка:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco
```


Просмотр алерта:
```shell
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep environ
```