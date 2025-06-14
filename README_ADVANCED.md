# PySecKit - Расширенные возможности

## 🚀 Обзор расширенной функциональности

PySecKit был расширен следующими enterprise-возможностями:

### 🔌 Система плагинов
- **Расширяемая архитектура** для добавления новых сканнеров
- **Автоматическое обнаружение** плагинов в настраиваемых директориях
- **Метаданные плагинов** с версионированием и зависимостями
- **Простой API** для создания кастомных сканнеров

### 📊 Интеграция с Elasticsearch/Kibana
- **Централизованное хранение** результатов сканирования
- **Автоматическое создание индексов** с оптимизированными mappings
- **Поиск и агрегация** данных о безопасности
- **Готовые дашборды Kibana** для визуализации

### 📬 Система уведомлений
- **Slack интеграция** с богатым форматированием
- **Microsoft Teams** поддержка
- **Email уведомления** с HTML шаблонами
- **Настраиваемые триггеры** для различных событий

### 🛡️ Продвинутое моделирование угроз
- **Автоматический анализ** кодовой базы
- **STRIDE модель** для категоризации угроз
- **Генерация диаграм** потоков данных
- **Рекомендации по миtigации** для каждой угрозы

### 🌐 Веб-интерфейс управления
- **Интерактивный dashboard** с метриками безопасности
- **REST API** для интеграции с внешними системами
- **Управление сканнерами** через веб-интерфейс
- **Визуализация результатов** с графиками и отчётами

## 📋 Быстрый старт с расширенными возможностями

### 1. Установка зависимостей

```bash
# Установка с расширенными зависимостями
pip install -e .[dev,cloud,enterprise]

# Или установка всех зависимостей
pip install -r requirements-full.txt
```

### 2. Настройка конфигурации

Обновите `.pyseckit.yml` для включения расширенных функций:

```yaml
# Elasticsearch интеграция
integrations:
  elasticsearch:
    enabled: true
    hosts: ["localhost:9200"]
    username: "elastic"
    password: "password"
    index_prefix: "pyseckit"
    
  # Уведомления
  notifications:
    slack:
      enabled: true
      webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
      channel: "#security"
    
    teams:
      enabled: true
      webhook_url: "https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK"

# Система плагинов
plugins:
  discovery_paths:
    - "./plugins"
    - "~/.pyseckit/plugins"

# Веб-интерфейс
web:
  enabled: true
  host: "0.0.0.0"
  port: 5000

# Threat modeling
threat_modeling:
  auto_generate: true
  output_formats: ["json", "yaml"]
  include_mitigations: true
```

### 3. Запуск веб-интерфейса

```bash
# Запуск веб-интерфейса
pyseckit web

# Открываете браузер на http://localhost:5000
```

### 4. Использование расширенных функций

```python
#!/usr/bin/env python3
"""Пример использования расширенных возможностей PySecKit."""

import asyncio
from pyseckit import (
    Config, ScannerManager, 
    PluginRegistry, ElasticsearchIntegration,
    NotificationManager, AdvancedThreatModelGenerator
)

async def advanced_security_scan():
    """Расширенное сканирование с всеми возможностями."""
    
    # Загружаем конфигурацию
    config = Config()
    
    # 1. Загружаем плагины
    plugin_registry = PluginRegistry()
    plugin_registry.discover_plugins()
    print(f"Загружено плагинов: {len(plugin_registry.get_all_plugins())}")
    
    # 2. Настраиваем Elasticsearch
    es_integration = ElasticsearchIntegration(config.get('integrations.elasticsearch'))
    if es_integration.is_enabled():
        await es_integration.create_indices()
    
    # 3. Настраиваем уведомления
    notification_manager = NotificationManager(config.get('integrations.notifications'))
    
    # 4. Запускаем сканирование
    scanner_manager = ScannerManager(config)
    results = await scanner_manager.run_all_scanners(["."])
    
    # 5. Сохраняем в Elasticsearch
    if es_integration.is_enabled():
        await es_integration.index_scan_results(results)
    
    # 6. Отправляем уведомления
    await notification_manager.send_scan_completion_notification(results)
    
    # 7. Генерируем модель угроз
    threat_modeler = AdvancedThreatModelGenerator()
    threat_model = threat_modeler.generate_comprehensive_model(".")
    
    print("🎉 Расширенное сканирование завершено!")
    print(f"📊 Результаты сохранены в Elasticsearch")
    print(f"📬 Уведомления отправлены")
    print(f"🛡️ Модель угроз сгенерирована")

if __name__ == "__main__":
    asyncio.run(advanced_security_scan())
```

## 🔌 Создание кастомных плагинов

### Базовый плагин-сканнер

```python
from pyseckit.plugins import ScannerPlugin, PluginMetadata
from pyseckit.core.scanner import ScanResult

class CustomPatternScanner(ScannerPlugin):
    """Кастомный сканнер для поиска паттернов."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom-pattern-scanner",
            version="1.0.0",
            description="Сканнер для поиска кастомных паттернов",
            author="Your Name",
            dependencies=["re", "pathlib"]
        )
    
    def scan(self, targets, **kwargs) -> ScanResult:
        """Выполняет сканирование."""
        issues = []
        
        # Ваша логика сканирования
        patterns = [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']"
        ]
        
        for target in targets:
            # Сканируем файлы на наличие паттернов
            issues.extend(self._scan_file(target, patterns))
        
        return ScanResult(
            scanner_name=self.get_metadata().name,
            issues=issues,
            summary=self._create_summary(issues)
        )
    
    def _scan_file(self, filepath, patterns):
        """Сканирует отдельный файл."""
        # Реализация сканирования файла
        pass
    
    def _create_summary(self, issues):
        """Создаёт сводку по результатам."""
        # Подсчёт по критичности
        pass
```

### Регистрация плагина

```python
# В файле plugins/my_plugin.py
from pyseckit.plugins import PluginRegistry

# Регистрируем плагин
registry = PluginRegistry()
registry.register_plugin_class("custom-pattern-scanner", CustomPatternScanner)
```

## 📊 Elasticsearch и Kibana

### Настройка индексов

```python
from pyseckit.integrations import ElasticsearchIntegration

# Настройка подключения
es_config = {
    'enabled': True,
    'hosts': ['localhost:9200'],
    'username': 'elastic',
    'password': 'password',
    'ssl': True,
    'verify_certs': True,
    'index_prefix': 'pyseckit'
}

es_integration = ElasticsearchIntegration(es_config)

# Создание индексов
await es_integration.create_indices()

# Индексация результатов
await es_integration.index_scan_results(scan_results)

# Поиск уязвимостей
vulnerabilities = await es_integration.search_findings(
    query={"severity": "high"},
    size=100
)
```

### Kibana дашборды

PySecKit автоматически создаёт индексы, оптимизированные для Kibana:

- **pyseckit-scans** - информация о сканированиях
- **pyseckit-findings** - найденные уязвимости
- **pyseckit-metrics** - метрики безопасности

## 📬 Система уведомлений

### Slack интеграция

```python
from pyseckit.integrations import SlackNotifier

slack_config = {
    'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
    'channel': '#security',
    'username': 'PySecKit',
    'icon_emoji': ':shield:'
}

notifier = SlackNotifier(slack_config)

# Отправка уведомления о завершении сканирования
await notifier.send_scan_completion({
    'project': 'my-project',
    'critical_issues': 2,
    'high_issues': 5,
    'total_issues': 20
})

# Уведомление о критической уязвимости
await notifier.send_critical_finding({
    'title': 'SQL Injection Found',
    'severity': 'critical',
    'file': 'app.py',
    'line': 156
})
```

### Microsoft Teams

```python
from pyseckit.integrations import TeamsNotifier

teams_config = {
    'webhook_url': 'https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK'
}

notifier = TeamsNotifier(teams_config)
await notifier.send_scan_completion(scan_data)
```

## 🛡️ Продвинутое моделирование угроз

### Автоматическая генерация

```python
from pyseckit.threat_model import AdvancedThreatModelGenerator

# Создание генератора
threat_modeler = AdvancedThreatModelGenerator()

# Анализ кодовой базы
assets = threat_modeler.analyze_codebase("./src")

# Генерация угроз по модели STRIDE
for asset in assets:
    threats = threat_modeler.generate_threats_for_asset(asset)
    for threat in threats:
        print(f"Угроза: {threat['description']}")
        print(f"Митигация: {threat['mitigation']}")

# Экспорт модели угроз
threat_model = threat_modeler.generate_comprehensive_model(".")
threat_modeler.export_to_json(threat_model, "threat_model.json")
threat_modeler.export_to_yaml(threat_model, "threat_model.yaml")
```

### STRIDE категории

- **Spoofing** - подмена личности
- **Tampering** - несанкционированное изменение
- **Repudiation** - отказ от совершённых действий
- **Information Disclosure** - раскрытие информации
- **Denial of Service** - отказ в обслуживании
- **Elevation of Privilege** - повышение привилегий

## 🌐 Веб-интерфейс и API

### Запуск веб-сервера

```bash
# Стандартный запуск
pyseckit web

# С кастомными параметрами
pyseckit web --host 0.0.0.0 --port 8080 --debug

# В production режиме
pyseckit web --host 0.0.0.0 --port 80 --workers 4
```

### REST API endpoints

| Метод | Endpoint | Описание |
|-------|----------|----------|
| GET | `/api/status` | Статус системы |
| POST | `/api/scan` | Запуск сканирования |
| GET | `/api/scans` | Список сканирований |
| GET | `/api/scans/{id}` | Детали сканирования |
| GET | `/api/results/{id}` | Результаты сканирования |
| POST | `/api/threat-model` | Генерация модели угроз |
| GET | `/api/plugins` | Список плагинов |
| GET | `/api/metrics` | Метрики безопасности |

### Примеры API запросов

```bash
# Получение статуса
curl http://localhost:5000/api/status

# Запуск сканирования
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["."], "scanners": ["bandit", "semgrep"]}'

# Получение результатов
curl http://localhost:5000/api/results/scan_123
```

## 🔧 CLI расширения

### Новые команды

```bash
# Управление веб-интерфейсом
pyseckit web                    # Запуск веб-сервера
pyseckit web --port 8080        # На порту 8080

# Работа с плагинами
pyseckit plugins list           # Список плагинов
pyseckit plugins install <name> # Установка плагина
pyseckit plugins remove <name>  # Удаление плагина

# Моделирование угроз
pyseckit threat-model generate  # Генерация модели
pyseckit threat-model export    # Экспорт в файл

# Тестирование уведомлений
pyseckit test-notifications     # Тест всех каналов
pyseckit test-slack            # Тест Slack
pyseckit test-teams            # Тест Teams
```

## 🐳 Docker поддержка

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Установка зависимостей
COPY requirements.txt .
RUN pip install -r requirements.txt

# Копирование кода
COPY . .
RUN pip install -e .

# Настройка портов
EXPOSE 5000

# Запуск веб-интерфейса
CMD ["pyseckit", "web", "--host", "0.0.0.0", "--port", "5000"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  pyseckit:
    build: .
    ports:
      - "5000:5000"
    environment:
      - PYSECKIT_CONFIG=/app/.pyseckit.yml
    volumes:
      - ./reports:/app/reports
      - ./.pyseckit.yml:/app/.pyseckit.yml
    depends_on:
      - elasticsearch
      
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
      
  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  es_data:
```

## 🚀 Примеры использования

Смотрите директорию `examples/` для подробных примеров:

- `examples/quickstart_advanced.py` - быстрый старт с расширенными возможностями
- `examples/advanced_usage.py` - продвинутые сценарии использования
- `examples/integration_test.py` - комплексный тест всех компонентов
- `examples/complete_demo.py` - полная демонстрация возможностей
- `examples/system_check.py` - проверка работоспособности системы

## 📚 Дополнительная документация

- [Архитектура плагинов](docs/plugins.md)
- [Интеграция с Elasticsearch](docs/elasticsearch.md)
- [Настройка уведомлений](docs/notifications.md)
- [Моделирование угроз](docs/threat-modeling.md)
- [Веб-API документация](docs/web-api.md)
- [Развёртывание в продакшене](docs/deployment.md)

## 🤝 Участие в разработке

Мы приветствуем участие в развитии PySecKit! 

### Как внести вклад:

1. Fork репозитория
2. Создайте feature branch
3. Внесите изменения
4. Добавьте тесты
5. Создайте Pull Request

### Разработка плагинов

Документация по созданию плагинов: [docs/plugin-development.md](docs/plugin-development.md)

## 📄 Лицензия

MIT License - подробности в файле [LICENSE](LICENSE)

## 🆘 Поддержка

- 📧 Email: support@pyseckit.org
- 💬 Slack: [PySecKit Community](https://pyseckit.slack.com)
- 🐛 Issues: [GitHub Issues](https://github.com/pyseckit/pyseckit/issues)
- 📖 Документация: [docs.pyseckit.org](https://docs.pyseckit.org)

---

**PySecKit** - Ваш надёжный партнёр в области DevSecOps! 🛡️ 