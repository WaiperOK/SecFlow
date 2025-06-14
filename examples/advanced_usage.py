#!/usr/bin/env python3
"""
Пример расширенного использования PySecKit.

Демонстрирует:
- Интеграцию с Elasticsearch
- Систему уведомлений
- Автоматическое threat modeling
- Плагинную систему
- Веб-интерфейс
"""

import asyncio
from pathlib import Path
from datetime import datetime

from pyseckit.core.config import Config
from pyseckit.core.scanner import ScannerManager
from pyseckit.plugins.registry import plugin_registry
from pyseckit.plugins.scanner_plugin import CustomScannerExample
from pyseckit.integrations.elasticsearch_integration import ElasticsearchIntegration
from pyseckit.integrations.notifications import NotificationManager
from pyseckit.threat_model.advanced_generator import AdvancedThreatModelGenerator
from pyseckit.web.app import WebInterface


def main():
    """Демонстрация расширенных возможностей PySecKit."""
    print("🚀 PySecKit Advanced Usage Demo")
    print("=" * 50)
    
    # 1. Загружаем конфигурацию
    print("\n1️⃣ Загрузка конфигурации...")
    config = Config.from_file('.pyseckit.yml')
    print("✅ Конфигурация загружена")
    
    # 2. Регистрируем кастомный плагин
    print("\n2️⃣ Регистрация кастомного сканера...")
    
    # Регистрируем пример кастомного сканера
    plugin_registry.register_plugin(CustomScannerExample)
    
    # Инициализируем плагин с конфигурацией
    custom_scanner = plugin_registry.get_plugin('custom-scanner', {
        'patterns': [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
    })
    
    if custom_scanner:
        print("✅ Кастомный сканер зарегистрирован")
        print(f"   Название: {custom_scanner.metadata.name}")
        print(f"   Версия: {custom_scanner.metadata.version}")
    
    # 3. Настройка Elasticsearch интеграции
    print("\n3️⃣ Настройка Elasticsearch...")
    es_config = {
        'enabled': False,  # Изменить на True для реального использования
        'hosts': ['localhost:9200'],
        'index_prefix': 'pyseckit-demo'
    }
    
    es_integration = ElasticsearchIntegration(es_config)
    if es_integration.enabled:
        print("✅ Elasticsearch подключен")
    else:
        print("⚠️ Elasticsearch отключен (настройте в конфиге)")
    
    # 4. Настройка уведомлений
    print("\n4️⃣ Настройка уведомлений...")
    notification_config = {
        'slack': {
            'enabled': False,  # Изменить на True и настроить webhook
            'webhook_url': 'YOUR_SLACK_WEBHOOK_URL',
            'channel': '#security-alerts'
        },
        'teams': {
            'enabled': False,  # Изменить на True и настроить webhook
            'webhook_url': 'YOUR_TEAMS_WEBHOOK_URL'
        }
    }
    
    notification_manager = NotificationManager(notification_config)
    print(f"✅ Уведомления настроены ({len(notification_manager.notifiers)} каналов)")
    
    # 5. Запуск сканирования с интеграциями
    print("\n5️⃣ Запуск интегрированного сканирования...")
    
    scanner_manager = ScannerManager(config.get_scanners_config())
    target = "."
    
    # Запускаем кастомный сканер
    if custom_scanner:
        print(f"🔍 Запуск кастомного сканера для: {target}")
        result = custom_scanner.scan(target)
        
        if result:
            print(f"✅ Сканирование завершено. Найдено: {len(result.findings)} проблем")
            
            # Отправляем в Elasticsearch
            if es_integration.enabled:
                if es_integration.index_scan_result(result):
                    print("📊 Результаты отправлены в Elasticsearch")
                
                if es_integration.index_findings(result):
                    print("🔍 Находки проиндексированы")
            
            # Отправляем уведомления
            if result.findings:
                notification_results = notification_manager.send_scan_completed(result)
                for notifier, success in notification_results.items():
                    status = "✅" if success else "❌"
                    print(f"📢 {status} Уведомление {notifier}")
    
    # 6. Генерация модели угроз
    print("\n6️⃣ Генерация модели угроз...")
    
    threat_generator = AdvancedThreatModelGenerator()
    
    try:
        threat_model = threat_generator.analyze_codebase(target)
        
        print(f"✅ Модель угроз создана:")
        print(f"   📋 Активов: {len(threat_model.assets)}")
        print(f"   🔄 Потоков данных: {len(threat_model.data_flows)}")
        print(f"   ⚠️ Угроз: {len(threat_model.threats)}")
        
        # Сохраняем модель
        output_file = f"threat_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        threat_generator.export_to_json(threat_model, output_file)
        print(f"💾 Модель сохранена в: {output_file}")
        
        # Показываем топ-3 угрозы
        if threat_model.threats:
            print("\n🔥 Топ-3 угрозы:")
            for i, threat in enumerate(threat_model.threats[:3], 1):
                print(f"   {i}. {threat.title} (риск: {threat.risk_rating})")
                
    except Exception as e:
        print(f"❌ Ошибка создания модели угроз: {e}")
    
    # 7. Демонстрация плагинной системы
    print("\n7️⃣ Управление плагинами...")
    
    plugins = plugin_registry.list_plugins()
    print(f"📦 Доступно плагинов: {len(plugins)}")
    
    for plugin in plugins:
        status = "🟢" if plugin['initialized'] else "🟡"
        print(f"   {status} {plugin['name']} v{plugin['version']} ({plugin['category']})")
    
    # 8. Веб-интерфейс (демонстрация инициализации)
    print("\n8️⃣ Веб-интерфейс...")
    
    try:
        web_interface = WebInterface('.pyseckit.yml')
        system_status = web_interface.get_system_status()
        
        print("✅ Веб-интерфейс инициализирован")
        print(f"   🔧 Конфигурация: {'✅' if system_status['config_loaded'] else '❌'}")
        print(f"   📊 Elasticsearch: {'✅' if system_status['elasticsearch_enabled'] else '❌'}")
        print(f"   📢 Уведомления: {'✅' if system_status['notifications_enabled'] else '❌'}")
        print(f"   🔍 Сканеры: {system_status['scanners_available']}")
        print(f"   🔌 Плагины: {system_status['plugins_loaded']}")
        
        print("\n🌐 Для запуска веб-интерфейса выполните:")
        print("   pyseckit web --host 127.0.0.1 --port 5000")
        
    except Exception as e:
        print(f"❌ Ошибка инициализации веб-интерфейса: {e}")
    
    # 9. Демонстрация статистики
    print("\n9️⃣ Статистика и аналитика...")
    
    if es_integration.enabled:
        try:
            stats = es_integration.get_scan_statistics(days=7)
            if stats:
                print("📈 Статистика за неделю:")
                print(f"   📊 Всего сканирований: {stats.get('total_scans', 0)}")
                print(f"   🔍 Всего находок: {stats.get('total_findings', 0)}")
            else:
                print("📈 Статистика недоступна (нет данных)")
        except Exception as e:
            print(f"❌ Ошибка получения статистики: {e}")
    else:
        print("📈 Статистика недоступна (Elasticsearch отключен)")
    
    print("\n" + "=" * 50)
    print("🎉 Демонстрация завершена!")
    print("\nДля начала работы:")
    print("1. Настройте Elasticsearch в .pyseckit.yml")
    print("2. Добавьте webhook URL для уведомлений")
    print("3. Запустите веб-интерфейс: pyseckit web")
    print("4. Создайте кастомные плагины в папке plugins/")


def demo_custom_scanner():
    """Демонстрация создания кастомного сканера."""
    print("\n🔧 Создание кастомного сканера...")
    
    from pyseckit.plugins.scanner_plugin import ScannerPlugin
    from pyseckit.plugins.base import PluginMetadata
    from pyseckit.core.scanner import ScanResult
    from datetime import datetime
    
    class MyCustomScanner(ScannerPlugin):
        """Пример кастомного сканера."""
        
        @property
        def metadata(self):
            return PluginMetadata(
                name="my-custom-scanner",
                version="1.0.0", 
                description="Мой кастомный сканер безопасности",
                author="Developer",
                category="custom",
                config_schema={
                    "required": ["rules"],
                    "properties": {
                        "rules": {
                            "type": "array",
                            "description": "Правила сканирования"
                        }
                    }
                }
            )
        
        def initialize(self):
            """Инициализация сканера."""
            print(f"   Инициализация {self.metadata.name}")
            self._initialized = True
            return True
        
        def cleanup(self):
            """Очистка ресурсов."""
            self._initialized = False
        
        def scan(self, target):
            """Выполняет кастомное сканирование."""
            print(f"   Сканирование {target} с помощью {self.metadata.name}")
            
            # Простая демонстрация
            findings = [
                {
                    "severity": "MEDIUM",
                    "title": "Custom Security Issue",
                    "description": "Обнаружена потенциальная проблема безопасности",
                    "file": target,
                    "line": 1,
                    "rule_id": "CUSTOM-001"
                }
            ]
            
            return ScanResult(
                scanner_name=self.metadata.name,
                target=target,
                start_time=datetime.now(),
                end_time=datetime.now(),
                findings=findings,
                metadata={"custom": True}
            )
    
    # Регистрируем и тестируем
    config = {"rules": ["check_passwords", "check_keys"]}
    scanner = MyCustomScanner(config)
    
    if scanner.initialize():
        print("✅ Кастомный сканер инициализирован")
        
        # Тестируем сканирование
        result = scanner.scan("test_file.py")
        if result:
            print(f"✅ Тест прошел успешно. Найдено: {len(result.findings)} проблем")
        
        scanner.cleanup()


if __name__ == "__main__":
    main()
    demo_custom_scanner() 