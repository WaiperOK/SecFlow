#!/usr/bin/env python3
"""
Полная демонстрация возможностей PySecKit.
Показывает использование всех расширенных функций фреймворка.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import logging

# Настройка красивого логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from pyseckit import (
        Config, ScannerManager, ReportManager,
        PluginRegistry, ElasticsearchIntegration,
        NotificationManager, AdvancedThreatModelGenerator
    )
    from pyseckit.web import create_app
    from pyseckit.integrations import SlackNotifier, TeamsNotifier
    from pyseckit.plugins import ScannerPlugin
except ImportError as e:
    logger.error(f"❌ Ошибка импорта PySecKit: {e}")
    logger.error("📦 Установите PySecKit: pip install -e .")
    sys.exit(1)


class PySecKitDemo:
    """Демонстрационный класс для showcasing PySecKit."""
    
    def __init__(self):
        self.config = Config()
        self.demo_results: Dict[str, Any] = {}
        
    def print_header(self, title: str, char: str = "="):
        """Красивый заголовок."""
        width = 70
        logger.info(char * width)
        logger.info(f"{title:^{width}}")
        logger.info(char * width)
    
    def print_section(self, title: str):
        """Заголовок секции."""
        logger.info(f"\n🔸 {title}")
        logger.info("-" * (len(title) + 3))
    
    def demo_basic_scanning(self):
        """Демонстрация базового сканирования."""
        self.print_section("Базовое сканирование")
        
        try:
            # Создаем менеджер сканнеров
            scanner_manager = ScannerManager(self.config.dict())
            
            # Получаем список доступных сканнеров
            available_scanners = scanner_manager.get_available_scanners()
            logger.info(f"📋 Доступные сканнеры: {list(available_scanners.keys())}")
            
            # Создаем тестовый файл с уязвимостями
            test_file = Path("demo_vulnerable.py")
            test_content = '''
import os
import subprocess

# Потенциальные уязвимости для демонстрации
password = "hardcoded_password123"  # Hard-coded password
api_key = "sk-1234567890abcdef"     # API key in code

def unsafe_eval(user_input):
    return eval(user_input)  # Code injection

def shell_command(filename):
    os.system(f"cat {filename}")  # Shell injection

# SQL injection example
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''
            test_file.write_text(test_content)
            
            try:
                logger.info("📋 Доступные сканнеры для демонстрации:")
                if available_scanners:
                    for name, scanner in available_scanners.items():
                        logger.info(f"   • {name}: {scanner.__class__.__name__}")
                else:
                    logger.info("   • Пока нет зарегистрированных сканнеров")
                
                logger.info("💡 В продакшене здесь будут доступны:")
                logger.info("   • Bandit - статический анализ Python")
                logger.info("   • Semgrep - мультиязычный анализ")
                logger.info("   • Safety - проверка зависимостей")
                logger.info("   • OWASP ZAP - динамическое тестирование")
                logger.info("   • GitLeaks - поиск секретов")
                logger.info("   • Checkov - анализ IaC")
                
                logger.info("✅ Создан тестовый файл с примерами уязвимостей")
                logger.info("✅ Система готова к сканированию")
            
            finally:
                # Удаляем тестовый файл
                if test_file.exists():
                    test_file.unlink()
                    
        except Exception as e:
            logger.error(f"❌ Ошибка базового сканирования: {e}")
    
    def demo_plugin_system(self):
        """Демонстрация системы плагинов."""
        self.print_section("Система плагинов")
        
        try:
            # Создаем реестр плагинов
            plugin_registry = PluginRegistry()
            
            # Поиск и загрузка плагинов
            logger.info("🔍 Поиск плагинов...")
            plugin_registry.discover_plugins()
            
            # Получаем список плагинов
            plugins = plugin_registry.get_all_plugins()
            logger.info(f"📦 Найдено плагинов: {len(plugins)}")
            
            # Создаем пример кастомного плагина
            class DemoScanner(ScannerPlugin):
                """Демонстрационный сканер-плагин."""
                
                def get_metadata(self):
                    from pyseckit.plugins.base import PluginMetadata
                    return PluginMetadata(
                        name="demo-scanner",
                        version="1.0.0",
                        description="Демонстрационный сканер",
                        author="PySecKit Demo"
                    )
                
                def scan(self, targets, **kwargs):
                    from pyseckit.core.scanner import ScanResult
                    # Простая имитация сканирования
                    return ScanResult(
                        scanner_name="demo-scanner",
                        issues=[],
                        summary={'total': 0, 'high': 0, 'medium': 0, 'low': 0}
                    )
            
            # Регистрируем кастомный плагин
            plugin_registry.register_plugin_class("demo-scanner", DemoScanner)
            logger.info("✅ Кастомный плагин зарегистрирован")
            
            # Получаем обновленный список
            updated_plugins = plugin_registry.get_all_plugins()
            logger.info(f"📦 Всего плагинов после регистрации: {len(updated_plugins)}")
            
        except Exception as e:
            logger.error(f"❌ Ошибка системы плагинов: {e}")
    
    def demo_elasticsearch_integration(self):
        """Демонстрация интеграции с Elasticsearch."""
        self.print_section("Интеграция с Elasticsearch")
        
        try:
            # Конфигурация для демонстрации
            es_config = {
                'enabled': False,  # Отключено для демо
                'hosts': ['localhost:9200'],
                'username': 'elastic',
                'password': 'password',
                'index_prefix': 'pyseckit-demo',
                'ssl': False,
                'verify_certs': True
            }
            
            # Создаем интеграцию
            es_integration = ElasticsearchIntegration(es_config)
            logger.info("📊 Elasticsearch интеграция инициализирована")
            
            # Демонстрация структуры данных для индексации
            sample_scan_result = {
                'timestamp': '2024-01-01T12:00:00Z',
                'project': 'demo-project',
                'scanner': 'bandit',
                'findings': [
                    {
                        'severity': 'high',
                        'title': 'Hard-coded password',
                        'description': 'Password found in source code',
                        'file': 'app.py',
                        'line': 15,
                        'confidence': 'high'
                    }
                ],
                'summary': {'total': 1, 'high': 1, 'medium': 0, 'low': 0}
            }
            
            logger.info("📋 Пример данных для индексации:")
            logger.info(f"   - Проект: {sample_scan_result['project']}")
            logger.info(f"   - Сканер: {sample_scan_result['scanner']}")
            logger.info(f"   - Найдено проблем: {sample_scan_result['summary']['total']}")
            
            # Если бы Elasticsearch был включен:
            logger.info("💡 В продакшене данные будут автоматически индексированы")
            logger.info("💡 Доступны поиск, агрегация и дашборды Kibana")
            
        except Exception as e:
            logger.error(f"❌ Ошибка интеграции Elasticsearch: {e}")
    
    def demo_notifications(self):
        """Демонстрация системы уведомлений."""
        self.print_section("Система уведомлений")
        
        try:
            # Конфигурация уведомлений
            notification_config = {
                'slack': {
                    'enabled': False,  # Отключено для демо
                    'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
                    'channel': '#security-alerts',
                    'username': 'PySecKit',
                    'icon_emoji': ':shield:'
                },
                'teams': {
                    'enabled': False,  # Отключено для демо
                    'webhook_url': 'https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK'
                },
                'email': {
                    'enabled': False,  # Отключено для демо
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': 'your-email@gmail.com',
                    'password': 'your-app-password',
                    'from_email': 'security@yourcompany.com',
                    'to_emails': ['admin@yourcompany.com'],
                    'use_tls': True
                }
            }
            
            # Создаем менеджер уведомлений
            notification_manager = NotificationManager(notification_config)
            logger.info("📬 Менеджер уведомлений инициализирован")
            
            # Демонстрация типов уведомлений
            logger.info("📋 Доступные типы уведомлений:")
            logger.info("   • Slack - уведомления в каналы Slack")
            logger.info("   • Microsoft Teams - уведомления в каналы Teams")
            logger.info("   • Email - email уведомления")
            
            # Пример данных для уведомления
            scan_data = {
                'project': 'demo-project',
                'timestamp': '2024-01-01T12:00:00Z',
                'critical_issues': 2,
                'high_issues': 5,
                'total_issues': 15,
                'scanners': ['bandit', 'semgrep', 'safety']
            }
            
            logger.info("📊 Пример уведомления о завершении сканирования:")
            logger.info(f"   - Проект: {scan_data['project']}")
            logger.info(f"   - Критические: {scan_data['critical_issues']}")
            logger.info(f"   - Высокие: {scan_data['high_issues']}")
            logger.info(f"   - Всего: {scan_data['total_issues']}")
            
            # В продакшене уведомления будут отправлены:
            logger.info("💡 В продакшене уведомления будут отправлены во все настроенные каналы")
            
        except Exception as e:
            logger.error(f"❌ Ошибка системы уведомлений: {e}")
    
    def demo_threat_modeling(self):
        """Демонстрация продвинутого моделирования угроз."""
        self.print_section("Продвинутое моделирование угроз")
        
        try:
            # Создаем генератор моделей угроз
            threat_modeler = AdvancedThreatModelGenerator()
            logger.info("🛡️ Генератор моделей угроз инициализирован")
            
            # Анализируем текущую директорию проекта
            project_dir = Path(__file__).parent.parent
            logger.info(f"🔍 Анализ проекта: {project_dir}")
            
            # Анализируем активы в кодовой базе
            assets = threat_modeler.analyze_codebase(str(project_dir))
            logger.info(f"📦 Обнаружено активов: {len(assets)}")
            
            # Показываем несколько найденных активов
            for i, asset in enumerate(assets[:3]):
                logger.info(f"   {i+1}. {asset.get('name', 'Unknown')} ({asset.get('type', 'unknown')})")
            
            # Генерируем угрозы для первого актива
            if assets:
                first_asset = assets[0]
                logger.info(f"🎯 Генерация угроз для актива: {first_asset.get('name', 'Unknown')}")
                
                threats = threat_modeler.generate_threats_for_asset(first_asset)
                logger.info(f"⚠️ Сгенерировано угроз: {len(threats)}")
                
                # Показываем несколько угроз
                for i, threat in enumerate(threats[:3]):
                    threat_type = threat.get('category', 'Unknown')
                    description = threat.get('description', 'No description')[:60] + "..."
                    logger.info(f"   {i+1}. [{threat_type}] {description}")
            
            # Демонстрация возможностей экспорта
            logger.info("📄 Доступные форматы экспорта:")
            logger.info("   • JSON - структурированные данные")
            logger.info("   • YAML - человекочитаемый формат")
            logger.info("   • Диаграммы потоков данных")
            logger.info("   • Отчёты с рекомендациями по миtigации")
            
        except Exception as e:
            logger.error(f"❌ Ошибка моделирования угроз: {e}")
    
    def demo_web_interface(self):
        """Демонстрация веб-интерфейса."""
        self.print_section("Веб-интерфейс управления")
        
        try:
            # Создаем Flask приложение
            app = create_app()
            logger.info("🌐 Веб-приложение создано")
            
            # Информация о веб-интерфейсе
            logger.info("📋 Возможности веб-интерфейса:")
            logger.info("   • Dashboard с общей статистикой безопасности")
            logger.info("   • Управление сканерами и настройками")
            logger.info("   • Просмотр результатов сканирования")
            logger.info("   • Интерактивные отчёты и графики")
            logger.info("   • REST API для интеграций")
            
            # Демонстрация API endpoints
            logger.info("🔌 Основные API endpoints:")
            logger.info("   • GET  /api/status - статус системы")
            logger.info("   • POST /api/scan - запуск сканирования")
            logger.info("   • GET  /api/scans - список сканирований")
            logger.info("   • GET  /api/results/{scan_id} - результаты")
            logger.info("   • POST /api/threat-model - генерация модели угроз")
            
            # Тестируем базовые маршруты
            with app.test_client() as client:
                # Проверяем статус API
                response = client.get('/api/status')
                if response.status_code == 200:
                    logger.info("✅ API статус: доступен")
                else:
                    logger.info(f"⚠️ API статус: {response.status_code}")
            
            logger.info("💡 Запустите веб-интерфейс: pyseckit web --host 0.0.0.0 --port 5000")
            
        except Exception as e:
            logger.error(f"❌ Ошибка веб-интерфейса: {e}")
    
    def demo_report_generation(self):
        """Демонстрация генерации отчётов."""
        self.print_section("Генерация отчётов")
        
        try:
            # Создаем менеджер отчётов
            report_manager = ReportManager(self.config)
            logger.info("📊 Менеджер отчётов инициализирован")
            
            # Создаем тестовые данные сканирования
            sample_results = {
                'scan_info': {
                    'timestamp': '2024-01-01T12:00:00Z',
                    'project_name': 'PySecKit Demo Project',
                    'target_directories': ['.'],
                    'scanners_used': ['bandit', 'semgrep', 'safety'],
                    'duration': 45.6
                },
                'results': {
                    'bandit': {
                        'issues': [
                            {
                                'severity': 'high',
                                'title': 'Hardcoded password string',
                                'description': 'Password found in source code',
                                'file': 'app.py',
                                'line': 15,
                                'confidence': 'high',
                                'cwe': 'CWE-259'
                            },
                            {
                                'severity': 'medium',
                                'title': 'Use of eval',
                                'description': 'Use of eval detected',
                                'file': 'utils.py',
                                'line': 42,
                                'confidence': 'high',
                                'cwe': 'CWE-95'
                            }
                        ],
                        'summary': {'total': 2, 'high': 1, 'medium': 1, 'low': 0}
                    },
                    'semgrep': {
                        'issues': [
                            {
                                'severity': 'high',
                                'title': 'SQL injection vulnerability',
                                'description': 'Potential SQL injection',
                                'file': 'database.py',
                                'line': 78,
                                'confidence': 'medium'
                            }
                        ],
                        'summary': {'total': 1, 'high': 1, 'medium': 0, 'low': 0}
                    },
                    'safety': {
                        'issues': [
                            {
                                'severity': 'medium',
                                'title': 'Vulnerable dependency',
                                'description': 'requests 2.25.0 has known vulnerabilities',
                                'package': 'requests',
                                'version': '2.25.0',
                                'cve': 'CVE-2023-32681'
                            }
                        ],
                        'summary': {'total': 1, 'high': 0, 'medium': 1, 'low': 0}
                    }
                }
            }
            
            logger.info("📋 Обработка результатов сканирования:")
            total_issues = sum(
                result['summary']['total'] 
                for result in sample_results['results'].values()
            )
            logger.info(f"   • Всего проблем найдено: {total_issues}")
            logger.info(f"   • Использовано сканнеров: {len(sample_results['results'])}")
            
            # Генерируем JSON отчёт
            json_report = report_manager.generate_json_report(sample_results)
            logger.info("✅ JSON отчёт сгенерирован")
            
            # Информация о доступных форматах
            logger.info("📄 Доступные форматы отчётов:")
            logger.info("   • JSON - структурированные данные для API")
            logger.info("   • HTML - интерактивные веб-отчёты")
            logger.info("   • CSV - табличные данные для анализа")
            logger.info("   • PDF - печатные отчёты (требует доп. настройки)")
            
            # Демонстрация группировки и фильтрации
            logger.info("🔍 Возможности анализа:")
            logger.info("   • Группировка по критичности")
            logger.info("   • Фильтрация по типам уязвимостей")
            logger.info("   • Трендовый анализ по времени")
            logger.info("   • Сравнение между проектами")
            
        except Exception as e:
            logger.error(f"❌ Ошибка генерации отчётов: {e}")
    
    def demo_cicd_integration(self):
        """Демонстрация CI/CD интеграции."""
        self.print_section("CI/CD интеграция")
        
        try:
            logger.info("🚀 Возможности CI/CD интеграции:")
            logger.info("   • GitHub Actions - автоматическое сканирование PR")
            logger.info("   • GitLab CI - интеграция в пайплайны")
            logger.info("   • Jenkins - плагин для Jenkins")
            logger.info("   • Azure DevOps - расширение для Azure")
            logger.info("   • Любые CI/CD через Docker или CLI")
            
            # Пример GitHub Actions workflow
            logger.info("\n📋 Пример GitHub Actions workflow:")
            github_workflow = '''
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    - name: Install PySecKit
      run: pip install pyseckit
    - name: Run Security Scan
      run: pyseckit scan --fail-on-high --output-format json
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-results
        path: reports/
'''
            logger.info("   (см. .github/workflows/security.yml)")
            
            # Пример настроек fail conditions
            logger.info("\n⚙️ Настройки условий провала:")
            logger.info("   • --fail-on-critical - провал при критических проблемах")
            logger.info("   • --fail-on-high - провал при высоких проблемах")
            logger.info("   • --max-issues 10 - максимум проблем для прохождения")
            
            # Интеграция с системами трекинга
            logger.info("\n🎫 Интеграция с системами трекинга:")
            logger.info("   • Jira - автоматическое создание задач")
            logger.info("   • GitHub Issues - создание issues")
            logger.info("   • ServiceNow - интеграция с ITSM")
            
        except Exception as e:
            logger.error(f"❌ Ошибка демонстрации CI/CD: {e}")
    
    async def run_complete_demo(self):
        """Запускает полную демонстрацию."""
        self.print_header("🛡️ ПОЛНАЯ ДЕМОНСТРАЦИЯ PYSECKIT 🛡️")
        
        logger.info("Добро пожаловать в интерактивную демонстрацию PySecKit!")
        logger.info("Фреймворк для интеграции безопасности в DevSecOps процессы")
        
        # Выполняем демонстрацию базового сканирования
        self.demo_basic_scanning()
        
        # Заключение
        self.print_header("🎉 DEMO ЗАВЕРШЕНО 🎉", "=")
        logger.info("✨ Спасибо за внимание к PySecKit!")
        logger.info("")
        logger.info("📚 Дополнительные ресурсы:")
        logger.info("   • Документация: https://pyseckit.readthedocs.io")
        logger.info("   • GitHub: https://github.com/pyseckit/pyseckit")
        logger.info("   • Примеры: ./examples/")
        logger.info("")
        logger.info("🚀 Быстрый старт:")
        logger.info("   pip install pyseckit")
        logger.info("   pyseckit init")
        logger.info("   pyseckit scan")
        logger.info("")
        logger.info("🌟 Начните использовать PySecKit уже сегодня!")


async def main():
    """Главная функция демонстрации."""
    try:
        demo = PySecKitDemo()
        await demo.run_complete_demo()
        return 0
    except KeyboardInterrupt:
        logger.info("\n⚠️ Демонстрация прервана пользователем")
        return 1
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    # Запускаем демонстрацию
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 