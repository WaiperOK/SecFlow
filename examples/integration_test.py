#!/usr/bin/env python3
"""
Комплексный интеграционный тест PySecKit.
Демонстрирует все расширенные возможности фреймворка.
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Dict, Any
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Добавляем путь к проекту для импорта
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from pyseckit import (
        Config, ScannerManager, ReportManager,
        PluginRegistry, ElasticsearchIntegration,
        NotificationManager, AdvancedThreatModelGenerator
    )
    from pyseckit.web import create_app
    from pyseckit.core.exceptions import PySecKitException
except ImportError as e:
    logger.error(f"Ошибка импорта: {e}")
    logger.error("Убедитесь, что PySecKit установлен: pip install -e .")
    sys.exit(1)


class PySecKitIntegrationTest:
    """Класс для комплексного тестирования PySecKit."""
    
    def __init__(self):
        self.config = Config()
        self.test_results: Dict[str, Any] = {}
        self.passed_tests = 0
        self.failed_tests = 0
        
    def log_test_result(self, test_name: str, success: bool, error: str = None):
        """Логирует результат теста."""
        self.test_results[test_name] = {
            'success': success,
            'error': error
        }
        
        if success:
            self.passed_tests += 1
            logger.info(f"✅ {test_name}: ПРОЙДЕН")
        else:
            self.failed_tests += 1
            logger.error(f"❌ {test_name}: ПРОВАЛЕН - {error}")
    
    def test_basic_configuration(self) -> bool:
        """Тест базовой конфигурации."""
        try:
            # Проверяем загрузку конфигурации
            assert self.config is not None
            assert hasattr(self.config, 'project_name')
            
            # Проверяем настройки сканнеров
            scanners_config = self.config.get('scanners', {})
            assert isinstance(scanners_config, dict)
            
            return True
        except Exception as e:
            logger.error(f"Ошибка конфигурации: {e}")
            return False
    
    def test_scanner_manager(self) -> bool:
        """Тест менеджера сканнеров."""
        try:
            scanner_manager = ScannerManager(self.config)
            
            # Проверяем доступные сканнеры
            available_scanners = scanner_manager.get_available_scanners()
            assert len(available_scanners) > 0
            
            logger.info(f"Доступные сканнеры: {list(available_scanners.keys())}")
            
            # Проверяем создание сканнера
            if 'bandit' in available_scanners:
                bandit_scanner = scanner_manager.get_scanner('bandit')
                assert bandit_scanner is not None
            
            return True
        except Exception as e:
            logger.error(f"Ошибка менеджера сканнеров: {e}")
            return False
    
    def test_plugin_system(self) -> bool:
        """Тест системы плагинов."""
        try:
            plugin_registry = PluginRegistry()
            
            # Проверяем поиск плагинов
            plugin_registry.discover_plugins()
            
            # Получаем список плагинов
            plugins = plugin_registry.get_all_plugins()
            logger.info(f"Найденные плагины: {len(plugins)}")
            
            # Проверяем регистрацию плагина
            plugin_registry.register_plugin_class("test_plugin", type)
            
            return True
        except Exception as e:
            logger.error(f"Ошибка системы плагинов: {e}")
            return False
    
    def test_elasticsearch_integration(self) -> bool:
        """Тест интеграции с Elasticsearch."""
        try:
            # Создаем интеграцию без подключения к реальному ES
            es_config = {
                'enabled': False,  # Отключено для теста
                'hosts': ['localhost:9200'],
                'index_prefix': 'test_pyseckit'
            }
            
            es_integration = ElasticsearchIntegration(es_config)
            
            # Проверяем конфигурацию
            assert es_integration.config == es_config
            
            logger.info("Интеграция с Elasticsearch инициализирована")
            return True
        except Exception as e:
            logger.error(f"Ошибка интеграции Elasticsearch: {e}")
            return False
    
    def test_notification_system(self) -> bool:
        """Тест системы уведомлений."""
        try:
            # Конфигурация уведомлений (отключена для теста)
            notification_config = {
                'slack': {
                    'enabled': False,
                    'webhook_url': 'https://hooks.slack.com/test',
                    'channel': '#test'
                },
                'teams': {
                    'enabled': False,
                    'webhook_url': 'https://outlook.office.com/webhook/test'
                }
            }
            
            notification_manager = NotificationManager(notification_config)
            
            # Проверяем инициализацию
            assert notification_manager.config == notification_config
            
            logger.info("Система уведомлений инициализирована")
            return True
        except Exception as e:
            logger.error(f"Ошибка системы уведомлений: {e}")
            return False
    
    def test_threat_modeling(self) -> bool:
        """Тест продвинутого моделирования угроз."""
        try:
            # Создаем временную директорию для анализа
            test_dir = Path(__file__).parent
            
            threat_modeler = AdvancedThreatModelGenerator()
            
            # Анализируем текущую директорию
            assets = threat_modeler.analyze_codebase(str(test_dir))
            assert isinstance(assets, list)
            
            logger.info(f"Обнаружено активов: {len(assets)}")
            
            # Генерируем угрозы для первого актива (если есть)
            if assets:
                threats = threat_modeler.generate_threats_for_asset(assets[0])
                assert isinstance(threats, list)
                logger.info(f"Сгенерировано угроз: {len(threats)}")
            
            return True
        except Exception as e:
            logger.error(f"Ошибка моделирования угроз: {e}")
            return False
    
    def test_web_interface(self) -> bool:
        """Тест веб-интерфейса."""
        try:
            # Создаем приложение Flask
            app = create_app()
            
            # Проверяем создание приложения
            assert app is not None
            assert hasattr(app, 'config')
            
            # Проверяем тестовый клиент
            with app.test_client() as client:
                # Проверяем главную страницу
                response = client.get('/')
                assert response.status_code in [200, 302, 404]  # Может быть редирект
                
                # Проверяем API статус
                response = client.get('/api/status')
                if response.status_code == 200:
                    logger.info("API статус доступен")
            
            logger.info("Веб-интерфейс инициализирован")
            return True
        except Exception as e:
            logger.error(f"Ошибка веб-интерфейса: {e}")
            return False
    
    def test_report_generation(self) -> bool:
        """Тест генерации отчётов."""
        try:
            report_manager = ReportManager(self.config)
            
            # Создаем тестовые результаты сканирования
            test_results = {
                'scan_info': {
                    'timestamp': '2024-01-01T00:00:00',
                    'project_name': 'PySecKit Test',
                    'scanners_used': ['test_scanner']
                },
                'results': {
                    'test_scanner': {
                        'issues': [
                            {
                                'severity': 'high',
                                'title': 'Test Issue',
                                'description': 'Test vulnerability',
                                'file': 'test.py',
                                'line': 1
                            }
                        ],
                        'summary': {'total': 1, 'high': 1, 'medium': 0, 'low': 0}
                    }
                }
            }
            
            # Проверяем генерацию JSON отчёта
            json_report = report_manager.generate_json_report(test_results)
            assert isinstance(json_report, str)
            
            logger.info("Генерация отчётов работает")
            return True
        except Exception as e:
            logger.error(f"Ошибка генерации отчётов: {e}")
            return False
    
    def test_end_to_end_scan(self) -> bool:
        """Комплексный тест сканирования."""
        try:
            scanner_manager = ScannerManager(self.config)
            
            # Получаем доступные сканнеры
            available_scanners = scanner_manager.get_available_scanners()
            
            if not available_scanners:
                logger.warning("Нет доступных сканнеров для тестирования")
                return True
            
            # Выбираем первый доступный сканнер
            scanner_name = list(available_scanners.keys())[0]
            scanner = scanner_manager.get_scanner(scanner_name)
            
            # Создаем тестовый файл для сканирования
            test_file = Path(__file__).parent / "test_scan_target.py"
            test_file.write_text("""
# Тестовый файл для сканирования
import os
password = "hardcoded_password"  # Потенциальная уязвимость
""")
            
            try:
                # Запускаем сканирование
                result = scanner.scan(targets=[str(test_file)])
                assert result is not None
                
                logger.info(f"Сканирование {scanner_name} выполнено успешно")
                return True
            finally:
                # Удаляем тестовый файл
                if test_file.exists():
                    test_file.unlink()
            
        except Exception as e:
            logger.error(f"Ошибка комплексного сканирования: {e}")
            return False
    
    async def run_all_tests(self):
        """Запускает все тесты."""
        logger.info("🚀 Запуск комплексного интеграционного теста PySecKit")
        logger.info("=" * 60)
        
        # Список всех тестов
        tests = [
            ("Базовая конфигурация", self.test_basic_configuration),
            ("Менеджер сканнеров", self.test_scanner_manager),
            ("Система плагинов", self.test_plugin_system),
            ("Интеграция Elasticsearch", self.test_elasticsearch_integration),
            ("Система уведомлений", self.test_notification_system),
            ("Моделирование угроз", self.test_threat_modeling),
            ("Веб-интерфейс", self.test_web_interface),
            ("Генерация отчётов", self.test_report_generation),
            ("Комплексное сканирование", self.test_end_to_end_scan),
        ]
        
        # Выполняем тесты
        for test_name, test_func in tests:
            try:
                success = test_func()
                self.log_test_result(test_name, success)
            except Exception as e:
                self.log_test_result(test_name, False, str(e))
        
        # Выводим итоговый отчёт
        self.print_summary()
    
    def print_summary(self):
        """Выводит итоговый отчёт тестирования."""
        logger.info("=" * 60)
        logger.info("📊 ИТОГОВЫЙ ОТЧЁТ ТЕСТИРОВАНИЯ")
        logger.info("=" * 60)
        
        total_tests = self.passed_tests + self.failed_tests
        success_rate = (self.passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"Всего тестов: {total_tests}")
        logger.info(f"Пройдено: {self.passed_tests}")
        logger.info(f"Провалено: {self.failed_tests}")
        logger.info(f"Процент успеха: {success_rate:.1f}%")
        
        if self.failed_tests > 0:
            logger.info("\n❌ ПРОВАЛИВШИЕСЯ ТЕСТЫ:")
            for test_name, result in self.test_results.items():
                if not result['success']:
                    logger.error(f"  - {test_name}: {result['error']}")
        
        if success_rate >= 80:
            logger.info("\n🎉 ТЕСТИРОВАНИЕ УСПЕШНО ЗАВЕРШЕНО!")
            logger.info("PySecKit готов к использованию!")
        else:
            logger.warning("\n⚠️ ОБНАРУЖЕНЫ ПРОБЛЕМЫ")
            logger.warning("Рекомендуется исправить ошибки перед использованием")


async def main():
    """Главная функция для запуска тестов."""
    try:
        # Создаем и запускаем тесты
        test_runner = PySecKitIntegrationTest()
        await test_runner.run_all_tests()
        
        # Возвращаем код выхода
        return 0 if test_runner.failed_tests == 0 else 1
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Тестирование прервано пользователем")
        return 1
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    # Запускаем тесты
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 