#!/usr/bin/env python3
"""
Скрипт для проверки работоспособности PySecKit.
Проверяет все основные компоненты системы.
"""

import sys
import os
from pathlib import Path
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent.parent))

def check_imports():
    """Проверяет импорты основных модулей."""
    logger.info("🔍 Проверка импортов...")
    
    checks = [
        ("Основные модули", ["pyseckit"]),
        ("Конфигурация", ["pyseckit.core.config"]),
        ("Сканнеры", ["pyseckit.core.scanner"]),
        ("Отчёты", ["pyseckit.reporting.manager"]),
        ("Плагины", ["pyseckit.plugins"]),
        ("Интеграции", ["pyseckit.integrations"]),
        ("Веб-интерфейс", ["pyseckit.web"]),
        ("Моделирование угроз", ["pyseckit.threat_model"]),
    ]
    
    success_count = 0
    total_count = len(checks)
    
    for check_name, modules in checks:
        try:
            for module in modules:
                __import__(module)
            logger.info(f"✅ {check_name}: OK")
            success_count += 1
        except ImportError as e:
            logger.error(f"❌ {check_name}: ОШИБКА - {e}")
        except Exception as e:
            logger.error(f"❌ {check_name}: НЕОЖИДАННАЯ ОШИБКА - {e}")
    
    return success_count, total_count

def check_configuration():
    """Проверяет загрузку конфигурации."""
    logger.info("⚙️ Проверка конфигурации...")
    
    try:
        from pyseckit.core.config import Config
        config = Config()
        
        # Проверяем основные параметры
        if hasattr(config, 'project_name'):
            logger.info("✅ Конфигурация: загружена успешно")
            return True
        else:
            logger.error("❌ Конфигурация: отсутствуют обязательные параметры")
            return False
            
    except Exception as e:
        logger.error(f"❌ Конфигурация: ошибка загрузки - {e}")
        return False

def check_scanners():
    """Проверяет доступность сканнеров."""
    logger.info("🔍 Проверка сканнеров...")
    
    try:
        from pyseckit.core.config import Config
        from pyseckit.core.scanner import ScannerManager
        
        config = Config()
        scanner_manager = ScannerManager(config.dict())  # Используем dict() для получения данных
        
        available_scanners = scanner_manager.get_available_scanners()
        
        if available_scanners:
            logger.info(f"✅ Сканнеры: найдено {len(available_scanners)}")
            for name in list(available_scanners.keys())[:3]:  # Показываем первые 3
                logger.info(f"   • {name}")
            return True
        else:
            logger.warning("⚠️ Сканнеры: не найдено доступных сканнеров")
            return False
            
    except Exception as e:
        logger.error(f"❌ Сканнеры: ошибка - {e}")
        return False

def check_plugins():
    """Проверяет систему плагинов."""
    logger.info("🔌 Проверка системы плагинов...")
    
    try:
        from pyseckit.plugins import PluginRegistry
        
        plugin_registry = PluginRegistry()
        plugin_registry.discover_plugins()
        
        plugins = plugin_registry.get_all_plugins()
        logger.info(f"✅ Плагины: система работает, найдено {len(plugins)} плагинов")
        return True
        
    except Exception as e:
        logger.error(f"❌ Плагины: ошибка - {e}")
        return False

def check_integrations():
    """Проверяет интеграции."""
    logger.info("🔗 Проверка интеграций...")
    
    try:
        from pyseckit.integrations import ElasticsearchIntegration, NotificationManager
        
        # Проверяем Elasticsearch интеграцию
        es_config = {'enabled': False, 'hosts': ['localhost:9200']}
        es_integration = ElasticsearchIntegration(es_config)
        
        # Проверяем систему уведомлений с корректной конфигурацией
        notification_config = {
            'slack': {'enabled': False},
            'teams': {'enabled': False},
            'email': {'enabled': False}
        }
        notification_manager = NotificationManager(notification_config)
        
        logger.info("✅ Интеграции: инициализация успешна")
        return True
        
    except Exception as e:
        logger.error(f"❌ Интеграции: ошибка - {e}")
        return False

def check_web_interface():
    """Проверяет веб-интерфейс."""
    logger.info("🌐 Проверка веб-интерфейса...")
    
    try:
        from pyseckit.web import create_app
        
        app = create_app()
        if app:
            logger.info("✅ Веб-интерфейс: приложение создано успешно")
            return True
        else:
            logger.error("❌ Веб-интерфейс: ошибка создания приложения")
            return False
            
    except Exception as e:
        logger.error(f"❌ Веб-интерфейс: ошибка - {e}")
        return False

def main():
    """Главная функция проверки."""
    logger.info("🚀 ПРОВЕРКА СИСТЕМЫ PYSECKIT")
    logger.info("=" * 50)
    
    checks = [
        ("Импорты", check_imports),
        ("Конфигурация", check_configuration),
        ("Сканнеры", check_scanners),
        ("Плагины", check_plugins),
        ("Интеграции", check_integrations),
        ("Веб-интерфейс", check_web_interface),
    ]
    
    passed = 0
    total = len(checks)
    
    for check_name, check_func in checks:
        try:
            if check_name == "Импорты":
                success_count, total_count = check_func()
                if success_count == total_count:
                    passed += 1
                logger.info(f"📊 Импорты: {success_count}/{total_count} успешно")
            else:
                if check_func():
                    passed += 1
        except Exception as e:
            logger.error(f"💥 Критическая ошибка в проверке '{check_name}': {e}")
    
    # Итоговый отчёт
    logger.info("\n" + "=" * 50)
    logger.info("📊 ИТОГОВЫЙ ОТЧЁТ")
    logger.info("=" * 50)
    
    success_rate = (passed / total * 100) if total > 0 else 0
    logger.info(f"Пройдено проверок: {passed}/{total}")
    logger.info(f"Процент успеха: {success_rate:.1f}%")
    
    if success_rate >= 80:
        logger.info("\n🎉 СИСТЕМА ГОТОВА К РАБОТЕ!")
        logger.info("PySecKit успешно настроен и может использоваться.")
    elif success_rate >= 60:
        logger.info("\n⚠️ СИСТЕМА ЧАСТИЧНО ГОТОВА")
        logger.info("Некоторые функции могут работать некорректно.")
    else:
        logger.info("\n❌ СИСТЕМА НЕ ГОТОВА")
        logger.info("Требуется устранение ошибок перед использованием.")
    
    logger.info("\n🚀 Для запуска сканирования используйте:")
    logger.info("   pyseckit scan")
    logger.info("\n📚 Для получения помощи:")
    logger.info("   pyseckit --help")
    
    return 0 if success_rate >= 60 else 1

if __name__ == "__main__":
    sys.exit(main()) 