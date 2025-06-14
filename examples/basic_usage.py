#!/usr/bin/env python3
"""
Пример базового использования PySecKit.

Демонстрирует основные возможности библиотеки для сканирования безопасности.
"""

from pathlib import Path
import sys

# Добавляем путь к библиотеке (для разработки)
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyseckit.core.config import Config
from pyseckit.core.scanner import ScannerManager
from pyseckit.sast import BanditScanner, SemgrepScanner, SafetyScanner
from pyseckit.reporting.manager import ReportManager


def main():
    """Основная функция демонстрации."""
    print("🛡️  PySecKit - Универсальный фреймворк безопасности")
    print("=" * 60)
    
    # 1. Загружаем конфигурацию
    print("\n📋 1. Загрузка конфигурации...")
    try:
        config = Config.load_default()
        print(f"✓ Конфигурация загружена для проекта: {config.project_name}")
    except Exception as e:
        print(f"❌ Ошибка загрузки конфигурации: {e}")
        return
    
    # 2. Инициализируем менеджер сканнеров
    print("\n🔍 2. Инициализация сканнеров...")
    manager = ScannerManager()
    
    # Регистрируем SAST сканнеры
    scanners = {
        'bandit': BanditScanner(),
        'semgrep': SemgrepScanner(),
        'safety': SafetyScanner(),
    }
    
    for name, scanner in scanners.items():
        manager.register_scanner(scanner)
        is_available = scanner.is_available()
        status = "✓ Доступен" if is_available else "❌ Не установлен"
        print(f"  {name}: {status}")
    
    # 3. Получаем список доступных сканнеров
    available_scanners = manager.get_available_scanners()
    
    if not available_scanners:
        print("\n⚠️  Нет доступных сканнеров. Установите необходимые инструменты:")
        print("pip install bandit semgrep safety")
        return
    
    print(f"\n✓ Доступно сканнеров: {len(available_scanners)}")
    
    # 4. Выполняем сканирование
    print("\n🔎 3. Выполнение сканирования...")
    target_path = Path(".")
    
    all_results = []
    
    for scanner_name in available_scanners:
        try:
            print(f"  Запуск {scanner_name}...")
            scanner = manager.get_scanner(scanner_name)
            
            if scanner:
                results = scanner.scan(target_path)
                all_results.extend(results)
                
                # Статистика по сканнеру
                stats = scanner.get_stats()
                print(f"    Найдено проблем: {stats.total_issues}")
                if stats.total_issues > 0:
                    print(f"    Критические: {stats.critical_issues}")
                    print(f"    Высокие: {stats.high_issues}")
                    print(f"    Средние: {stats.medium_issues}")
                    print(f"    Низкие: {stats.low_issues}")
        
        except Exception as e:
            print(f"    ❌ Ошибка сканнера {scanner_name}: {e}")
    
    # 5. Анализируем результаты
    print(f"\n📊 4. Анализ результатов...")
    print(f"Всего найдено проблем: {len(all_results)}")
    
    if all_results:
        # Группируем по критичности
        by_severity = {}
        for result in all_results:
            severity = result.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        print("Распределение по критичности:")
        for severity, count in sorted(by_severity.items(), 
                                    key=lambda x: all_results[0].__class__.__dict__['Severity'][x[0].upper()].priority, 
                                    reverse=True):
            print(f"  {severity.title()}: {count}")
        
        # Показываем топ-5 проблем
        print("\nТоп-5 проблем:")
        sorted_results = sorted(all_results, key=lambda x: x.severity.priority, reverse=True)
        for i, result in enumerate(sorted_results[:5], 1):
            file_info = f" в {result.file_path}:{result.line_number}" if result.file_path else ""
            print(f"  {i}. [{result.severity.value.upper()}] {result.title}{file_info}")
    
    # 6. Генерируем отчёты
    print("\n📄 5. Генерация отчётов...")
    
    if all_results:
        report_manager = ReportManager(config.reporting)
        
        # Создаём директорию для отчётов
        reports_dir = Path("./reports")
        reports_dir.mkdir(exist_ok=True)
        
        try:
            # JSON отчёт
            json_path = reports_dir / "security_report.json"
            report_manager.generate_json_report(all_results, json_path)
            print(f"✓ JSON отчёт: {json_path}")
            
            # HTML отчёт
            html_path = reports_dir / "security_report.html"
            report_manager.generate_html_report(all_results, html_path)
            print(f"✓ HTML отчёт: {html_path}")
            
            # CSV отчёт
            csv_path = reports_dir / "security_report.csv"
            report_manager.generate_csv_report(all_results, csv_path)
            print(f"✓ CSV отчёт: {csv_path}")
            
        except Exception as e:
            print(f"❌ Ошибка генерации отчётов: {e}")
    
    else:
        print("✓ Проблемы безопасности не найдены!")
    
    # 7. Проверяем критерии CI/CD
    print("\n🚀 6. Проверка критериев CI/CD...")
    
    critical_issues = sum(1 for r in all_results if r.severity.value == 'critical')
    high_issues = sum(1 for r in all_results if r.severity.value == 'high')
    
    if config.cicd.fail_on_critical and critical_issues > 0:
        print(f"❌ Сборка должна завершиться с ошибкой: найдено {critical_issues} критических проблем")
        return 1
    
    if config.cicd.fail_on_high and (critical_issues + high_issues) > 0:
        print(f"❌ Сборка должна завершиться с ошибкой: найдено {critical_issues + high_issues} критических/высоких проблем")
        return 1
    
    if config.cicd.max_issues and len(all_results) > config.cicd.max_issues:
        print(f"❌ Сборка должна завершиться с ошибкой: найдено {len(all_results)} проблем (лимит: {config.cicd.max_issues})")
        return 1
    
    print("✅ Критерии CI/CD выполнены!")
    
    print("\n🎉 Сканирование безопасности завершено успешно!")
    return 0


if __name__ == "__main__":
    sys.exit(main()) 