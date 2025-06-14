#!/usr/bin/env python3
"""
Быстрый старт PySecKit - Расширенные возможности
================================================

Этот пример демонстрирует как быстро начать использовать 
расширенные возможности PySecKit:

1. Создание кастомного сканера
2. Настройка уведомлений  
3. Интеграция с Elasticsearch
4. Запуск веб-интерфейса
5. Автоматическое threat modeling
"""

import sys
import os
from pathlib import Path


def setup_custom_scanner():
    """Создание и регистрация кастомного сканера."""
    print("🔧 Создание кастомного сканера...")
    
    scanner_code = '''
from pyseckit.plugins.scanner_plugin import ScannerPlugin
from pyseckit.plugins.base import PluginMetadata
from pyseckit.core.scanner import ScanResult
from datetime import datetime
import re

class PasswordScannerPlugin(ScannerPlugin):
    """Сканер для поиска незащищенных паролей в коде."""
    
    @property
    def metadata(self):
        return PluginMetadata(
            name="password-scanner",
            version="1.0.0",
            description="Поиск незащищенных паролей и API ключей",
            author="Security Team",
            category="security",
            config_schema={
                "required": ["patterns"],
                "properties": {
                    "patterns": {
                        "type": "array",
                        "description": "Регулярные выражения для поиска"
                    }
                }
            }
        )
    
    def initialize(self):
        """Инициализация сканера."""
        if not self.validate_config():
            return False
        self._initialized = True
        return True
    
    def cleanup(self):
        """Очистка ресурсов."""
        self._initialized = False
    
    def scan(self, target):
        """Выполняет поиск незащищенных паролей."""
        findings = []
        patterns = self.config.get("patterns", [
            r'password\\s*=\\s*["\'][^"\']+["\']',
            r'api_key\\s*=\\s*["\'][^"\']+["\']',
            r'secret\\s*=\\s*["\'][^"\']+["\']',
            r'token\\s*=\\s*["\'][^"\']+["\']'
        ])
        
        if os.path.isfile(target):
            files_to_scan = [target]
        elif os.path.isdir(target):
            files_to_scan = []
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith(('.py', '.js', '.ts', '.java', '.yaml', '.yml', '.json')):
                        files_to_scan.append(os.path.join(root, file))
        else:
            files_to_scan = []
        
        for file_path in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\\n') + 1
                        findings.append({
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "title": "Hardcoded Secret Detected",
                            "description": f"Потенциально незащищенный секрет найден в коде",
                            "file": file_path,
                            "line": line_num,
                            "column": match.start() - content.rfind('\\n', 0, match.start()),
                            "code": match.group(0),
                            "rule_id": f"HARDCODED-SECRET-{hash(pattern) % 1000}",
                            "cwe": "CWE-798",
                            "owasp": "A07:2021",
                            "references": [
                                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                            ]
                        })
            except Exception:
                continue
        
        return ScanResult(
            scanner_name=self.metadata.name,
            target=target,
            start_time=datetime.now(),
            end_time=datetime.now(),
            findings=findings,
            metadata={
                "patterns_used": len(patterns),
                "files_scanned": len(files_to_scan)
            }
        )
'''
    
    # Создаем директорию для плагинов
    plugins_dir = Path("plugins")
    plugins_dir.mkdir(exist_ok=True)
    
    # Сохраняем файл плагина
    plugin_file = plugins_dir / "password_scanner.py"
    with open(plugin_file, 'w', encoding='utf-8') as f:
        f.write(scanner_code)
    
    print(f"✅ Кастомный сканер создан: {plugin_file}")
    return plugin_file


def setup_config():
    """Создание расширенной конфигурации."""
    print("⚙️ Настройка конфигурации...")
    
    config_content = '''# PySecKit - Расширенная конфигурация
project_name: "My Secure Project"

# Основные настройки
target_directories:
  - "."

# Настройки сканеров
scanners:
  bandit:
    enabled: true
    timeout: 300
    severity_threshold: "medium"
  
  safety:
    enabled: true
    timeout: 180
    
  # Кастомный сканер
  password-scanner:
    enabled: true
    timeout: 120
    patterns:
      - 'password\\\\s*=\\\\s*["\'][^"\']+["\']'
      - 'api_key\\\\s*=\\\\s*["\'][^"\']+["\']'
      - 'secret\\\\s*=\\\\s*["\'][^"\']+["\']'
      - 'token\\\\s*=\\\\s*["\'][^"\']+["\']'

# Интеграции
integrations:
  # Elasticsearch для аналитики
  elasticsearch:
    enabled: false  # Измените на true для активации
    hosts: ["localhost:9200"]
    username: ""
    password: ""
    ssl: false
    index_prefix: "pyseckit"
    
  # Уведомления
  notifications:
    slack:
      enabled: false  # Измените на true и добавьте webhook_url
      webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
      channel: "#security-alerts"
      username: "PySecKit Security Bot"
      icon_emoji: ":shield:"
      
    teams:
      enabled: false  # Измените на true и добавьте webhook_url
      webhook_url: "https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK"
      
    email:
      enabled: false  # Измените на true и настройте SMTP
      smtp_server: "smtp.gmail.com"
      smtp_port: 587
      username: "your-email@gmail.com"
      password: "your-app-password"
      from_email: "security@company.com"
      to_emails:
        - "admin@company.com"
        - "security-team@company.com"
      use_tls: true

# Плагины
plugins:
  discovery_paths:
    - "./plugins"
    - "~/.pyseckit/plugins"

# Веб-интерфейс
web:
  enabled: true
  host: "127.0.0.1"
  port: 5000
  debug: false

# Threat Modeling
threat_modeling:
  auto_generate: true
  output_formats: ["json", "yaml"]
  include_mitigations: true
  include_attack_vectors: true
  
# Отчеты
reporting:
  output_dir: "./reports"
  formats:
    - "json"
    - "html"
  include_metadata: true

# Качественные критерии
quality_gates:
  fail_on_critical: true
  fail_on_high: false
  max_issues: 50
'''
    
    config_file = Path(".pyseckit-advanced.yml")
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(config_content)
    
    print(f"✅ Конфигурация создана: {config_file}")
    return config_file


def create_demo_code():
    """Создание демонстрационного кода с уязвимостями."""
    print("📝 Создание демонстрационного кода...")
    
    demo_code = '''#!/usr/bin/env python3
"""
Демонстрационный код с примерами проблем безопасности.
Этот код специально содержит уязвимости для демонстрации PySecKit.
"""

import os
import subprocess
import sqlite3

# Проблема: Hardcoded credentials
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "secret_token_do_not_share"

class DatabaseManager:
    def __init__(self):
        # Проблема: SQL Injection vulnerability
        self.db_password = "admin123"
        
    def get_user(self, user_id):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Небезопасный SQL запрос
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        return cursor.fetchone()
    
    def authenticate(self, username, password):
        # Проблема: Weak password validation
        if password == "password" or password == "123456":
            return True
        return False

class CommandExecutor:
    def run_command(self, command):
        # Проблема: Command injection
        result = subprocess.run(f"echo {command}", shell=True, capture_output=True)
        return result.stdout

class WebHandler:
    def process_input(self, user_input):
        # Проблема: XSS vulnerability
        return f"<div>Hello {user_input}</div>"
    
    def include_file(self, filename):
        # Проблема: Path traversal
        with open(f"./uploads/{filename}", 'r') as f:
            return f.read()

# Проблема: Sensitive data in logs
def log_user_action(username, password, action):
    print(f"User {username} with password {password} performed: {action}")

# Проблема: Weak encryption
def encrypt_data(data):
    # Использование устаревшего алгоритма
    import hashlib
    return hashlib.md5(data.encode()).hexdigest()

if __name__ == "__main__":
    # Демонстрация уязвимостей
    db = DatabaseManager()
    
    # SQL Injection test
    user = db.get_user("1 OR 1=1")
    
    # Command injection test
    executor = CommandExecutor()
    result = executor.run_command("test; rm -rf /")
    
    # XSS test
    handler = WebHandler()
    output = handler.process_input("<script>alert('XSS')</script>")
    
    print("Демонстрационный код выполнен")
'''
    
    demo_dir = Path("demo_project")
    demo_dir.mkdir(exist_ok=True)
    
    demo_file = demo_dir / "vulnerable_app.py"
    with open(demo_file, 'w', encoding='utf-8') as f:
        f.write(demo_code)
    
    # Создаем requirements.txt с уязвимыми зависимостями
    requirements = '''# Демонстрационные зависимости с уязвимостями
django==2.0.0  # Устаревшая версия с уязвимостями
requests==2.5.0  # Устаревшая версия
flask==0.12.0  # Устаревшая версия
'''
    
    req_file = demo_dir / "requirements.txt"
    with open(req_file, 'w', encoding='utf-8') as f:
        f.write(requirements)
    
    print(f"✅ Демонстрационный код создан: {demo_dir}")
    return demo_dir


def print_usage_examples():
    """Выводит примеры использования."""
    print("\n" + "="*60)
    print("🚀 ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ РАСШИРЕННЫХ ВОЗМОЖНОСТЕЙ")
    print("="*60)
    
    print("\n1️⃣ Базовое сканирование:")
    print("   pyseckit scan ./demo_project -c .pyseckit-advanced.yml")
    
    print("\n2️⃣ Запуск веб-интерфейса:")
    print("   pyseckit web -c .pyseckit-advanced.yml --port 5000")
    print("   Откройте: http://127.0.0.1:5000")
    
    print("\n3️⃣ Генерация модели угроз:")
    print("   pyseckit threat-model ./demo_project --output threat-model.json")
    
    print("\n4️⃣ Управление плагинами:")
    print("   pyseckit plugins -c .pyseckit-advanced.yml")
    
    print("\n5️⃣ Тестирование уведомлений:")
    print("   pyseckit test-notifications -c .pyseckit-advanced.yml")
    
    print("\n6️⃣ API использование:")
    print("   # Запустите веб-интерфейс, затем:")
    print("   curl -X POST http://localhost:5000/api/scan \\")
    print("     -H 'Content-Type: application/json' \\")
    print('     -d \'{"target": "./demo_project", "scanners": ["bandit", "password-scanner"]}\'')
    
    print("\n7️⃣ Интеграция с CI/CD:")
    print("   # GitHub Actions example:")
    print("   - name: Security Scan")
    print("     run: |")
    print("       pip install pyseckit")
    print("       pyseckit scan . --fail-on-high")
    
    print("\n📊 НАСТРОЙКА ELASTICSEARCH:")
    print("   1. Запустите Elasticsearch: docker run -p 9200:9200 elasticsearch:8.0.0")
    print("   2. Измените enabled: true в .pyseckit-advanced.yml")
    print("   3. Перезапустите сканирование")
    
    print("\n📢 НАСТРОЙКА УВЕДОМЛЕНИЙ:")
    print("   1. Slack: Создайте Incoming Webhook в Slack App")
    print("   2. Teams: Создайте Incoming Webhook в Teams")
    print("   3. Email: Настройте SMTP в конфигурации")
    
    print("\n🔌 СОЗДАНИЕ КАСТОМНОГО ПЛАГИНА:")
    print("   1. Скопируйте файл plugins/password_scanner.py")
    print("   2. Измените логику сканирования")
    print("   3. Зарегистрируйте в plugin_registry")
    
    print("\n" + "="*60)


def main():
    """Основная функция быстрого старта."""
    print("🚀 PySecKit - Быстрый старт расширенных возможностей")
    print("=" * 60)
    
    try:
        # 1. Создаем кастомный сканер
        plugin_file = setup_custom_scanner()
        
        # 2. Настраиваем конфигурацию
        config_file = setup_config()
        
        # 3. Создаем демонстрационный код
        demo_dir = create_demo_code()
        
        print(f"\n✅ Быстрый старт завершен!")
        print(f"📁 Созданные файлы:")
        print(f"   📄 Конфигурация: {config_file}")
        print(f"   🔌 Плагин: {plugin_file}")
        print(f"   📝 Демо-код: {demo_dir}")
        
        # 4. Показываем примеры использования
        print_usage_examples()
        
        print("\n🎉 Готово! Теперь вы можете использовать все расширенные возможности PySecKit!")
        
    except Exception as e:
        print(f"❌ Ошибка при настройке: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 