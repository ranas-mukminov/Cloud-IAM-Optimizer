# Cloud IAM Optimizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/ranas-mukminov/Cloud-IAM-Optimizer/pulls)

> **AWS/GCP IAM Least Privilege Auditor** — автоматизированный анализ IAM-политик и рекомендации по минимизации привилегий  
> *AWS/GCP IAM Least Privilege Auditor — automated IAM policy analysis and privilege minimization recommendations*

🌐 **[run-as-daemon.dev](https://run-as-daemon.dev)** | 👨‍💻 **[@ranas-mukminov](https://github.com/ranas-mukminov)**

[🇷🇺 Русская версия](README.ru.md) | [🇺🇸 English version](README.md)

---

## 🎯 Purpose

**Cloud IAM Optimizer** — это инструмент для аудита прав доступа (IAM) в облачных провайдерах AWS и GCP. Он помогает выявить избыточные привилегии, отсутствие MFA, старые ключи доступа и другие проблемы безопасности.

**Основные возможности:**
- ✅ Анализ IAM-пользователей AWS (список, политики, ключи, MFA)
- ✅ Выявление нарушений безопасности (отсутствие MFA, избыточные права)
- ✅ JSON/текстовый вывод для интеграции в CI/CD
- 🔄 Поддержка GCP (в разработке)

**Для кого:**
- DevOps/SRE-инженеры
- Специалисты по информационной безопасности
- Команды разработки, внедряющие принцип наименьших привилегий

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- AWS CLI настроен (`aws configure`) ИЛИ переменные окружения `AWS_*`
- (Опционально) GCP Service Account для анализа GCP

### Installation

```bash
# Clone repository
git clone https://github.com/ranas-mukminov/Cloud-IAM-Optimizer.git
cd Cloud-IAM-Optimizer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# или: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze AWS IAM (default profile)
python src/iam_optimizer.py --provider aws

# Use specific AWS profile
python src/iam_optimizer.py --provider aws --profile production

# Export as JSON
python src/iam_optimizer.py --provider aws --output json > audit_report.json

# Help
python src/iam_optimizer.py --help
```

### Example Output

```
======================================================================
Cloud IAM Optimizer - AWS Analysis
======================================================================
Timestamp: 2025-11-24T20:58:00Z

Total Users: 5

──────────────────────────────────────────────────────────────────────
IAM Users:
──────────────────────────────────────────────────────────────────────

👤 admin-user
   User ID: AIDAI23XXXXXXXXXXXX
   Created: 2024-01-15T10:30:00Z
   MFA Enabled: ✅ Yes
   Groups: Admins
   Managed Policies: 1
   Inline Policies: 0
   Access Keys: 0

👤 developer-1
   User ID: AIDAI45YYYYYYYYYYYY
   Created: 2024-06-20T14:22:00Z
   MFA Enabled: ❌ No
   Groups: Developers
   Managed Policies: 2
   Inline Policies: 1
   Access Keys: 1

──────────────────────────────────────────────────────────────────────
Security Findings:
──────────────────────────────────────────────────────────────────────

🔴 [HIGH] developer-1
   Issue: User has active access keys but MFA is not enabled
   Recommendation: Enable MFA for all users with programmatic access

======================================================================
For enterprise features and commercial support:
🌐 https://run-as-daemon.dev
📧 Contact: @ranas-mukminov
======================================================================
```

---

## ⚙️ Configuration

### Environment Variables

Создайте файл `.env` на основе `.env.example`:

```bash
cp .env.example .env
```

**AWS (рекомендуется использовать профили):**
```bash
AWS_PROFILE=your-profile-name
```

**AWS (явные креденшиалы, НЕ рекомендуется для production):**
```bash
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-east-1
```

**GCP:**
```bash
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
GCP_PROJECT_ID=your-project-id
```

> ⚠️ **ВАЖНО:** Никогда не коммитьте файл `.env` в Git! Он уже добавлен в `.gitignore`.

---

## 🔍 Examples

### Analyze Multiple AWS Accounts

```bash
# Production account
python src/iam_optimizer.py --provider aws --profile prod --output json > prod_audit.json

# Staging account
python src/iam_optimizer.py --provider aws --profile staging --output json > staging_audit.json

# Development account
python src/iam_optimizer.py --provider aws --profile dev --output json > dev_audit.json
```

### CI/CD Integration

```yaml
# .github/workflows/iam-audit.yml
name: Weekly IAM Audit
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9:00 UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run IAM audit
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          python src/iam_optimizer.py --provider aws --output json > iam_audit.json
      
      - name: Upload audit report
        uses: actions/upload-artifact@v3
        with:
          name: iam-audit-report
          path: iam_audit.json
```

---

## 📊 Features Roadmap

- [x] AWS IAM user listing
- [x] AWS MFA detection
- [x] AWS access keys audit
- [x] AWS managed/inline policies listing
- [ ] AWS policy permission analysis
- [ ] AWS unused permissions detection
- [ ] AWS CloudTrail integration (last used)
- [ ] GCP IAM support
- [ ] Azure AD support
- [ ] Automated remediation suggestions
- [ ] Prometheus metrics export
- [ ] Slack/Teams notifications

---

## 🛡️ Privacy & Compliance

> [!IMPORTANT]  
> **Данные, обрабатываемые инструментом:**  
> - IAM metadata (имена пользователей, ID, даты создания)  
> - Список политик и групп  
> - Статус MFA и ключей доступа  
> 
> **Что НЕ логируется:**  
> - AWS credentials (Access Key ID, Secret Access Key)  
> - Содержимое политик IAM  
> - Персональные данные конечных пользователей облачных сервисов  

**Соответствие законодательству РФ:**
- При использовании в production-окружениях российских компаний убедитесь в соблюдении требований **152-ФЗ "О персональных данных"**
- Для обработки персональных данных клиентов требуется их согласие
- Рекомендуется хранить отчёты в защищённых хранилищах с контролем доступа
- **For Russian Federation compliance inquiries, please visit our local mirror: [run-as-daemon.ru](https://run-as-daemon.ru)**

**Для аудита соответствия:**
- Используйте JSON-вывод для интеграции с системами SIEM
- Результаты можно экспортировать в Elasticsearch/Grafana для визуализации
- Контакт для консультаций: **[run-as-daemon.dev](https://run-as-daemon.dev)**

---

## 🏢 Commercial Support

> **Нужна помощь с внедрением или кастомизацией?**

ИП Мукминов Ранас Раушанович предоставляет коммерческую поддержку для этого проекта:

### Услуги:
- ✅ **Аудит облачной инфраструктуры** (AWS, GCP, Azure)
- ✅ **Внедрение принципа наименьших привилегий** (least privilege)
- ✅ **Настройка автоматизированного мониторинга IAM**
- ✅ **Интеграция с Prometheus/Grafana/SIEM**
- ✅ **Обучение команд DevSecOps практикам**
- ✅ **Разработка кастомных политик и правил**

### Контакты:
- 🌐 **Website:** [run-as-daemon.dev](https://run-as-daemon.dev)
- 📧 **Email:** [через форму на сайте]
- 💼 **GitHub:** [@ranas-mukminov](https://github.com/ranas-mukminov)

**Реквизиты:**  
ИП Мукминов Ранас Раушанович  
ОГРНИП: 322169000136872  
ИНН: 161201915096  

---

## 📖 Production Notes

> [!WARNING]  
> **Перед использованием в production:**  
> - Убедитесь, что IAM-роли/пользователи имеют минимальные права для аудита (`iam:List*`, `iam:Get*`)
> - Используйте dedicated IAM users/roles только для аудита
> - Храните AWS credentials в AWS Secrets Manager или аналогичных хранилищах
> - Настройте ротацию ключей доступа (максимум 90 дней)

**Рекомендуемые IAM политики для аудита AWS:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListAccessKeys",
        "iam:ListMFADevices"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 🤝 Contributing

Contributions are welcome! This is a **public demo version** of the tool. The enterprise version is deployed as part of commercial audits.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Development Setup:**

```bash
# Install dev dependencies
pip install -r requirements.txt pytest black flake8

# Run linter
flake8 src/

# Format code
black src/

# Run tests
pytest tests/
```

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Ranas Mukminov (@ranas-mukminov)

---

## 🔗 Related Projects

- [AutoHarden-Toolkit](https://github.com/ranas-mukminov/AutoHarden-Toolkit) — Automated Linux server hardening
- [Ranas Security Stack Documentation](https://run-as-daemon.ru) — Full security stack overview

---

**Made with ❤️ by [@ranas-mukminov](https://github.com/ranas-mukminov)**  
**[run-as-daemon.dev](https://run-as-daemon.dev)** — Your DevSecOps Partner
