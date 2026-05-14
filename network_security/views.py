from django.shortcuts import render, redirect
from django.contrib import messages
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from collections import Counter

    # Сетевое оборудование
NETWORK_DEVICES = {
        'switch_01': {'name': 'Главный коммутатор', 'ip': '10.0.0.1', 'protected': False},
        'switch_02': {'name': 'Резервный коммутатор', 'ip': '10.0.0.2', 'protected': False},
        'router_01': {'name': 'Маршрутизатор периметра', 'ip': '10.0.0.254', 'protected': False},
        'ap_01': {'name': 'Точка доступа WiFi', 'ip': '10.0.0.100', 'protected': False},
        'patch_panel_01': {'name': 'Патч-панель', 'ip': None, 'protected': False},
    }

    # Роли и права доступа
ROLES = {
        'guest': {'level': 0, 'devices': [], 'actions': ['view']},
        'operator': {'level': 1, 'devices': ['switch_01', 'router_01'], 'actions': ['view', 'monitor']},
        'admin': {'level': 2, 'devices': ['switch_01', 'switch_02', 'router_01'], 'actions': ['view', 'monitor', 'block', 'unblock']},
        'auditor': {'level': 3, 'devices': list(NETWORK_DEVICES.keys()), 'actions': ['view', 'view_logs']},
    }

    # Пароли ролей
PASSWORDS = {
        'operator': 'operator123',
        'admin': 'admin123',
        'auditor': 'auditor456',
    }

    # Журнал событий
ACCESS_LOGS = []

def log_event(username, role, action, device, result, details=''):
        ACCESS_LOGS.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'role': role,
            'action': action,
            'device': device,
            'result': result,
            'details': details,
        })

def generate_charts():
        """Генерирует графики на основе ACCESS_LOGS"""

        if not ACCESS_LOGS:
            return None, None, None

        # 1. Столбчатая диаграмма: активность пользователей
        user_counts = Counter(log['username'] for log in ACCESS_LOGS)
        fig1, ax1 = plt.subplots(figsize=(8, 5))
        ax1.bar(user_counts.keys(), user_counts.values(), color='steelblue')
        ax1.set_title('Активность пользователей', fontsize=14)
        ax1.set_xlabel('Пользователь')
        ax1.set_ylabel('Количество действий')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        buffer1 = io.BytesIO()
        plt.savefig(buffer1, format='png')
        buffer1.seek(0)
        chart_user = base64.b64encode(buffer1.read()).decode('utf-8')
        plt.close(fig1)

        # 2. Круговая диаграмма: распределение операций
        action_counts = Counter(log['action'] for log in ACCESS_LOGS)
        action_labels = {'view': 'Просмотр', 'monitor': 'Мониторинг', 'block': 'Блокировка', 'unblock': 'Разблокировка'}
        labels = [action_labels.get(k, k) for k in action_counts.keys()]
        fig2, ax2 = plt.subplots(figsize=(6, 6))
        ax2.pie(action_counts.values(), labels=labels, autopct='%1.1f%%', startangle=90)
        ax2.set_title('Распределение операций', fontsize=14)
        plt.tight_layout()

        buffer2 = io.BytesIO()
        plt.savefig(buffer2, format='png')
        buffer2.seek(0)
        chart_actions = base64.b64encode(buffer2.read()).decode('utf-8')
        plt.close(fig2)

        # 3. График динамики событий
        if len(ACCESS_LOGS) >= 2:
            recent = ACCESS_LOGS[-20:]
            times = list(range(1, len(recent) + 1))
            granted = [1 if log['result'] == 'GRANTED' else 0 for log in recent]
            denied = [1 if log['result'] == 'DENIED' else 0 for log in recent]

            fig3, ax3 = plt.subplots(figsize=(10, 4))
            ax3.plot(times, granted, 'g-o', label='Разрешено', linewidth=2)
            ax3.plot(times, denied, 'r-s', label='Запрещено', linewidth=2)
            ax3.set_title('Динамика событий (последние 20)', fontsize=14)
            ax3.set_xlabel('Номер события')
            ax3.set_ylabel('Количество')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
            plt.tight_layout()

            buffer3 = io.BytesIO()
            plt.savefig(buffer3, format='png')
            buffer3.seek(0)
            chart_timeline = base64.b64encode(buffer3.read()).decode('utf-8')
            plt.close(fig3)
        else:
            chart_timeline = None

        return chart_user, chart_actions, chart_timeline

def dashboard(request):
        username = request.session.get('username', 'Гость')
        role = request.session.get('role', 'guest')
        available_devices = ROLES.get(role, ROLES['guest'])['devices']
        available_actions = ROLES.get(role, ROLES['guest'])['actions']

        context = {
            'username': username,
            'role': role,
            'devices': NETWORK_DEVICES,
            'available_devices': available_devices,
            'available_actions': available_actions,
        }
        return render(request, 'network_security/dashboard.html', context)

def check_access(request):
        if request.method == 'POST':
            username = request.POST.get('username', 'Неизвестный')
            role = request.POST.get('role', 'guest')
            device_id = request.POST.get('device_id')
            action = request.POST.get('action', 'view')
            password = request.POST.get('password', '')

            access_granted = False
            result_message = ""

            if role not in ROLES:
                result_message = "Ошибка: неизвестная роль"
            elif action not in ROLES[role]['actions']:
                result_message = f"Доступ запрещён: у роли '{role}' нет права на действие '{action}'"
            elif device_id not in ROLES[role]['devices'] and ROLES[role]['level'] < 2:
                result_message = f"Доступ запрещён: устройство '{device_id}' недоступно для роли '{role}'"
            elif role in PASSWORDS and password != PASSWORDS[role]:
                result_message = "Ошибка аутентификации: неверный пароль"
            else:
                access_granted = True
                device = NETWORK_DEVICES.get(device_id, {})
                if action == 'block':
                    device['protected'] = True
                    result_message = f"Устройство {device.get('name', device_id)} ЗАБЛОКИРОВАНО"
                elif action == 'unblock':
                    device['protected'] = False
                    result_message = f"Устройство {device.get('name', device_id)} РАЗБЛОКИРОВАНО"
                else:
                    result_message = f"Доступ разрешён: {action} к {device.get('name', device_id)}"

            log_event(username, role, action, device_id, 'GRANTED' if access_granted else 'DENIED', result_message)

            if access_granted:
                messages.success(request, result_message)
            else:
                messages.error(request, result_message)

            request.session['username'] = username
            request.session['role'] = role

            return redirect('security_dashboard')

        return redirect('security_dashboard')

def admin_panel(request):
        if request.method == 'POST':
            admin_password = request.POST.get('admin_password', '')
            if admin_password == 'admin123':
                request.session['is_admin'] = True
                messages.success(request, 'Вход в панель администратора выполнен')
            else:
                messages.error(request, 'Неверный пароль администратора')
                return redirect('security_dashboard')

        if not request.session.get('is_admin', False):
            return redirect('security_dashboard')

        denied_attempts = [log for log in ACCESS_LOGS if log['result'] == 'DENIED']
        user_attempts = {}
        for log in ACCESS_LOGS:
            user = log.get('username', 'unknown')
            user_attempts[user] = user_attempts.get(user, 0) + 1

        context = {
            'total_attempts': len(ACCESS_LOGS),
            'denied_attempts': len(denied_attempts),
            'user_attempts': user_attempts,
            'recent_logs': ACCESS_LOGS[-20:],
        }
        return render(request, 'network_security/admin_panel.html', context)

def view_logs(request):
        role = request.session.get('role', 'guest')
        if role not in ['auditor', 'admin']:
            messages.error(request, 'Доступ к журналу событий запрещён')
            return redirect('security_dashboard')

        # Генерируем графики
        chart_user, chart_actions, chart_timeline = generate_charts()

        context = {
            'logs': ACCESS_LOGS[::-1],
            'total_count': len(ACCESS_LOGS),
            'chart_user': chart_user,
            'chart_actions': chart_actions,
            'chart_timeline': chart_timeline,
        }
        return render(request, 'network_security/logs.html', context)