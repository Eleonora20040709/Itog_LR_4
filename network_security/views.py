from django.shortcuts import render

# Create your views here.

from django.shortcuts import render, redirect
from django.contrib import messages
from datetime import datetime

# Сетевое оборудование
NETWORK_DEVICES = {
    'switch_01': {'name': 'Главный коммутатор', 'ip': '10.0.0.1', 'protected': False},
    'switch_02': {'name': 'Резервный коммутатор', 'ip': '10.0.0.2', 'protected': False},
    'router_01': {'name': 'Маршрутизатор', 'ip': '10.0.0.254', 'protected': False},
    'ap_01': {'name': 'Точка доступа WiFi', 'ip': '10.0.0.100', 'protected': False},
    'patch_panel_01': {'name': 'Патч-панель', 'ip': None, 'protected': False},
}

# Роли
ROLES = {
    'guest': {'level': 0, 'devices': [], 'actions': ['view']},
    'operator': {'level': 1, 'devices': ['switch_01', 'router_01'], 'actions': ['view', 'monitor']},
    'admin': {'level': 2, 'devices': ['switch_01', 'switch_02', 'router_01'], 'actions': ['view', 'monitor', 'block', 'unblock']},
    'auditor': {'level': 3, 'devices': list(NETWORK_DEVICES.keys()), 'actions': ['view', 'view_logs']},
}

PASSWORDS = {'operator': 'op123', 'admin': 'admin123', 'auditor': 'aud456'}
ACCESS_LOGS = []

def log(username, role, action, device, result, detail=''):
    ACCESS_LOGS.append({
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'username': username, 'role': role, 'action': action,
        'device': device, 'result': result, 'detail': detail,
    })

def dashboard(request):
    role = request.session.get('role', 'guest')
    return render(request, 'network_security/dashboard.html', {
        'username': request.session.get('username', 'Гость'),
        'role': role,
        'devices': NETWORK_DEVICES,
        'available_devices': ROLES[role]['devices'],
        'available_actions': ROLES[role]['actions'],
    })

def check_access(request):
    if request.method == 'POST':
        username = request.POST['username']
        role = request.POST['role']
        device_id = request.POST['device_id']
        action = request.POST['action']
        password = request.POST.get('password', '')

        if role in PASSWORDS and password != PASSWORDS[role]:
            log(username, role, action, device_id, 'DENIED', 'Wrong password')
            messages.error(request, 'Неверный пароль')
            return redirect('security_dashboard')

        if action not in ROLES[role]['actions']:
            log(username, role, action, device_id, 'DENIED', 'No permission')
            messages.error(request, f'Нет права на {action}')
            return redirect('security_dashboard')

        if device_id not in ROLES[role]['devices'] and ROLES[role]['level'] < 2:
            log(username, role, action, device_id, 'DENIED', 'Device not available')
            messages.error(request, f'Устройство недоступно для роли {role}')
            return redirect('security_dashboard')

        device = NETWORK_DEVICES[device_id]
        if action == 'block':
            device['protected'] = True
            msg = f'{device["name"]} заблокировано'
        elif action == 'unblock':
            device['protected'] = False
            msg = f'{device["name"]} разблокировано'
        else:
            msg = f'{action} к {device["name"]} разрешён'

        log(username, role, action, device_id, 'GRANTED', msg)
        messages.success(request, msg)
        request.session['username'] = username
        request.session['role'] = role
        return redirect('security_dashboard')
    return redirect('security_dashboard')

def admin_panel(request):
    if request.method == 'POST' and request.POST.get('admin_password') == 'admin123':
        request.session['is_admin'] = True
        messages.success(request, 'Вход выполнен')
    if not request.session.get('is_admin'):
        return render(request, 'network_security/admin_login.html')

    denied = [log for log in ACCESS_LOGS if log['result'] == 'DENIED']
    attacks = {}
    for log in ACCESS_LOGS:
        attacks[log['username']] = attacks.get(log['username'], 0) + 1

    return render(request, 'network_security/admin_panel.html', {
        'total': len(ACCESS_LOGS),
        'denied': len(denied),
        'attacks': attacks,
        'logs': ACCESS_LOGS[-30:],
    })

def view_logs(request):
    if request.session.get('role') not in ['auditor', 'admin']:
        messages.error(request, 'Доступ запрещён')
        return redirect('security_dashboard')
    return render(request, 'network_security/logs.html', {
        'logs': ACCESS_LOGS[::-1],
        'count': len(ACCESS_LOGS),
    })