# coding: utf-8
import re
from jumpserver.context_processor import default_interface
from django.conf import settings
from IPy import IP

from common.utils import lookup_domain


def get_interface_setting_or_default():
    import json
    data = dict(default_interface)
    try:
        from settings.models import Setting
        item = Setting.objects.filter(name='INTERFACE').first()
        if item and item.value:
            val = json.loads(item.value)
            if isinstance(val, dict):
                data.update(val)
    except Exception:
        pass

    # An uploaded image whose file is gone would render as a broken <img>; use the default instead.
    try:
        import os
        from xpack.api.interface import INTERFACE_UPLOAD_URL, INTERFACE_UPLOAD_DIR
        for field in ('logo_index', 'logo_logout', 'favicon', 'login_image'):
            value = data.get(field)
            if isinstance(value, str) and value.startswith(INTERFACE_UPLOAD_URL):
                filename = os.path.basename(value)
                if not os.path.isfile(os.path.join(INTERFACE_UPLOAD_DIR, filename)):
                    data[field] = default_interface.get(field)
    except Exception:
        pass

    HEX_COLOR_PATTERN = re.compile(r'^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?(?:[0-9a-fA-F]{2})?$')

    def safe_json_dumps(obj):
        return json.dumps(obj).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')

    try:
        from xpack.api.interface import THEMES_LIST
        current_theme = data.get('theme', 'midnight_dark')
        theme_item = None
        for t in THEMES_LIST:
            if t['name'] == current_theme:
                theme_item = t
                break
        if not theme_item and THEMES_LIST:
            theme_item = THEMES_LIST[0]
        if theme_item:
            colors = dict(theme_item['colors'])
            custom_primary = data.get('custom_primary')
            if custom_primary and isinstance(custom_primary, str) and HEX_COLOR_PATTERN.match(custom_primary.strip()):
                custom_primary = custom_primary.strip()
                colors['--color-primary'] = custom_primary
                colors['--color-link'] = custom_primary
                colors['--menu-text-active'] = custom_primary
            mode = data.get('theme_mode') or ('dark' if theme_item.get('is_dark') else 'light')
            is_dark = (mode == 'dark') if mode in ['dark', 'light'] else theme_item.get('is_dark', False)
            colors['theme_mode'] = mode
            colors['is_dark'] = is_dark
            data['theme_info'] = {
                'colors': colors,
                'is_dark': is_dark,
                'theme_mode': mode
            }
            data['theme_info_json'] = safe_json_dumps(data['theme_info'])
    except Exception:
        pass
    if 'theme_info_json' not in data:
        data['theme_info_json'] = safe_json_dumps(data.get('theme_info', {}))

    return data


def get_login_title():
    return get_interface_setting_or_default()['login_title']


def generate_ips(address_string):
    def transform(_ip):
        real_ip, err_msg = lookup_domain(_ip)
        return _ip if err_msg or real_ip == '0.0.0.0' else real_ip

    # 支持的格式
    # 192.168.1.1,192.168.1.2
    # 192.168.1.1-12 | 192.168.1.1-192.168.1.12 | 192.168.1.0/30 | 192.168.1.1
    ips = []
    ip_list = address_string.split(',')
    if len(ip_list) >= 1:
        for ip in ip_list:
            try:
                ips.append(str(IP(transform(ip))))
            except ValueError:
                pass
        if ips:
            return ips

    ip_list = address_string.split('-')
    try:
        if len(ip_list) == 2:
            start_ip, end_ip = ip_list
            if ip_list[1].find('.') == -1:
                end_ip = start_ip[:start_ip.rindex('.') + 1] + end_ip
            for ip in range(IP(start_ip).int(), IP(end_ip).int() + 1):
                ips.extend((str(ip) for ip in IP(ip)))
        else:
            ips.extend((str(ip) for ip in IP(ip_list[0])))
    except ValueError:
        ips = []
    return ips


def is_valid_port(port):
    valid = True
    try:
        port = int(port)
        if port > 65535 or port < 1:
            valid = False
    except (TypeError, ValueError):
        valid = False
    return valid


def generate_ports(ports):
    port_list = []
    if isinstance(ports, int):
        port_list.append(ports)
    elif isinstance(ports, str):
        port_list.extend(
            [int(p) for p in ports.split(',') if p.isdigit()]
        )
    elif isinstance(ports, list):
        port_list = ports
    port_list = list(map(int, filter(is_valid_port, port_list)))
    return port_list
