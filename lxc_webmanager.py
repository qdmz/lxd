#!/usr/bin/env python3
"""
LXC容器Web管理工具 - Python Flask实现

"""

import os
import json
import subprocess
import shlex
import datetime
import re
import ipaddress
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# 配置信息
CONFIG = {
    # 用户配置
    'users': {
        'admin': {
            'password': 'admin123',
            'role': 'admin',
            'allowed_containers': ['*']
        },
        'user1': {
            'password': 'user123', 
            'role': 'user',
            'allowed_containers': ['web-server', 'db-server', 'user1-']
        },
        'user2': {
            'password': 'user123', 
            'role': 'user',
            'allowed_containers': ['app-server', 'user2-']
        },
        'viewer': {
            'password': 'view123', 
            'role': 'viewer',
            'allowed_containers': ['web-server']
        }
    },
    
    # 权限定义
    'permissions': {
        'admin': ['view', 'start', 'stop', 'restart', 'freeze', 'create', 'delete', 'edit', 'backup', 'restore', 'monitor', 'manage_users', 'port_forwarding'],
        'user': ['view', 'start', 'stop', 'restart', 'freeze', 'backup', 'monitor', 'create_own'],
        'viewer': ['view', 'monitor']
    },
    
    # LXC配置
    'lxc_path': '/var/lib/lxc',
    'backup_path': '/www/backups/lxc',
    'templates': {
        'ubuntu': 'ubuntu:22.04',
        'alpine': 'alpine:edge',
        'centos': 'centos:8',
        'debian': 'debian:11'
    },
    
    # 资源限制默认值
    'default_limits': {
        'cpu': '1',
        'memory': '512MB',
        'disk': '10GB'
    },
    
    # LXC命令配置
    'lxc_command': {
        'use_sudo': False,
        'lxc_path': '/snap/bin/lxc',
        'socket_path': '/var/snap/lxd/common/lxd/unix.socket'
    },
    
    # 端口转发配置
    'port_forwarding': {
        'enabled': True,
        'iptables_path': '/sbin/iptables',
        'ip6tables_path': '/sbin/ip6tables',
        'rules_file': '/etc/iptables/rules.v4',
        'allowed_ports': {
            'min': 1024,
            'max': 65535
        }
    }
}

# 工具函数
def execute_command(command, shell=False):
    """执行系统命令并返回结果"""
    try:
        if shell:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        
        return {
            'success': result.returncode == 0,
            'output': result.stdout.strip().split('\n') if result.stdout else [],
            'error': result.stderr.strip().split('\n') if result.stderr else [],
            'returncode': result.returncode
        }
    except Exception as e:
        return {
            'success': False,
            'output': [],
            'error': [str(e)],
            'returncode': -1
        }

def execute_lxc_command(command):
    """执行LXC命令"""
    lxc_config = CONFIG['lxc_command']
    lxc_path = lxc_config['lxc_path']
    
    if lxc_config.get('use_sudo', False):
        full_command = f"sudo -n {lxc_path} {command}"
    else:
        full_command = f"{lxc_path} {command}"
    
    return execute_command(full_command)

def execute_sudo_command(command):
    """执行需要sudo权限的命令"""
    full_command = f"sudo {command}"
    return execute_command(full_command, shell=True)

def check_permission(action, container_name=None):
    """检查操作权限"""
    if 'user_role' not in session:
        return False
    
    role = session['user_role']
    
    # 管理员拥有所有权限
    if role == 'admin':
        return True
    
    # 检查角色是否存在权限配置
    if role not in CONFIG['permissions']:
        return False
    
    # 检查基本权限
    if action not in CONFIG['permissions'][role]:
        return False
    
    # 如果涉及具体容器，检查容器权限
    if container_name is not None and not check_container_permission(container_name):
        return False
    
    return True

def check_container_permission(container_name):
    """检查用户对容器的权限"""
    if session.get('user_role') == 'admin':
        return True
    
    allowed_containers = session.get('allowed_containers', [])
    
    for pattern in allowed_containers:
        if pattern.endswith('-'):
            prefix = pattern[:-1]
            if container_name.startswith(prefix):
                return True
        elif pattern == container_name or pattern == '*':
            return True
    
    return False

def filter_containers_by_permission(containers):
    """根据用户权限过滤容器列表"""
    return {name: container for name, container in containers.items() 
            if check_container_permission(name)}

def generate_container_name(base_name):
    """为普通用户生成容器名称（添加用户名前缀）"""
    if session.get('user_role') == 'admin':
        return base_name
    
    username = session.get('username', '')
    
    if base_name.startswith(f"{username}-"):
        return base_name
    
    return f"{username}-{base_name}"

def login_required(f):
    """登录装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_containers():
    """获取容器列表"""
    result = execute_lxc_command("list --format json")
    containers = {}
    
    if result['success'] and result['output']:
        try:
            containers_data = json.loads(''.join(result['output']))
            
            for container_data in containers_data:
                name = container_data.get('name', '未知')
                status = container_data.get('status', 'unknown').lower()
                ip = '未知'
                
                try:
                    state = container_data.get('state')
                    if state and isinstance(state, dict):
                        network = state.get('network')
                        if network and isinstance(network, dict):
                            for interface, net_info in network.items():
                                if net_info and isinstance(net_info, dict):
                                    addresses = net_info.get('addresses')
                                    if addresses and isinstance(addresses, list):
                                        for addr in addresses:
                                            if isinstance(addr, dict) and addr.get('family') == 'inet' and addr.get('scope') == 'global':
                                                ip = addr.get('address', '未知')
                                                break
                except Exception as e:
                    print(f"Error getting IP for {name}: {e}")
                
                containers[name] = {
                    'name': name,
                    'status': status,
                    'ip': ip,
                    'cpu_usage': '0%',
                    'memory_usage': '0MB/0MB',
                    'disk_usage': '0GB/0GB',
                    'processes': '0',
                    'owner': '未知'
                }
                
                if '-' in name:
                    prefix = name.split('-')[0]
                    containers[name]['owner'] = prefix
                    
        except json.JSONDecodeError:
            result = execute_lxc_command("list")
            if result['success']:
                for line in result['output']:
                    if 'NAME' in line or '---' in line or not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        status = parts[1].lower()
                        ip = '未知'
                        
                        for i in range(2, len(parts)):
                            if '.' in parts[i] and parts[i].count('.') == 3:
                                ip_parts = parts[i].split('.')
                                if all(part.isdigit() for part in ip_parts):
                                    ip = parts[i]
                                    break
                        
                        containers[name] = {
                            'name': name,
                            'status': status,
                            'ip': ip,
                            'cpu_usage': '0%',
                            'memory_usage': '0MB/0MB',
                            'disk_usage': '0GB/0GB',
                            'processes': '0',
                            'owner': '未知'
                        }
                        
                        if '-' in name:
                            prefix = name.split('-')[0]
                            containers[name]['owner'] = prefix
    
    return filter_containers_by_permission(containers)

def get_backups():
    """获取备份列表"""
    backup_dir = CONFIG['backup_path']
    backups = []
    
    if not os.path.exists(backup_dir):
        return backups
    
    try:
        for file in os.listdir(backup_dir):
            if file.endswith('.tar.gz') and '_backup_' in file:
                parts = file.split('_backup_')
                if len(parts) == 2:
                    container_name = parts[0]
                    timestamp = parts[1].replace('.tar.gz', '')
                    
                    if check_container_permission(container_name):
                        file_path = os.path.join(backup_dir, file)
                        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        
                        backups.append({
                            'file': file,
                            'container': container_name,
                            'date': timestamp.replace('_', ' '),
                            'path': file_path,
                            'size': file_size
                        })
    except Exception as e:
        print(f"Error reading backups: {e}")
    
    return backups

def get_port_forwarding_rules():
    """获取端口转发规则列表"""
    rules = []
    
    if not CONFIG['port_forwarding']['enabled']:
        return rules
    
    try:
        # 获取NAT表的PREROUTING链规则
        result = execute_sudo_command(f"{CONFIG['port_forwarding']['iptables_path']} -t nat -L PREROUTING -n --line-numbers")
        
        if result['success']:
            for line in result['output']:
                # 查找DNAT规则
                if 'DNAT' in line and 'dpt:' in line:
                    parts = line.split()
                    if len(parts) >= 11:
                        rule_num = parts[0]
                        protocol = parts[3] if parts[3] in ['tcp', 'udp'] else 'tcp'
                        
                        # 提取目标端口
                        dpt_match = re.search(r'dpt:(\d+)', line)
                        if dpt_match:
                            external_port = dpt_match.group(1)
                            
                            # 提取目标地址
                            to_match = re.search(r'to:([\d.]+):(\d+)', line)
                            if to_match:
                                container_ip = to_match.group(1)
                                internal_port = to_match.group(2)
                                
                                # 获取容器名称
                                container_name = get_container_by_ip(container_ip)
                                
                                rules.append({
                                    'rule_num': rule_num,
                                    'protocol': protocol,
                                    'external_port': external_port,
                                    'container_ip': container_ip,
                                    'container_name': container_name,
                                    'internal_port': internal_port,
                                    'description': f"{protocol.upper()} {external_port} -> {container_name}:{internal_port}"
                                })
    except Exception as e:
        print(f"Error getting port forwarding rules: {e}")
    
    return rules

def get_container_by_ip(ip):
    """根据IP地址获取容器名称"""
    containers = get_containers()
    for name, container in containers.items():
        if container.get('ip') == ip:
            return name
    return '未知'

def add_port_forwarding_rule(protocol, external_port, container_name, internal_port, description=""):
    """添加端口转发规则"""
    if not CONFIG['port_forwarding']['enabled']:
        return {'success': False, 'message': '端口转发功能已禁用'}
    
    # 验证端口号
    try:
        ext_port = int(external_port)
        int_port = int(internal_port)
        
        min_port = CONFIG['port_forwarding']['allowed_ports']['min']
        max_port = CONFIG['port_forwarding']['allowed_ports']['max']
        
        if ext_port < min_port or ext_port > max_port or int_port < 1 or int_port > 65535:
            return {'success': False, 'message': f'端口号必须在{min_port}-65535范围内'}
    except ValueError:
        return {'success': False, 'message': '端口号必须是数字'}
    
    # 验证协议
    if protocol not in ['tcp', 'udp']:
        return {'success': False, 'message': '协议必须是tcp或udp'}
    
    # 获取容器IP
    containers = get_containers()
    if container_name not in containers:
        return {'success': False, 'message': '容器不存在'}
    
    container_ip = containers[container_name].get('ip')
    if container_ip == '未知':
        return {'success': False, 'message': '无法获取容器IP地址'}
    
    # 检查端口是否已被占用
    rules = get_port_forwarding_rules()
    for rule in rules:
        if rule['protocol'] == protocol and rule['external_port'] == external_port:
            return {'success': False, 'message': f'{protocol.upper()}端口{external_port}已被占用'}
    
    # 添加端口转发规则
    try:
        # 添加PREROUTING规则
        cmd = (f"{CONFIG['port_forwarding']['iptables_path']} -t nat -A PREROUTING "
               f"-p {protocol} --dport {external_port} "
               f"-j DNAT --to-destination {container_ip}:{internal_port}")
        
        result = execute_sudo_command(cmd)
        
        if not result['success']:
            return {'success': False, 'message': f'添加规则失败: {" ".join(result["error"])}'}
        
        # 保存规则（如果配置了规则文件）
        if CONFIG['port_forwarding'].get('rules_file'):
            save_result = execute_sudo_command(f"{CONFIG['port_forwarding']['iptables_path']}-save > {CONFIG['port_forwarding']['rules_file']}")
            if not save_result['success']:
                return {'success': True, 'message': '规则已添加但保存失败，重启后可能失效'}
        
        return {'success': True, 'message': '端口转发规则添加成功'}
    
    except Exception as e:
        return {'success': False, 'message': f'添加规则时出错: {str(e)}'}

def delete_port_forwarding_rule(rule_num, protocol):
    """删除端口转发规则"""
    if not CONFIG['port_forwarding']['enabled']:
        return {'success': False, 'message': '端口转发功能已禁用'}
    
    try:
        # 删除PREROUTING规则
        cmd = f"{CONFIG['port_forwarding']['iptables_path']} -t nat -D PREROUTING {rule_num}"
        result = execute_sudo_command(cmd)
        
        if not result['success']:
            return {'success': False, 'message': f'删除规则失败: {" ".join(result["error"])}'}
        
        # 保存规则（如果配置了规则文件）
        if CONFIG['port_forwarding'].get('rules_file'):
            save_result = execute_sudo_command(f"{CONFIG['port_forwarding']['iptables_path']}-save > {CONFIG['port_forwarding']['rules_file']}")
            if not save_result['success']:
                return {'success': True, 'message': '规则已删除但保存失败，重启后可能恢复'}
        
        return {'success': True, 'message': '端口转发规则删除成功'}
    
    except Exception as e:
        return {'success': False, 'message': f'删除规则时出错: {str(e)}'}

# 路由定义
@app.route('/')
def index():
    """首页重定向"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('containers'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in CONFIG['users'] and CONFIG['users'][username]['password'] == password:
            session['username'] = username
            session['user_role'] = CONFIG['users'][username]['role']
            session['allowed_containers'] = CONFIG['users'][username]['allowed_containers']
            session['authenticated'] = True
            
            flash('登录成功！', 'success')
            return redirect(url_for('containers'))
        else:
            flash('用户名或密码错误！', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

@app.route('/containers')
@login_required
def containers():
    """容器管理页面"""
    containers_list = get_containers()
    return render_template('containers.html', 
                         containers=containers_list, 
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/monitor')
@login_required
def monitor():
    """资源监控页面"""
    if not check_permission('monitor'):
        flash('没有权限访问资源监控页面', 'error')
        return redirect(url_for('containers'))
    
    containers_list = get_containers()
    return render_template('monitor.html', 
                         containers=containers_list,
                         user_role=session.get('user_role'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_container():
    """创建容器页面"""
    if not check_permission('create_own'):
        flash('没有权限创建容器', 'error')
        return redirect(url_for('containers'))
    
    if request.method == 'POST':
        container_name = request.form.get('container_name', '').strip()
        template = request.form.get('template')
        cpu_limit = request.form.get('cpu_limit', '').strip()
        memory_limit = request.form.get('memory_limit', '').strip()
        
        if not container_name:
            flash('请填写容器名称', 'error')
            return redirect(url_for('create_container'))
        
        if not template:
            flash('请选择模板', 'error')
            return redirect(url_for('create_container'))
        
        final_name = generate_container_name(container_name)
        
        if not re.match(r'^[a-z0-9\-_]+$', final_name):
            flash('容器名称只能包含小写字母、数字、横线和下划线', 'error')
            return redirect(url_for('create_container'))
        
        existing_containers = get_containers()
        if final_name in existing_containers:
            flash('容器已存在', 'error')
            return redirect(url_for('create_container'))
        
        if not check_container_permission(final_name):
            flash('没有权限创建此名称的容器', 'error')
            return redirect(url_for('create_container'))
        
        result = execute_lxc_command(f"launch {template} {final_name}")
        
        if not result['success']:
            error_msg = " ".join(result['error']) if result['error'] else "未知错误"
            flash(f'创建失败: {error_msg}', 'error')
            return redirect(url_for('create_container'))
        
        if cpu_limit:
            execute_lxc_command(f"config set {final_name} limits.cpu {cpu_limit}")
        
        if memory_limit:
            execute_lxc_command(f"config set {final_name} limits.memory {memory_limit}")
        
        flash(f'容器 {final_name} 创建成功', 'success')
        return redirect(url_for('containers'))
    
    return render_template('create.html', 
                         templates=CONFIG['templates'],
                         default_limits=CONFIG['default_limits'],
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/backup')
@login_required
def backup_management():
    """备份管理页面 - 修复版本"""
    if not check_permission('backup'):
        flash('没有权限访问备份管理页面', 'error')
        return redirect(url_for('containers'))
    
    backups = get_backups()
    containers_list = get_containers()
    
    return render_template('backup.html', 
                         backups=backups,
                         containers=containers_list,
                         user_role=session.get('user_role'))

@app.route('/port_forwarding')
@login_required
def port_forwarding():
    """端口转发管理页面 - 修复版本"""
    if not check_permission('port_forwarding'):
        flash('没有权限访问端口转发管理页面', 'error')
        return redirect(url_for('containers'))
    
    rules = get_port_forwarding_rules()
    containers_list = get_containers()
    
    return render_template('port_forwarding.html',
                         rules=rules,
                         containers=containers_list,
                         user_role=session.get('user_role'),
                         port_config=CONFIG['port_forwarding'])

@app.route('/admin/system_status')
@login_required
def admin_system_status():
    """系统状态检查页面 - 修复版本"""
    if not check_permission('monitor'):
        flash('没有权限访问系统状态页面', 'error')
        return redirect(url_for('containers'))
    
    # 获取LXD服务状态
    lxd_service_status = execute_sudo_command("systemctl is-active snap.lxd.daemon")
    lxd_service_info = execute_sudo_command("systemctl status snap.lxd.daemon")
    
    # 获取LXD版本信息
    lxd_version = execute_lxc_command("--version")
    
    # 获取存储池信息
    storage_pools_result = execute_lxc_command("storage list --format json")
    storage_pools = []
    if storage_pools_result['success'] and storage_pools_result['output']:
        try:
            storage_pools = json.loads(''.join(storage_pools_result['output']))
        except:
            pass
    
    # 获取网络信息
    networks_result = execute_lxc_command("network list --format json")
    networks = []
    if networks_result['success'] and networks_result['output']:
        try:
            networks = json.loads(''.join(networks_result['output']))
        except:
            pass
    
    # 获取配置文件信息
    profiles_result = execute_lxc_command("profile list --format json")
    profiles = []
    if profiles_result['success'] and profiles_result['output']:
        try:
            profiles = json.loads(''.join(profiles_result['output']))
        except:
            pass
    
    # 获取容器统计信息
    containers_result = execute_lxc_command("list --format json")
    container_stats = {
        'total': 0,
        'running': 0,
        'stopped': 0,
        'frozen': 0,
        'error': 0
    }
    
    if containers_result['success'] and containers_result['output']:
        try:
            containers_data = json.loads(''.join(containers_result['output']))
            container_stats['total'] = len(containers_data)
            
            for container in containers_data:
                status = container.get('status', '').lower()
                if status == 'running':
                    container_stats['running'] += 1
                elif status == 'stopped':
                    container_stats['stopped'] += 1
                elif status == 'frozen':
                    container_stats['frozen'] += 1
                elif status == 'error':
                    container_stats['error'] += 1
        except:
            pass
    
    # 获取系统资源使用情况
    system_info = {
        'hostname': execute_command("hostname")['output'][0] if execute_command("hostname")['success'] and execute_command("hostname")['output'] else '未知',
        'uptime': execute_command("uptime -p")['output'][0] if execute_command("uptime -p")['success'] and execute_command("uptime -p")['output'] else '未知',
        'load_average': execute_command("cat /proc/loadavg")['output'][0] if execute_command("cat /proc/loadavg")['success'] and execute_command("cat /proc/loadavg")['output'] else '未知',
        'memory_usage': execute_command("free -h")['output'] if execute_command("free -h")['success'] else [],
        'disk_usage': execute_command("df -h /")['output'] if execute_command("df -h /")['success'] else []
    }
    
    # 检查关键服务状态
    services_status = {
        'lxd': lxd_service_status,
        'apparmor': execute_sudo_command("systemctl is-active apparmor"),
        'ufw': execute_sudo_command("systemctl is-active ufw"),
        'iptables': execute_sudo_command("systemctl is-active iptables")
    }
    
    # 检查备份目录状态
    backup_dir = CONFIG['backup_path']
    backup_status = {
        'exists': os.path.exists(backup_dir),
        'writable': os.access(backup_dir, os.W_OK) if os.path.exists(backup_dir) else False,
        'size': 0
    }
    
    if backup_status['exists']:
        try:
            # 计算备份目录大小
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(backup_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total_size += os.path.getsize(fp)
            backup_status['size'] = total_size
        except:
            pass
    
    # 获取容器列表用于显示
    containers_list = get_containers()
    
    return render_template('admin_system_status.html',
                         lxd_service_status=lxd_service_status,
                         lxd_service_info=lxd_service_info,
                         lxd_version=lxd_version,
                         storage_pools=storage_pools,
                         networks=networks,
                         profiles=profiles,
                         container_stats=container_stats,
                         system_info=system_info,
                         services_status=services_status,
                         backup_status=backup_status,
                         containers=containers_list,
                         config=CONFIG,
                         user_role=session.get('user_role'))

@app.route('/backup/create', methods=['POST'])
@login_required
def create_backup():
    """创建备份"""
    container_name = request.form.get('container_name')
    
    if not container_name:
        flash('参数错误', 'error')
        return redirect(url_for('containers'))
    
    if not check_permission('backup', container_name):
        flash('没有权限备份此容器', 'error')
        return redirect(url_for('containers'))
    
    # 创建备份目录
    backup_dir = CONFIG['backup_path']
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_name = f"{container_name}_backup_{timestamp}"
    
    # 创建快照
    result = execute_lxc_command(f"publish {container_name} --alias {backup_name}")
    
    if not result['success']:
        flash(f'备份创建失败: {" ".join(result["error"])}', 'error')
        return redirect(url_for('containers'))
    
    # 导出备份
    export_file = os.path.join(backup_dir, f"{backup_name}.tar.gz")
    result = execute_lxc_command(f"image export {backup_name} {export_file}")
    
    # 删除临时镜像
    execute_lxc_command(f"image delete {backup_name}")
    
    if result['success']:
        flash('备份创建成功', 'success')
    else:
        flash('备份导出失败', 'error')
    
    return redirect(url_for('backup_management'))

@app.route('/backup/restore', methods=['POST'])
@login_required
def restore_backup():
    """恢复备份"""
    if not check_permission('create_own'):
        flash('没有权限恢复备份', 'error')
        return redirect(url_for('backup_management'))
    
    backup_file = request.form.get('backup_file')
    new_name = request.form.get('new_name')
    
    if not backup_file or not new_name:
        flash('参数错误', 'error')
        return redirect(url_for('backup_management'))
    
    # 生成最终的容器名称
    final_name = generate_container_name(new_name)
    
    # 导入镜像
    result = execute_lxc_command(f"image import {backup_file} temp_restore")
    
    if not result['success']:
        flash('备份导入失败', 'error')
        return redirect(url_for('backup_management'))
    
    # 从镜像启动容器
    result = execute_lxc_command(f"launch temp_restore {final_name}")
    
    # 删除临时镜像
    execute_lxc_command("image delete temp_restore")
    
    if result['success']:
        flash(f'备份恢复成功，容器名: {final_name}', 'success')
    else:
        flash('恢复失败', 'error')
    
    return redirect(url_for('containers'))

@app.route('/backup/download/<filename>')
@login_required
def download_backup(filename):
    """下载备份文件"""
    if not check_permission('backup'):
        flash('没有权限下载备份', 'error')
        return redirect(url_for('backup_management'))
    
    file_path = os.path.join(CONFIG['backup_path'], filename)
    
    if not os.path.exists(file_path):
        flash('备份文件不存在', 'error')
        return redirect(url_for('backup_management'))
    
    # 检查用户是否有权限下载此备份
    container_name = filename.split('_backup_')[0]
    if not check_container_permission(container_name):
        flash('没有权限下载此备份', 'error')
        return redirect(url_for('backup_management'))
    
    return send_file(file_path, as_attachment=True)

@app.route('/backup/delete', methods=['POST'])
@login_required
def delete_backup():
    """删除备份"""
    if not check_permission('backup'):
        flash('没有权限删除备份', 'error')
        return redirect(url_for('backup_management'))
    
    backup_file = request.form.get('backup_file')
    
    if not backup_file:
        flash('参数错误', 'error')
        return redirect(url_for('backup_management'))
    
    file_path = os.path.join(CONFIG['backup_path'], backup_file)
    
    # 检查用户是否有权限删除此备份
    container_name = backup_file.split('_backup_')[0]
    if not check_container_permission(container_name):
        flash('没有权限删除此备份', 'error')
        return redirect(url_for('backup_management'))
    
    try:
        os.remove(file_path)
        flash('备份删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'error')
    
    return redirect(url_for('backup_management'))

@app.route('/port_forwarding/add', methods=['POST'])
@login_required
def add_port_forward():
    """添加端口转发规则"""
    if not check_permission('port_forwarding'):
        return jsonify({'success': False, 'message': '没有权限添加端口转发规则'})
    
    protocol = request.form.get('protocol', 'tcp')
    external_port = request.form.get('external_port')
    container_name = request.form.get('container_name')
    internal_port = request.form.get('internal_port')
    description = request.form.get('description', '')
    
    if not all([protocol, external_port, container_name, internal_port]):
        return jsonify({'success': False, 'message': '请填写所有必填字段'})
    
    result = add_port_forwarding_rule(protocol, external_port, container_name, internal_port, description)
    
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')
    
    return jsonify(result)

@app.route('/port_forwarding/delete', methods=['POST'])
@login_required
def delete_port_forward():
    """删除端口转发规则"""
    if not check_permission('port_forwarding'):
        return jsonify({'success': False, 'message': '没有权限删除端口转发规则'})
    
    rule_num = request.form.get('rule_num')
    protocol = request.form.get('protocol', 'tcp')
    
    if not rule_num:
        return jsonify({'success': False, 'message': '规则编号不能为空'})
    
    result = delete_port_forwarding_rule(rule_num, protocol)
    
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')
    
    return jsonify(result)

@app.route('/container/action', methods=['POST'])
@login_required
def container_action():
    """容器操作（启动、停止、重启、删除等）"""
    action = request.form.get('action')
    container_name = request.form.get('container_name')
    
    if not container_name or not action:
        flash('参数错误', 'error')
        return redirect(url_for('containers'))
    
    if not check_permission(action, container_name):
        flash(f'没有权限执行 {action} 操作', 'error')
        return redirect(url_for('containers'))
    
    if action in ['start', 'stop', 'restart', 'freeze', 'unfreeze']:
        result = execute_lxc_command(f"{action} {container_name}")
    elif action == 'delete':
        result = execute_lxc_command(f"delete {container_name} --force")
    else:
        flash('不支持的操作', 'error')
        return redirect(url_for('containers'))
    
    if result['success']:
        flash(f'操作执行成功: {action} {container_name}', 'success')
    else:
        flash(f'操作失败: {" ".join(result["error"])}', 'error')
    
    return redirect(url_for('containers'))

# 错误处理
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='页面未找到'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='服务器内部错误'), 500

if __name__ == '__main__':
    # 创建必要的目录
    os.makedirs(CONFIG['backup_path'], exist_ok=True)
    
    # 启动Flask应用
    app.run(host='0.0.0.0', port=5000, debug=True)
