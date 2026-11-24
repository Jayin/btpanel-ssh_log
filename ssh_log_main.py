# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 - SSH登录日志插件
# +-------------------------------------------------------------------
# | Author: Rover
# +-------------------------------------------------------------------

import os
import sys
import re
import json
import time
import glob
import ipaddress
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

os.chdir("/www/server/panel")
sys.path.append("class/")
import public


class ssh_log_main:
    # 扫描与数据配置常量（解耦硬编码）
    MAX_SCAN_LINES = 15000          # 日志最大解析行数
    OVERVIEW_SCAN_LINES = 8000      # 概览看板扫描行数
    MAX_CACHE_SIZE = 3000           # IP 缓存最大条数
    TOP_ATTACKERS_LIMIT = 20        # 爆破榜 TOP 条数
    DEFAULT_PAGE_SIZE = 15          # 默认每页大小
    THREAD_POOL_WORKERS = 8         # 归属地并发解析线程数

    def __init__(self):
        # 动态获取宝塔安装根目录，杜绝写死 /www/server/panel
        self._panel_path = public.get_panel_path()
        self._plugin_path = os.path.join(self._panel_path, "plugin", "ssh_log")
        self._cache_file = os.path.join(self._plugin_path, "ip_cache.json")
        self._ip_cache = {}
        self._load_cache()

    def _load_cache(self):
        """加载 IP 归属地缓存"""
        if os.path.exists(self._cache_file):
            try:
                content = public.readFile(self._cache_file)
                if content:
                    self._ip_cache = json.loads(content)
            except:
                self._ip_cache = {}

    def _save_cache(self):
        """保存 IP 归属地缓存"""
        try:
            if not os.path.exists(self._plugin_path):
                os.makedirs(self._plugin_path, 0o755)
            # 控制缓存大小，超出限制时保留最新的条目
            if len(self._ip_cache) > self.MAX_CACHE_SIZE:
                keys = list(self._ip_cache.keys())[-int(self.MAX_CACHE_SIZE * 0.7):]
                self._ip_cache = {k: self._ip_cache[k] for k in keys}
            public.writeFile(self._cache_file, json.dumps(self._ip_cache, ensure_ascii=False))
        except:
            pass

    def _is_local_ip(self, ip):
        """
        基于 Python 标准 ipaddress 库严格判定局域网/保留/回环 IP
        杜绝使用特定的子网前缀硬编码（如 100.113.）
        """
        if not ip or ip in ['-', '未知', 'localhost', '::1', '0.0.0.0']:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            # 检测是否为私网、回环、保留地址、链路本地
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return True
            # RFC 6598 运营商级 NAT (100.64.0.0/10)
            cgnat_net = ipaddress.ip_network('100.64.0.0/10')
            if ip_obj in cgnat_net:
                return True
        except:
            pass
        return False

    def _get_current_client_ip(self):
        """动态获取当前面板访问者的 IP 地址，防止误封锁管理员自身"""
        try:
            client_ip = public.get_client_ip()
            if client_ip:
                return client_ip.split(':')[0].strip()
        except:
            pass
        return ""

    def _is_safe_ip(self, ip, client_ip=""):
        """判断是否为安全保护 IP（内网/本机/当前管理员IP）"""
        if self._is_local_ip(ip):
            return True
        if client_ip and ip == client_ip:
            return True
        return False

    def _get_ip_location(self, ip):
        """获取 IP 归属地（带并发缓存）"""
        if not ip or ip in ['-', '未知', '']:
            return '未知'

        if ip in ['127.0.0.1', 'localhost', '::1']:
            return '本机回环 (Localhost)'
        if self._is_local_ip(ip):
            return '局域网/专用网络 (NAT)'

        if ip in self._ip_cache:
            return self._ip_cache[ip]

        # 调用宝塔免费 IP 库查询
        try:
            info = public.get_free_ip_info(ip)
            area = ''
            if isinstance(info, dict):
                carrier = info.get('carrier', '').strip()
                country = info.get('country', '').strip()
                province = info.get('province', '').strip()
                city = info.get('city', '').strip()

                parts = []
                for p in [country, province, city, carrier]:
                    if p and p not in parts and p not in ['保留', '未知']:
                        parts.append(p)
                area = ' '.join(parts) if parts else info.get('info', '未知归属地')
            if not area:
                area = '未知归属地'
            self._ip_cache[ip] = area
            return area
        except:
            return '未知归属地'

    def _resolve_ips_parallel(self, ips):
        """并发批量解析未缓存的 IP 归属地"""
        uncached = [ip for ip in set(ips) if ip and ip not in self._ip_cache and not self._is_local_ip(ip)]
        if uncached:
            try:
                with ThreadPoolExecutor(max_workers=self.THREAD_POOL_WORKERS) as executor:
                    list(executor.map(self._get_ip_location, uncached))
                self._save_cache()
            except:
                pass

    def _get_log_files(self):
        """
        动态探测系统 SSH 日志文件：
        同时兼容 Debian/Ubuntu (/var/log/auth.log) 以及 CentOS/RHEL (/var/log/secure)
        并支持 .1 与 -YYYYMMDD 日期轮转格式
        """
        files = []
        candidates = ['/var/log/auth.log', '/var/log/secure']
        for base in candidates:
            if os.path.exists(base):
                files.append(base)
            # 兼容两类轮转文件：.1 (Debian规范) 和 -YYYYMMDD (CentOS规范)
            rotated = glob.glob(base + '.1') + glob.glob(base + '-[0-9]*')
            for r in sorted(rotated, reverse=True)[:2]:
                if os.path.isfile(r) and not r.endswith('.gz') and r not in files:
                    files.append(r)
        return files

    def _parse_time(self, line):
        """提取并格式化日志时间为 YYYY-MM-DD HH:mm:ss（跨年安全）"""
        # 匹配 ISO 格式 2026-11-24T11:22:46...
        m1 = re.match(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', line)
        if m1:
            return f"{m1.group(1)} {m1.group(2)}"

        # 匹配标准 Syslog 格式: Nov 24 11:22:46
        m2 = re.match(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})', line)
        if m2:
            mon_str, day_str, time_str = m2.group(1), m2.group(2), m2.group(3)
            now = datetime.now()
            current_year = now.year
            try:
                dt = datetime.strptime(f"{current_year} {mon_str} {day_str} {time_str}", "%Y %b %d %H:%M:%S")
                # 跨年处理：如果当前是 1 月，日志是 12 月，则年份减 1
                if now.month == 1 and dt.month == 12:
                    dt = dt.replace(year=current_year - 1)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                return f"{mon_str} {day_str} {time_str}"

        return ""

    def _get_blocked_ips_set(self):
        """获取当前防火墙黑名单中的 IP 集合"""
        try:
            records = public.M('firewall').where('port like ?', ('%.%',)).select()
            return set(r['port'].split('/')[0] for r in records if 'port' in r)
        except:
            return set()

    def _scan_all_events(self, max_lines=None):
        """扫描日志并解析所有 SSH 事件"""
        if max_lines is None:
            max_lines = self.MAX_SCAN_LINES

        patterns = [
            # 登录成功 (公钥或密码)
            (re.compile(r'Accepted\s+(?P<method>publickey|password|keyboard-interactive)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)'), 
             'success', '登录成功'),
            # 非法用户密码错误
            (re.compile(r'Failed\s+(?P<method>password|publickey)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)'), 
             'invalid', '非法用户尝试'),
            # 合法用户密码错误
            (re.compile(r'Failed\s+(?P<method>password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)'), 
             'failed', '密码错误'),
            # 未知用户探测
            (re.compile(r'Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)'), 
             'invalid', '非法用户探测'),
            # 认证尝试超限
            (re.compile(r'maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+)\s+port\s+(?P<port>\d+)'), 
             'failed', '尝试次数超限'),
        ]

        log_files = self._get_log_files()
        raw_lines = []

        # 读取匹配的日志行
        for fpath in log_files:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                    for line in fp:
                        if 'sshd' in line or 'sshd-session' in line:
                            raw_lines.append(line)
            except:
                pass

        if len(raw_lines) > max_lines:
            raw_lines = raw_lines[-max_lines:]

        events = []
        for line in raw_lines:
            for pat, status, desc in patterns:
                m = pat.search(line)
                if m:
                    gd = m.groupdict()
                    t_str = self._parse_time(line)
                    method = gd.get('method', '-')
                    if method == 'publickey':
                        method_label = '公钥'
                    elif method == 'password':
                        method_label = '密码'
                    else:
                        method_label = '-'

                    events.append({
                        'time': t_str,
                        'status': status,
                        'desc': desc,
                        'user': gd.get('user', '-'),
                        'ip': gd.get('ip', '-'),
                        'port': gd.get('port', '-'),
                        'method': method_label
                    })
                    break

        events.reverse()
        return events

    # ==================== 接口方法 ====================

    def get_overview(self, get=None):
        """获取统计概览数据"""
        events = self._scan_all_events(max_lines=self.OVERVIEW_SCAN_LINES)
        today_str = datetime.now().strftime("%Y-%m-%d")

        today_success = 0
        today_failed = 0
        today_attacker_ips = set()
        latest_success = None

        for ev in events:
            ev_date = ev['time'].split(' ')[0] if ' ' in ev['time'] else ''
            if ev_date == today_str:
                if ev['status'] == 'success':
                    today_success += 1
                    if not latest_success:
                        latest_success = ev
                else:
                    today_failed += 1
                    today_attacker_ips.add(ev['ip'])

        if not latest_success:
            for ev in events:
                if ev['status'] == 'success':
                    latest_success = ev
                    break

        ssh_info = self.get_ssh_info()
        active_sessions = self.get_active_sessions()

        return public.returnMsg(True, {
            'today_success': today_success,
            'today_failed': today_failed,
            'today_attackers': len(today_attacker_ips),
            'active_sessions_count': len(active_sessions),
            'ssh_port': ssh_info.get('port', 22),
            'sshd_status': ssh_info.get('status', 'running'),
            'latest_success': latest_success or {}
        })

    def get_logs(self, get):
        """获取分页日志列表"""
        p = int(get.get('p', 1))
        row = int(get.get('row', self.DEFAULT_PAGE_SIZE))
        filter_status = get.get('status', 'all').strip()
        search_kw = get.get('search', '').strip().lower()
        date_filter = get.get('date', 'all').strip()

        events = self._scan_all_events()

        today_str = datetime.now().strftime("%Y-%m-%d")
        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        filtered = []
        for ev in events:
            # 状态过滤
            if filter_status == 'success' and ev['status'] != 'success':
                continue
            elif filter_status == 'failed' and ev['status'] != 'failed':
                continue
            elif filter_status == 'invalid' and ev['status'] != 'invalid':
                continue
            elif filter_status == 'all_failed' and ev['status'] not in ['failed', 'invalid']:
                continue

            # 日期过滤
            ev_date = ev['time'].split(' ')[0] if ' ' in ev['time'] else ''
            if date_filter == 'today' and ev_date != today_str:
                continue
            elif date_filter == 'yesterday' and ev_date != yesterday_str:
                continue

            # 关键词过滤 (用户名或 IP)
            if search_kw:
                if search_kw not in ev['ip'].lower() and search_kw not in ev['user'].lower():
                    continue

            filtered.append(ev)

        total_count = len(filtered)
        total_page = (total_count + row - 1) // row if row > 0 else 1
        start_idx = (p - 1) * row
        end_idx = start_idx + row
        page_events = filtered[start_idx:end_idx]

        blocked_ips = self._get_blocked_ips_set()
        client_ip = self._get_current_client_ip()

        # 并发解析当前页未缓存的 IP 归属地
        current_ips = [ev['ip'] for ev in page_events]
        self._resolve_ips_parallel(current_ips)

        for ev in page_events:
            ev['area'] = self._get_ip_location(ev['ip'])
            ev['blocked'] = ev['ip'] in blocked_ips
            # 动态标识是否允许封锁（保护管理员与内网IP）
            ev['can_block'] = not self._is_safe_ip(ev['ip'], client_ip)

        return public.returnMsg(True, {
            'data': page_events,
            'page': {
                'p': p,
                'row': row,
                'count': total_count,
                'total_page': total_page
            }
        })

    def get_top_attackers(self, get=None):
        """获取爆破攻击 TOP 榜单（尝试失败次数最多的 IP）"""
        events = self._scan_all_events(max_lines=self.MAX_SCAN_LINES)
        attack_map = {}

        for ev in events:
            if ev['status'] in ['failed', 'invalid']:
                ip = ev['ip']
                if ip not in attack_map:
                    attack_map[ip] = {
                        'ip': ip,
                        'count': 0,
                        'users': set(),
                        'last_time': ev['time'],
                        'first_time': ev['time']
                    }
                attack_map[ip]['count'] += 1
                if ev['user'] and ev['user'] != '-':
                    attack_map[ip]['users'].add(ev['user'])

        sorted_attacks = sorted(attack_map.values(), key=lambda x: x['count'], reverse=True)[:self.TOP_ATTACKERS_LIMIT]
        blocked_ips = self._get_blocked_ips_set()
        client_ip = self._get_current_client_ip()

        top_ips = [item['ip'] for item in sorted_attacks]
        self._resolve_ips_parallel(top_ips)

        for item in sorted_attacks:
            item['users'] = list(item['users'])[:5]
            item['area'] = self._get_ip_location(item['ip'])
            item['blocked'] = item['ip'] in blocked_ips
            item['can_block'] = not self._is_safe_ip(item['ip'], client_ip)

        return public.returnMsg(True, sorted_attacks)

    def get_active_sessions(self, get=None):
        """获取当前在线会话"""
        sessions = []
        try:
            output = subprocess.check_output(['w', '-h'], encoding='utf-8', errors='ignore')
            blocked_ips = self._get_blocked_ips_set()
            client_ip = self._get_current_client_ip()
            for line in output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    from_ip = parts[2]
                    clean_ip = from_ip.split(':')[0]
                    area = self._get_ip_location(clean_ip) if clean_ip else '-'
                    what_cmd = ' '.join(parts[7:]) if len(parts) > 7 else (parts[6] if len(parts) > 6 else '')

                    sessions.append({
                        'user': parts[0],
                        'tty': parts[1],
                        'from': from_ip,
                        'login': parts[3],
                        'idle': parts[4],
                        'what': what_cmd,
                        'area': area,
                        'blocked': clean_ip in blocked_ips,
                        'can_block': not self._is_safe_ip(clean_ip, client_ip)
                    })
        except:
            pass
        return sessions

    def get_active_sessions_api(self, get=None):
        """API 包装"""
        return public.returnMsg(True, self.get_active_sessions(get))

    def kill_session(self, get):
        """终止指定 TTY 会话"""
        tty = get.get('tty', '').strip()
        if not tty or not re.match(r'^[a-zA-Z0-9/]+$', tty):
            return public.returnMsg(False, '无效的终端名称')

        try:
            public.ExecShell(f"pkill -9 -t {tty}")
            return public.returnMsg(True, f"已终止终端 [{tty}] 的连接会话")
        except Exception as e:
            return public.returnMsg(False, f"终止终端失败: {str(e)}")

    def block_ip(self, get):
        """封锁指定 IP（加入防火墙黑名单）"""
        ip = get.get('ip', '').strip()
        if not ip or not public.check_ip(ip):
            return public.returnMsg(False, 'IP 地址格式不正确')

        client_ip = self._get_current_client_ip()
        if self._is_safe_ip(ip, client_ip):
            return public.returnMsg(False, '该 IP 属于受保护的内网、本机或管理员当前访问 IP，禁止封锁！')

        try:
            from firewalls import firewalls
            fw = firewalls()
            p = public.dict_obj()
            p.port = ip
            p.ps = 'SSH爆破防御拦截'
            res = fw.AddDropAddress(p)
            return res
        except Exception as e:
            return public.returnMsg(False, f'封锁失败: {str(e)}')

    def unblock_ip(self, get):
        """从防火墙解封指定 IP"""
        ip = get.get('ip', '').strip()
        if not ip or not public.check_ip(ip):
            return public.returnMsg(False, 'IP 地址格式不正确')

        try:
            rec = public.M('firewall').where('port=?', (ip,)).find()
            if not rec:
                return public.returnMsg(False, f'IP [{ip}] 未在防火墙封锁名单中')

            from firewalls import firewalls
            fw = firewalls()
            p = public.dict_obj()
            p.id = rec['id']
            p.port = ip
            res = fw.DelDropAddress(p)
            return res
        except Exception as e:
            return public.returnMsg(False, f'解封失败: {str(e)}')

    def batch_block(self, get):
        """批量封锁高危 IP"""
        ips = get.get('ips', '')
        if isinstance(ips, str):
            ip_list = [x.strip() for x in ips.split(',') if x.strip()]
        else:
            ip_list = list(ips)

        success_count = 0
        from firewalls import firewalls
        fw = firewalls()
        client_ip = self._get_current_client_ip()

        for ip in ip_list:
            if public.check_ip(ip) and not self._is_safe_ip(ip, client_ip):
                p = public.dict_obj()
                p.port = ip
                p.ps = 'SSH高频爆破批量拦截'
                try:
                    res = fw.AddDropAddress(p)
                    if res.get('status'):
                        success_count += 1
                except:
                    pass
        return public.returnMsg(True, f'成功批量封锁 {success_count} 个高危 IP')

    def get_ssh_info(self, get=None):
        """
        动态读取 SSH 服务配置与运行状态：
        兼容 /etc/ssh/sshd_config 以及 /etc/ssh/sshd_config.d/*.conf 覆盖配置
        """
        # 优先使用宝塔内置 API 获取端口， fallback 22
        try:
            port = public.get_ssh_port()
        except:
            port = 22

        permit_root = '未知'
        password_auth = '未知'

        # 收集所有 sshd 配置文件
        conf_files = ['/etc/ssh/sshd_config']
        if os.path.exists('/etc/ssh/sshd_config.d'):
            for sub_conf in glob.glob('/etc/ssh/sshd_config.d/*.conf'):
                conf_files.append(sub_conf)

        for cf in conf_files:
            if os.path.exists(cf):
                content = public.readFile(cf)
                if content:
                    # 匹配未被注释的有效参数
                    r_match = re.search(r'^\s*PermitRootLogin\s+(\S+)', content, re.MULTILINE)
                    if r_match:
                        permit_root = r_match.group(1)
                    pw_match = re.search(r'^\s*PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
                    if pw_match:
                        password_auth = pw_match.group(1)

        # 检查服务运行状态
        status = 'running'
        out, _ = public.ExecShell("systemctl is-active ssh || systemctl is-active sshd")
        if out.strip() != 'active':
            status = 'stopped'

        return {
            'port': port,
            'status': status,
            'permit_root': permit_root,
            'password_auth': password_auth
        }

    def get_ssh_info_api(self, get=None):
        """API 包装"""
        return public.returnMsg(True, self.get_ssh_info(get))

    def clear_logs(self, get=None):
        """安全清空当前 SSH 认证日志"""
        try:
            log_files = self._get_log_files()
            cleared = []
            for f in log_files:
                if f.endswith('.1') or '-' in os.path.basename(f):
                    os.remove(f)
                    cleared.append(os.path.basename(f))
                else:
                    with open(f, 'w') as fp:
                        fp.truncate(0)
                    cleared.append(os.path.basename(f))
            return public.returnMsg(True, f"已清理日志文件: {', '.join(cleared)}")
        except Exception as e:
            return public.returnMsg(False, f"清理失败: {str(e)}")

    def export_logs(self, get=None):
        """导出所有事件为 CSV（动态写入 temp 目录）"""
        events = self._scan_all_events(max_lines=self.MAX_SCAN_LINES)
        csv_lines = ["时间,状态,事件类型,用户名,IP地址,归属地,端口,认证方式"]
        for ev in events:
            area = self._get_ip_location(ev['ip'])
            line = f"\"{ev['time']}\",\"{ev['status']}\",\"{ev['desc']}\",\"{ev['user']}\",\"{ev['ip']}\",\"{area}\",\"{ev['port']}\",\"{ev['method']}\""
            csv_lines.append(line)

        temp_dir = os.path.join(self._panel_path, "temp")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, 0o755)
        save_path = os.path.join(temp_dir, "ssh_login_logs.csv")
        public.writeFile(save_path, '\n'.join(csv_lines))
        return public.returnMsg(True, {"filename": "ssh_login_logs.csv", "path": save_path})
