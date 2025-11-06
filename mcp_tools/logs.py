import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from app.models import LogEntry
import aiofiles

class LogsReader:
    def __init__(self):
        self.log_patterns = {
            'apache_combined': r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) \d+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"',
            'nginx_json': None,  # Will use JSON parsing
            'jsonl': None,       # Will use JSON parsing
            'auth': r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>[^"]*)" (?P<status>\d+)'
        }
        self.json_keys = {
            'timestamp': ['ts', 'timestamp', 'time'],
            'ip': ['ip', 'remote_addr', 'client_ip'],
            'user': ['user', 'username', 'remote_user'],
            'endpoint': ['endpoint', 'url', 'path', 'uri'],
            'status': ['status', 'status_code', 'response_code'],
            'user_agent': ['ua', 'user_agent', 'useragent']
        }
    
    async def read(self, path: str) -> List[LogEntry]:
        """Read and parse log files (.log or .jsonl)"""
        file_path = Path(path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        
        logs = []
        
        async with aiofiles.open(file_path, 'r') as f:
            if file_path.suffix == '.jsonl':
                async for line in f:
                    if line.strip():
                        try:
                            log_data = json.loads(line.strip())
                            logs.append(self._parse_json_log(log_data))
                        except json.JSONDecodeError:
                            continue
            else:
                content = await f.read()
                logs.extend(self._parse_text_logs(content))
        
        return logs
    
    def _parse_json_log(self, log_data: Dict[str, Any]) -> LogEntry:
        """Parse JSON log entry using flexible key mapping"""
        def get_field(field_name: str) -> Any:
            possible_keys = self.json_keys.get(field_name, [field_name])
            for key in possible_keys:
                if key in log_data:
                    return log_data[key]
            return None
        
        timestamp_value = get_field('timestamp') or datetime.now().isoformat()
        if isinstance(timestamp_value, str):
            timestamp = self._parse_timestamp(timestamp_value)
        else:
            timestamp = datetime.now()
            
        return LogEntry(
            timestamp=timestamp,
            ip=get_field('ip') or '',
            user=get_field('user'),
            endpoint=get_field('endpoint') or '',
            status=int(get_field('status') or 200),
            method=log_data.get('method', 'GET'),
            user_agent=get_field('user_agent'),
            payload_size=log_data.get('payload_size'),
            response_time=log_data.get('response_time')
        )
    
    def _parse_text_logs(self, content: str) -> List[LogEntry]:
        """Parse text-based log files"""
        logs = []
        lines = content.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            for log_type, pattern in self.log_patterns.items():
                if pattern and (match := re.match(pattern, line)):
                    try:
                        # Use 'ts' as the standard timestamp group name
                        timestamp_str = match.group('ts')
                        timestamp = self._parse_timestamp(timestamp_str)
                        
                        # Extract user agent if available
                        user_agent = None
                        if 'ua' in match.groupdict():
                            user_agent = match.group('ua') if match.group('ua') != '-' else None
                        
                        # Extract user if available
                        user = None
                        if 'user' in match.groupdict():
                            user = match.group('user') if match.group('user') != '-' else None
                        
                        logs.append(LogEntry(
                            timestamp=timestamp,
                            ip=match.group('ip'),
                            user=user,
                            endpoint=match.group('endpoint'),
                            status=int(match.group('status')),
                            method=match.group('method'),
                            user_agent=user_agent,
                            payload_size=None  # Not captured in these patterns
                        ))
                        break
                    except (ValueError, AttributeError):
                        continue
        
        return logs
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats"""
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str.replace(' +0000', ''), fmt.replace(' %z', ''))
            except ValueError:
                continue
        
        return datetime.now()

logs_reader = LogsReader()