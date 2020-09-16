import json
from insite_plugin import InsitePlugin
from process_monitor import state_mon, service_state


class Plugin(InsitePlugin):

    def can_group(self):
        return False

    def fetch(self, hosts):

        host = hosts[-1]

        try:

            self.monitor

        except Exception:

            mon_args = {
                'beat': host,
                'elastichost': '172.16.205.201',
                'timesync_enable': True,
                'query_window': 90,
                'services': ['mysqld', 'nginx', 'python2.7::eventd', 'python::test.py', 'python2.7::triton']
            }

            self.monitor = state_mon(**mon_args)

        documents = []

        for service in self.monitor.generate_state():

            fields = {
                'name': service.name,
                'status_descr': service.status_descr,
                'status': service.status,
                'd_cpu_pct': service.cpu_pct,
                'd_memory_pct': service.memory_pct,
                'l_memory_bytes': service.memory_bytes,
                'pid': service.pid,
                'num_processes': service.num_processes if len(service) == 0 else len(service),
                'subs': len(service),
                'failed': service.failed,
                'state': service.state,
                'duration': str(service.duration),
                'description': str(service),
                'type': 'overall'
            }

            document = {
                'fields': fields,
                'host': host,
                'name': 'state_mon'
            }

            documents.append(document)

            for sub in service:

                fields = {
                    'name': sub.name,
                    'status_descr': sub.status_descr,
                    'status': sub.status,
                    'd_cpu_pct': sub.cpu_pct,
                    'd_memory_pct': sub.memory_pct,
                    'l_memory_bytes': sub.memory_bytes,
                    'pid': sub.pid,
                    'num_processes': sub.num_processes,
                    'failed': sub.failed,
                    'state': sub.state,
                    'duration': str(sub.duration),
                    'description': str(sub),
                    'parent': service.name,
                    'type': 'sub'
                }

                document = {
                    'fields': fields,
                    'host': host,
                    'name': 'state_mon'
                }

                documents.append(document)

        fields = {
            'name': self.monitor.summary.name,
            'status_descr': self.monitor.summary.status_descr,
            'status': self.monitor.summary.status,
            'd_cpu_pct': self.monitor.summary.cpu_pct,
            'd_memory_pct': self.monitor.summary.memory_pct,
            'l_memory_bytes': self.monitor.summary.memory_bytes,
            'pid': self.monitor.summary.pid,
            'num_processes': self.monitor.summary.num_processes,
            'failed': self.monitor.summary.failed,
            'state': self.monitor.summary.state,
            'duration': str(self.monitor.summary.duration),
            'description': str(self.monitor.summary),
            'type': 'summary'
        }

        document = {
            'fields': fields,
            'host': host,
            'name': 'state_mon'
        }

        documents.append(document)

        return json.dumps(documents)

    def dispose(self):

        try:

            self.monitor.close()

        except Exception:
            pass
