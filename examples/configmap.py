
import yaml

import templatizer
from templatizer import Templatable, k8s, YamlBlob


class MonitoringConfig(YamlBlob):

    def __init__(self, cluster, job_name, pod_regex, **kwargs):
        super().__init__(**kwargs)

        self.cluster = cluster
        self.job_name = job_name
        self.pod_regex = pod_regex

    def data(self):
        return {
            'server': {
                'http_listen_port': 12345,
            },
            'prometheus': {
                'wal_directory': '/tmp/grafana-agent-wal',
                'global': {
                    'scrape_interval': '15s',
                    'external_labels': {
                        'cluster': self.cluster,
                    },
                },
                'configs': [{
                    'name': 'integrations',
                    'remote_write': [
                        {
                            'url': 'https://some-remote-write-url.com',
                            'basic_auth': {
                                'username': 'user',
                                'password': 'pass',
                            },
                        },
                    ],
                    'scrape_configs': [
                        {
                            'job_name': self.job_name,
                            'kubernetes_sd_configs': [{'role': 'pod'}],
                            'relabel_configs': [
                                {
                                    'action': 'labelmap',
                                    'regex': '__meta_kubernetes_pod_label_(.+)',
                                },
                                {
                                    'source_labels': ['__meta_kubernetes_namespace'],
                                    'regex': '(.+)',
                                    'target_label': 'namespace',
                                },
                                {
                                    'source_labels': ['__meta_kubernetes_pod_name'],
                                    'regex': '(.+)',
                                    'target_label': 'pod',
                                },
                                {
                                    'source_labels': ['__meta_kubernetes_pod_name'],
                                    'regex': self.pod_regex,
                                    'action': 'keep',
                                },
                            ],
                        },
                    ],
                }]
            }
        }


class SomeConfig(k8s.ConfigMap):
    def __init__(self, name, cfg, **kwargs):
        super().__init__()
        self._name = name
        self._cfg = cfg

    def metadata(self):
        return k8s.ObjectMeta(
            name=self._name,
            namespace='monitoring',
        )

    def data(self):
        return {
            'agent.yaml': self._cfg.generate(),
        }


def main():
    job_a = MonitoringConfig('cloud', 'envoy', 'envoy-.+')
    job_b = MonitoringConfig('cloud', 'nginx', 'nginx-.+')

    print(templatizer.run([
        SomeConfig('envoy-grafana-agent', job_a),
        SomeConfig('nginx-grafana-agent', job_b),
    ]))


if __name__ == '__main__':
    main()