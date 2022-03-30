
import templatizer
from templatizer import k8s


class CoolBinaryContainer(k8s.Container):
    def __init__(self, big, **kwargs) -> None:
        super().__init__(**kwargs)

        self.is_big = big

    name='my-cool-binary'
    command='/bin/true'
    image='gcr.io/my/cool-binary:latest'
    imagePullPolicy='IfNotPresent'

    def resources(self) -> k8s.ResourceRequirements:
        cpu = '1'
        memory = '1Gi'

        if self.is_big:
            cpu = '4'
            memory = '4Gi'

        return k8s.ResourceRequirements(
            limits={
                'cpu': cpu,
                'memory': memory,
            },
            requests={
                'cpu': cpu,
                'memory': memory,
            },
        )


class CoolBinaryPodSpec(k8s.PodSpec):
    def __init__(self, big, **kwargs) -> None:
        super().__init__(**kwargs)

        self.is_big = big

    def containers(self):
        return [
            CoolBinaryContainer(self.is_big),
        ]


class CoolBinaryTemplate(k8s.PodTemplateSpec):
    def __init__(self, name, big, **kwargs) -> None:
        super().__init__(**kwargs)

        self.name = name
        self.is_big = big

    def metadata(self):
        return k8s.ObjectMeta(
            labels={
                'name': self.name,
            },
        )

    def spec(self):
        return CoolBinaryPodSpec(self.is_big)


class MyCoolBinary(k8s.Deployment):
    def __init__(self, name, big, **kwargs) -> None:
        super().__init__(**kwargs)

        self.name = name
        self.is_big = big

    def metadata(self):
        return k8s.ObjectMeta(
            name=self.name,
            namespace='cool-namespace',
        )

    def spec(self):
        return k8s.DeploymentSpec(
            replicas=5,
            template=CoolBinaryTemplate(self.name, self.is_big),
            selector=k8s.LabelSelector(
                matchLabels={
                    'name': self.name,
                },
            )
        )


def main():
    print(templatizer.run([
        MyCoolBinary('my-cool-binary', False),
        MyCoolBinary('my-beefy-cool-binary', True),
    ]))


if __name__ == '__main__':
    main()