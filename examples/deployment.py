"""Deployment generation example with dynamic values."""
import templatizer
from templatizer import k8s

# pylint: disable=E0202


class CoolBinaryContainer(k8s.Container):
    """Defines a container with tweakable resource requests."""

    def __init__(self, big: bool) -> None:
        super().__init__("my-cool-binary", imagePullPolicy="IfNotPresent")

        self.is_big = big

    command = ["/bin/true"]
    image = "gcr.io/my/cool-binary:latest"

    @property
    def resources(self) -> k8s.ResourceRequirements:
        """Returns resources depending on the 'big' value."""
        cpu = "1"
        memory = "1Gi"

        if self.is_big:
            cpu = "4"
            memory = "4Gi"

        return k8s.ResourceRequirements(
            limits={
                "cpu": cpu,
                "memory": memory,
            },
            requests={
                "cpu": cpu,
                "memory": memory,
            },
        )


class CoolBinaryPodSpec(k8s.PodSpec):
    """Defines a PodSpec that includes a single CoolBinaryContainer."""

    def __init__(self, big: bool) -> None:
        super().__init__(
            [
                CoolBinaryContainer(big),
            ]
        )


class CoolBinaryTemplate(k8s.PodTemplateSpec):
    """Defines a template for a Deployment."""

    def __init__(self, name: str, big: bool) -> None:
        super().__init__()

        self.name = name
        self.is_big = big

    @property
    def metadata(self) -> k8s.ObjectMeta:
        """Returns metadata for the template."""
        return k8s.ObjectMeta(
            labels={
                "name": self.name,
            },
        )

    @property
    def spec(self) -> k8s.PodSpec:
        """Returns the PodSpec for this template."""
        return CoolBinaryPodSpec(self.is_big)


class MyCoolBinary(k8s.Deployment):
    """Defines a full Kubernetes deployment with tweakable parameters."""

    def __init__(self, name: str, big: bool) -> None:
        super().__init__()

        self.name = name
        self.is_big = big

    @property
    def metadata(self) -> k8s.ObjectMeta:
        """Returns metadata for the Deployment."""
        return k8s.ObjectMeta(
            name=self.name,
            namespace="cool-namespace",
        )

    @property
    def spec(self) -> k8s.DeploymentSpec:
        """Returns a deployment spec for the Deployment."""
        return k8s.DeploymentSpec(
            replicas=5,
            template=CoolBinaryTemplate(self.name, self.is_big),
            selector=k8s.LabelSelector(
                matchLabels={
                    "name": self.name,
                },
            ),
        )


if __name__ == "__main__":
    print(
        templatizer.run(
            [
                MyCoolBinary("my-cool-binary", False),
                MyCoolBinary("my-beefy-cool-binary", True),
            ]
        )
    )
