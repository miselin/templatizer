"""AUTO-GENERATED FILE: DO NOT EDIT"""
# pylint: skip-file
# flake8: noqa

from typing import Any, List, Optional

from . import K8STemplatable


class io__k8s__api__admissionregistration__v1__RuleWithOperations(K8STemplatable):
    """RuleWithOperations is a tuple of Operations and Resources. It is recommended to make sure that all the tuple expansions are valid."""

    props: List[str] = ["apiGroups", "apiVersions", "operations", "resources", "scope"]
    required_props: List[str] = []

    apiGroups: Optional[List[str]] = None
    apiVersions: Optional[List[str]] = None
    operations: Optional[List[str]] = None
    resources: Optional[List[str]] = None
    scope: Optional[str] = None

    def __init__(
        self,
        apiGroups: Optional[List[str]] = None,
        apiVersions: Optional[List[str]] = None,
        operations: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
        scope: Optional[str] = None,
    ):
        super().__init__()
        if apiGroups is not None:
            self.apiGroups = apiGroups
        if apiVersions is not None:
            self.apiVersions = apiVersions
        if operations is not None:
            self.operations = operations
        if resources is not None:
            self.resources = resources
        if scope is not None:
            self.scope = scope


class io__k8s__api__admissionregistration__v1__ServiceReference(K8STemplatable):
    """ServiceReference holds a reference to Service.legacy.k8s.io"""

    props: List[str] = ["name", "namespace", "path", "port"]
    required_props: List[str] = ["namespace", "name"]

    name: str
    namespace: str
    path: Optional[str] = None
    port: Optional[int] = None

    def __init__(
        self,
        name: str,
        namespace: str,
        path: Optional[str] = None,
        port: Optional[int] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if path is not None:
            self.path = path
        if port is not None:
            self.port = port


class io__k8s__api__admissionregistration__v1__WebhookClientConfig(K8STemplatable):
    """WebhookClientConfig contains the information to make a TLS connection with the webhook"""

    props: List[str] = ["caBundle", "service", "url"]
    required_props: List[str] = []

    caBundle: Optional[str] = None
    service: Optional[io__k8s__api__admissionregistration__v1__ServiceReference] = None
    url: Optional[str] = None

    def __init__(
        self,
        caBundle: Optional[str] = None,
        service: Optional[
            io__k8s__api__admissionregistration__v1__ServiceReference
        ] = None,
        url: Optional[str] = None,
    ):
        super().__init__()
        if caBundle is not None:
            self.caBundle = caBundle
        if service is not None:
            self.service = service
        if url is not None:
            self.url = url


class io__k8s__api__apiserverinternal__v1alpha1__ServerStorageVersion(K8STemplatable):
    """An API server instance reports the version it can decode and the version it encodes objects to when persisting objects in the backend."""

    props: List[str] = ["apiServerID", "decodableVersions", "encodingVersion"]
    required_props: List[str] = []

    apiServerID: Optional[str] = None
    decodableVersions: Optional[List[str]] = None
    encodingVersion: Optional[str] = None

    def __init__(
        self,
        apiServerID: Optional[str] = None,
        decodableVersions: Optional[List[str]] = None,
        encodingVersion: Optional[str] = None,
    ):
        super().__init__()
        if apiServerID is not None:
            self.apiServerID = apiServerID
        if decodableVersions is not None:
            self.decodableVersions = decodableVersions
        if encodingVersion is not None:
            self.encodingVersion = encodingVersion


class io__k8s__api__apiserverinternal__v1alpha1__StorageVersionSpec(K8STemplatable):
    """StorageVersionSpec is an empty spec."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__api__apps__v1__StatefulSetPersistentVolumeClaimRetentionPolicy(
    K8STemplatable
):
    """StatefulSetPersistentVolumeClaimRetentionPolicy describes the policy used for PVCs created from the StatefulSet VolumeClaimTemplates."""

    props: List[str] = ["whenDeleted", "whenScaled"]
    required_props: List[str] = []

    whenDeleted: Optional[str] = None
    whenScaled: Optional[str] = None

    def __init__(
        self, whenDeleted: Optional[str] = None, whenScaled: Optional[str] = None
    ):
        super().__init__()
        if whenDeleted is not None:
            self.whenDeleted = whenDeleted
        if whenScaled is not None:
            self.whenScaled = whenScaled


class io__k8s__api__authentication__v1__BoundObjectReference(K8STemplatable):
    """BoundObjectReference is a reference to an object that a token is bound to."""

    props: List[str] = ["apiVersion", "kind", "name", "uid"]
    required_props: List[str] = []

    apiVersion: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    uid: Optional[str] = None

    def __init__(
        self,
        apiVersion: Optional[str] = None,
        kind: Optional[str] = None,
        name: Optional[str] = None,
        uid: Optional[str] = None,
    ):
        super().__init__()
        if apiVersion is not None:
            self.apiVersion = apiVersion
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if uid is not None:
            self.uid = uid


class io__k8s__api__authentication__v1__TokenRequestSpec(K8STemplatable):
    """TokenRequestSpec contains client provided parameters of a token request."""

    props: List[str] = ["audiences", "boundObjectRef", "expirationSeconds"]
    required_props: List[str] = ["audiences"]

    audiences: List[str]
    boundObjectRef: Optional[
        io__k8s__api__authentication__v1__BoundObjectReference
    ] = None
    expirationSeconds: Optional[int] = None

    def __init__(
        self,
        audiences: List[str],
        boundObjectRef: Optional[
            io__k8s__api__authentication__v1__BoundObjectReference
        ] = None,
        expirationSeconds: Optional[int] = None,
    ):
        super().__init__()
        if audiences is not None:
            self.audiences = audiences
        if boundObjectRef is not None:
            self.boundObjectRef = boundObjectRef
        if expirationSeconds is not None:
            self.expirationSeconds = expirationSeconds


class io__k8s__api__authentication__v1__TokenReviewSpec(K8STemplatable):
    """TokenReviewSpec is a description of the token authentication request."""

    props: List[str] = ["audiences", "token"]
    required_props: List[str] = []

    audiences: Optional[List[str]] = None
    token: Optional[str] = None

    def __init__(
        self, audiences: Optional[List[str]] = None, token: Optional[str] = None
    ):
        super().__init__()
        if audiences is not None:
            self.audiences = audiences
        if token is not None:
            self.token = token


class io__k8s__api__authentication__v1__UserInfo(K8STemplatable):
    """UserInfo holds the information about the user needed to implement the user.Info interface."""

    props: List[str] = ["extra", "groups", "uid", "username"]
    required_props: List[str] = []

    extra: Any
    groups: Optional[List[str]] = None
    uid: Optional[str] = None
    username: Optional[str] = None

    def __init__(
        self,
        extra: Any = None,
        groups: Optional[List[str]] = None,
        uid: Optional[str] = None,
        username: Optional[str] = None,
    ):
        super().__init__()
        if extra is not None:
            self.extra = extra
        if groups is not None:
            self.groups = groups
        if uid is not None:
            self.uid = uid
        if username is not None:
            self.username = username


class io__k8s__api__authorization__v1__NonResourceAttributes(K8STemplatable):
    """NonResourceAttributes includes the authorization attributes available for non-resource requests to the Authorizer interface"""

    props: List[str] = ["path", "verb"]
    required_props: List[str] = []

    path: Optional[str] = None
    verb: Optional[str] = None

    def __init__(self, path: Optional[str] = None, verb: Optional[str] = None):
        super().__init__()
        if path is not None:
            self.path = path
        if verb is not None:
            self.verb = verb


class io__k8s__api__authorization__v1__NonResourceRule(K8STemplatable):
    """NonResourceRule holds information that describes a rule for the non-resource"""

    props: List[str] = ["nonResourceURLs", "verbs"]
    required_props: List[str] = ["verbs"]

    nonResourceURLs: Optional[List[str]] = None
    verbs: List[str]

    def __init__(self, verbs: List[str], nonResourceURLs: Optional[List[str]] = None):
        super().__init__()
        if verbs is not None:
            self.verbs = verbs
        if nonResourceURLs is not None:
            self.nonResourceURLs = nonResourceURLs


class io__k8s__api__authorization__v1__ResourceAttributes(K8STemplatable):
    """ResourceAttributes includes the authorization attributes available for resource requests to the Authorizer interface"""

    props: List[str] = [
        "group",
        "name",
        "namespace",
        "resource",
        "subresource",
        "verb",
        "version",
    ]
    required_props: List[str] = []

    group: Optional[str] = None
    name: Optional[str] = None
    namespace: Optional[str] = None
    resource: Optional[str] = None
    subresource: Optional[str] = None
    verb: Optional[str] = None
    version: Optional[str] = None

    def __init__(
        self,
        group: Optional[str] = None,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        resource: Optional[str] = None,
        subresource: Optional[str] = None,
        verb: Optional[str] = None,
        version: Optional[str] = None,
    ):
        super().__init__()
        if group is not None:
            self.group = group
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if resource is not None:
            self.resource = resource
        if subresource is not None:
            self.subresource = subresource
        if verb is not None:
            self.verb = verb
        if version is not None:
            self.version = version


class io__k8s__api__authorization__v1__ResourceRule(K8STemplatable):
    """ResourceRule is the list of actions the subject is allowed to perform on resources. The list ordering isn't significant, may contain duplicates, and possibly be incomplete."""

    props: List[str] = ["apiGroups", "resourceNames", "resources", "verbs"]
    required_props: List[str] = ["verbs"]

    apiGroups: Optional[List[str]] = None
    resourceNames: Optional[List[str]] = None
    resources: Optional[List[str]] = None
    verbs: List[str]

    def __init__(
        self,
        verbs: List[str],
        apiGroups: Optional[List[str]] = None,
        resourceNames: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
    ):
        super().__init__()
        if verbs is not None:
            self.verbs = verbs
        if apiGroups is not None:
            self.apiGroups = apiGroups
        if resourceNames is not None:
            self.resourceNames = resourceNames
        if resources is not None:
            self.resources = resources


class io__k8s__api__authorization__v1__SelfSubjectAccessReviewSpec(K8STemplatable):
    """SelfSubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes and NonResourceAuthorizationAttributes must be set"""

    props: List[str] = ["nonResourceAttributes", "resourceAttributes"]
    required_props: List[str] = []

    nonResourceAttributes: Optional[
        io__k8s__api__authorization__v1__NonResourceAttributes
    ] = None
    resourceAttributes: Optional[
        io__k8s__api__authorization__v1__ResourceAttributes
    ] = None

    def __init__(
        self,
        nonResourceAttributes: Optional[
            io__k8s__api__authorization__v1__NonResourceAttributes
        ] = None,
        resourceAttributes: Optional[
            io__k8s__api__authorization__v1__ResourceAttributes
        ] = None,
    ):
        super().__init__()
        if nonResourceAttributes is not None:
            self.nonResourceAttributes = nonResourceAttributes
        if resourceAttributes is not None:
            self.resourceAttributes = resourceAttributes


class io__k8s__api__authorization__v1__SelfSubjectRulesReviewSpec(K8STemplatable):
    """SelfSubjectRulesReviewSpec defines the specification for SelfSubjectRulesReview."""

    props: List[str] = ["namespace"]
    required_props: List[str] = []

    namespace: Optional[str] = None

    def __init__(self, namespace: Optional[str] = None):
        super().__init__()
        if namespace is not None:
            self.namespace = namespace


class io__k8s__api__authorization__v1__SubjectAccessReviewSpec(K8STemplatable):
    """SubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes and NonResourceAuthorizationAttributes must be set"""

    props: List[str] = [
        "extra",
        "groups",
        "nonResourceAttributes",
        "resourceAttributes",
        "uid",
        "user",
    ]
    required_props: List[str] = []

    extra: Any
    groups: Optional[List[str]] = None
    nonResourceAttributes: Optional[
        io__k8s__api__authorization__v1__NonResourceAttributes
    ] = None
    resourceAttributes: Optional[
        io__k8s__api__authorization__v1__ResourceAttributes
    ] = None
    uid: Optional[str] = None
    user: Optional[str] = None

    def __init__(
        self,
        extra: Any = None,
        groups: Optional[List[str]] = None,
        nonResourceAttributes: Optional[
            io__k8s__api__authorization__v1__NonResourceAttributes
        ] = None,
        resourceAttributes: Optional[
            io__k8s__api__authorization__v1__ResourceAttributes
        ] = None,
        uid: Optional[str] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if extra is not None:
            self.extra = extra
        if groups is not None:
            self.groups = groups
        if nonResourceAttributes is not None:
            self.nonResourceAttributes = nonResourceAttributes
        if resourceAttributes is not None:
            self.resourceAttributes = resourceAttributes
        if uid is not None:
            self.uid = uid
        if user is not None:
            self.user = user


class io__k8s__api__authorization__v1__SubjectAccessReviewStatus(K8STemplatable):
    """SubjectAccessReviewStatus"""

    props: List[str] = ["allowed", "denied", "evaluationError", "reason"]
    required_props: List[str] = ["allowed"]

    allowed: bool
    denied: Optional[bool] = None
    evaluationError: Optional[str] = None
    reason: Optional[str] = None

    def __init__(
        self,
        allowed: bool,
        denied: Optional[bool] = None,
        evaluationError: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if allowed is not None:
            self.allowed = allowed
        if denied is not None:
            self.denied = denied
        if evaluationError is not None:
            self.evaluationError = evaluationError
        if reason is not None:
            self.reason = reason


class io__k8s__api__authorization__v1__SubjectRulesReviewStatus(K8STemplatable):
    """SubjectRulesReviewStatus contains the result of a rules check. This check can be incomplete depending on the set of authorizers the server is configured with and any errors experienced during evaluation. Because authorization rules are additive, if a rule appears in a list it's safe to assume the subject has that permission, even if that list is incomplete."""

    props: List[str] = [
        "evaluationError",
        "incomplete",
        "nonResourceRules",
        "resourceRules",
    ]
    required_props: List[str] = ["resourceRules", "nonResourceRules", "incomplete"]

    evaluationError: Optional[str] = None
    incomplete: bool
    nonResourceRules: List[io__k8s__api__authorization__v1__NonResourceRule]
    resourceRules: List[io__k8s__api__authorization__v1__ResourceRule]

    def __init__(
        self,
        incomplete: bool,
        nonResourceRules: List[io__k8s__api__authorization__v1__NonResourceRule],
        resourceRules: List[io__k8s__api__authorization__v1__ResourceRule],
        evaluationError: Optional[str] = None,
    ):
        super().__init__()
        if incomplete is not None:
            self.incomplete = incomplete
        if nonResourceRules is not None:
            self.nonResourceRules = nonResourceRules
        if resourceRules is not None:
            self.resourceRules = resourceRules
        if evaluationError is not None:
            self.evaluationError = evaluationError


class io__k8s__api__autoscaling__v1__CrossVersionObjectReference(K8STemplatable):
    """CrossVersionObjectReference contains enough information to let you identify the referred resource."""

    props: List[str] = ["apiVersion", "kind", "name"]
    required_props: List[str] = ["kind", "name"]

    apiVersion: Optional[str] = None
    kind: str
    name: str

    def __init__(self, kind: str, name: str, apiVersion: Optional[str] = None):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiVersion is not None:
            self.apiVersion = apiVersion


class io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerSpec(K8STemplatable):
    """specification of a horizontal pod autoscaler."""

    props: List[str] = [
        "maxReplicas",
        "minReplicas",
        "scaleTargetRef",
        "targetCPUUtilizationPercentage",
    ]
    required_props: List[str] = ["scaleTargetRef", "maxReplicas"]

    maxReplicas: int
    minReplicas: Optional[int] = None
    scaleTargetRef: io__k8s__api__autoscaling__v1__CrossVersionObjectReference
    targetCPUUtilizationPercentage: Optional[int] = None

    def __init__(
        self,
        maxReplicas: int,
        scaleTargetRef: io__k8s__api__autoscaling__v1__CrossVersionObjectReference,
        minReplicas: Optional[int] = None,
        targetCPUUtilizationPercentage: Optional[int] = None,
    ):
        super().__init__()
        if maxReplicas is not None:
            self.maxReplicas = maxReplicas
        if scaleTargetRef is not None:
            self.scaleTargetRef = scaleTargetRef
        if minReplicas is not None:
            self.minReplicas = minReplicas
        if targetCPUUtilizationPercentage is not None:
            self.targetCPUUtilizationPercentage = targetCPUUtilizationPercentage


class io__k8s__api__autoscaling__v1__ScaleSpec(K8STemplatable):
    """ScaleSpec describes the attributes of a scale subresource."""

    props: List[str] = ["replicas"]
    required_props: List[str] = []

    replicas: Optional[int] = None

    def __init__(self, replicas: Optional[int] = None):
        super().__init__()
        if replicas is not None:
            self.replicas = replicas


class io__k8s__api__autoscaling__v1__ScaleStatus(K8STemplatable):
    """ScaleStatus represents the current status of a scale subresource."""

    props: List[str] = ["replicas", "selector"]
    required_props: List[str] = ["replicas"]

    replicas: int
    selector: Optional[str] = None

    def __init__(self, replicas: int, selector: Optional[str] = None):
        super().__init__()
        if replicas is not None:
            self.replicas = replicas
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2__CrossVersionObjectReference(K8STemplatable):
    """CrossVersionObjectReference contains enough information to let you identify the referred resource."""

    props: List[str] = ["apiVersion", "kind", "name"]
    required_props: List[str] = ["kind", "name"]

    apiVersion: Optional[str] = None
    kind: str
    name: str

    def __init__(self, kind: str, name: str, apiVersion: Optional[str] = None):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiVersion is not None:
            self.apiVersion = apiVersion


class io__k8s__api__autoscaling__v2__HPAScalingPolicy(K8STemplatable):
    """HPAScalingPolicy is a single policy which must hold true for a specified past interval."""

    props: List[str] = ["periodSeconds", "type", "value"]
    required_props: List[str] = ["type", "value", "periodSeconds"]

    periodSeconds: int
    type: str
    value: int

    def __init__(self, periodSeconds: int, type: str, value: int):
        super().__init__()
        if periodSeconds is not None:
            self.periodSeconds = periodSeconds
        if type is not None:
            self.type = type
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2__HPAScalingRules(K8STemplatable):
    """HPAScalingRules configures the scaling behavior for one direction. These Rules are applied after calculating DesiredReplicas from metrics for the HPA. They can limit the scaling velocity by specifying scaling policies. They can prevent flapping by specifying the stabilization window, so that the number of replicas is not set instantly, instead, the safest value from the stabilization window is chosen."""

    props: List[str] = ["policies", "selectPolicy", "stabilizationWindowSeconds"]
    required_props: List[str] = []

    policies: Optional[List[io__k8s__api__autoscaling__v2__HPAScalingPolicy]] = None
    selectPolicy: Optional[str] = None
    stabilizationWindowSeconds: Optional[int] = None

    def __init__(
        self,
        policies: Optional[
            List[io__k8s__api__autoscaling__v2__HPAScalingPolicy]
        ] = None,
        selectPolicy: Optional[str] = None,
        stabilizationWindowSeconds: Optional[int] = None,
    ):
        super().__init__()
        if policies is not None:
            self.policies = policies
        if selectPolicy is not None:
            self.selectPolicy = selectPolicy
        if stabilizationWindowSeconds is not None:
            self.stabilizationWindowSeconds = stabilizationWindowSeconds


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerBehavior(K8STemplatable):
    """HorizontalPodAutoscalerBehavior configures the scaling behavior of the target in both Up and Down directions (scaleUp and scaleDown fields respectively)."""

    props: List[str] = ["scaleDown", "scaleUp"]
    required_props: List[str] = []

    scaleDown: Optional[io__k8s__api__autoscaling__v2__HPAScalingRules] = None
    scaleUp: Optional[io__k8s__api__autoscaling__v2__HPAScalingRules] = None

    def __init__(
        self,
        scaleDown: Optional[io__k8s__api__autoscaling__v2__HPAScalingRules] = None,
        scaleUp: Optional[io__k8s__api__autoscaling__v2__HPAScalingRules] = None,
    ):
        super().__init__()
        if scaleDown is not None:
            self.scaleDown = scaleDown
        if scaleUp is not None:
            self.scaleUp = scaleUp


class io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference(K8STemplatable):
    """CrossVersionObjectReference contains enough information to let you identify the referred resource."""

    props: List[str] = ["apiVersion", "kind", "name"]
    required_props: List[str] = ["kind", "name"]

    apiVersion: Optional[str] = None
    kind: str
    name: str

    def __init__(self, kind: str, name: str, apiVersion: Optional[str] = None):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiVersion is not None:
            self.apiVersion = apiVersion


class io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference(K8STemplatable):
    """CrossVersionObjectReference contains enough information to let you identify the referred resource."""

    props: List[str] = ["apiVersion", "kind", "name"]
    required_props: List[str] = ["kind", "name"]

    apiVersion: Optional[str] = None
    kind: str
    name: str

    def __init__(self, kind: str, name: str, apiVersion: Optional[str] = None):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiVersion is not None:
            self.apiVersion = apiVersion


class io__k8s__api__autoscaling__v2beta2__HPAScalingPolicy(K8STemplatable):
    """HPAScalingPolicy is a single policy which must hold true for a specified past interval."""

    props: List[str] = ["periodSeconds", "type", "value"]
    required_props: List[str] = ["type", "value", "periodSeconds"]

    periodSeconds: int
    type: str
    value: int

    def __init__(self, periodSeconds: int, type: str, value: int):
        super().__init__()
        if periodSeconds is not None:
            self.periodSeconds = periodSeconds
        if type is not None:
            self.type = type
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2beta2__HPAScalingRules(K8STemplatable):
    """HPAScalingRules configures the scaling behavior for one direction. These Rules are applied after calculating DesiredReplicas from metrics for the HPA. They can limit the scaling velocity by specifying scaling policies. They can prevent flapping by specifying the stabilization window, so that the number of replicas is not set instantly, instead, the safest value from the stabilization window is chosen."""

    props: List[str] = ["policies", "selectPolicy", "stabilizationWindowSeconds"]
    required_props: List[str] = []

    policies: Optional[
        List[io__k8s__api__autoscaling__v2beta2__HPAScalingPolicy]
    ] = None
    selectPolicy: Optional[str] = None
    stabilizationWindowSeconds: Optional[int] = None

    def __init__(
        self,
        policies: Optional[
            List[io__k8s__api__autoscaling__v2beta2__HPAScalingPolicy]
        ] = None,
        selectPolicy: Optional[str] = None,
        stabilizationWindowSeconds: Optional[int] = None,
    ):
        super().__init__()
        if policies is not None:
            self.policies = policies
        if selectPolicy is not None:
            self.selectPolicy = selectPolicy
        if stabilizationWindowSeconds is not None:
            self.stabilizationWindowSeconds = stabilizationWindowSeconds


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerBehavior(
    K8STemplatable
):
    """HorizontalPodAutoscalerBehavior configures the scaling behavior of the target in both Up and Down directions (scaleUp and scaleDown fields respectively)."""

    props: List[str] = ["scaleDown", "scaleUp"]
    required_props: List[str] = []

    scaleDown: Optional[io__k8s__api__autoscaling__v2beta2__HPAScalingRules] = None
    scaleUp: Optional[io__k8s__api__autoscaling__v2beta2__HPAScalingRules] = None

    def __init__(
        self,
        scaleDown: Optional[io__k8s__api__autoscaling__v2beta2__HPAScalingRules] = None,
        scaleUp: Optional[io__k8s__api__autoscaling__v2beta2__HPAScalingRules] = None,
    ):
        super().__init__()
        if scaleDown is not None:
            self.scaleDown = scaleDown
        if scaleUp is not None:
            self.scaleUp = scaleUp


class io__k8s__api__batch__v1__UncountedTerminatedPods(K8STemplatable):
    """UncountedTerminatedPods holds UIDs of Pods that have terminated but haven't been accounted in Job status counters."""

    props: List[str] = ["failed", "succeeded"]
    required_props: List[str] = []

    failed: Optional[List[str]] = None
    succeeded: Optional[List[str]] = None

    def __init__(
        self, failed: Optional[List[str]] = None, succeeded: Optional[List[str]] = None
    ):
        super().__init__()
        if failed is not None:
            self.failed = failed
        if succeeded is not None:
            self.succeeded = succeeded


class io__k8s__api__certificates__v1__CertificateSigningRequestSpec(K8STemplatable):
    """CertificateSigningRequestSpec contains the certificate request."""

    props: List[str] = [
        "expirationSeconds",
        "extra",
        "groups",
        "request",
        "signerName",
        "uid",
        "usages",
        "username",
    ]
    required_props: List[str] = ["request", "signerName"]

    expirationSeconds: Optional[int] = None
    extra: Any
    groups: Optional[List[str]] = None
    request: str
    signerName: str
    uid: Optional[str] = None
    usages: Optional[List[str]] = None
    username: Optional[str] = None

    def __init__(
        self,
        request: str,
        signerName: str,
        expirationSeconds: Optional[int] = None,
        extra: Any = None,
        groups: Optional[List[str]] = None,
        uid: Optional[str] = None,
        usages: Optional[List[str]] = None,
        username: Optional[str] = None,
    ):
        super().__init__()
        if request is not None:
            self.request = request
        if signerName is not None:
            self.signerName = signerName
        if expirationSeconds is not None:
            self.expirationSeconds = expirationSeconds
        if extra is not None:
            self.extra = extra
        if groups is not None:
            self.groups = groups
        if uid is not None:
            self.uid = uid
        if usages is not None:
            self.usages = usages
        if username is not None:
            self.username = username


class io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource(K8STemplatable):
    """Represents a Persistent Disk resource in AWS.

    An AWS EBS disk must exist before mounting to a container. The disk must also be in the same AWS zone as the kubelet. An AWS EBS disk can only be mounted as read/write once. AWS EBS volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["fsType", "partition", "readOnly", "volumeID"]
    required_props: List[str] = ["volumeID"]

    fsType: Optional[str] = None
    partition: Optional[int] = None
    readOnly: Optional[bool] = None
    volumeID: str

    def __init__(
        self,
        volumeID: str,
        fsType: Optional[str] = None,
        partition: Optional[int] = None,
        readOnly: Optional[bool] = None,
    ):
        super().__init__()
        if volumeID is not None:
            self.volumeID = volumeID
        if fsType is not None:
            self.fsType = fsType
        if partition is not None:
            self.partition = partition
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__AttachedVolume(K8STemplatable):
    """AttachedVolume describes a volume attached to a node"""

    props: List[str] = ["devicePath", "name"]
    required_props: List[str] = ["name", "devicePath"]

    devicePath: str
    name: str

    def __init__(self, devicePath: str, name: str):
        super().__init__()
        if devicePath is not None:
            self.devicePath = devicePath
        if name is not None:
            self.name = name


class io__k8s__api__core__v1__AzureDiskVolumeSource(K8STemplatable):
    """AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod."""

    props: List[str] = [
        "cachingMode",
        "diskName",
        "diskURI",
        "fsType",
        "kind",
        "readOnly",
    ]
    required_props: List[str] = ["diskName", "diskURI"]

    cachingMode: Optional[str] = None
    diskName: str
    diskURI: str
    fsType: Optional[str] = None
    kind: Optional[str] = None
    readOnly: Optional[bool] = None

    def __init__(
        self,
        diskName: str,
        diskURI: str,
        cachingMode: Optional[str] = None,
        fsType: Optional[str] = None,
        kind: Optional[str] = None,
        readOnly: Optional[bool] = None,
    ):
        super().__init__()
        if diskName is not None:
            self.diskName = diskName
        if diskURI is not None:
            self.diskURI = diskURI
        if cachingMode is not None:
            self.cachingMode = cachingMode
        if fsType is not None:
            self.fsType = fsType
        if kind is not None:
            self.kind = kind
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__AzureFilePersistentVolumeSource(K8STemplatable):
    """AzureFile represents an Azure File Service mount on the host and bind mount to the pod."""

    props: List[str] = ["readOnly", "secretName", "secretNamespace", "shareName"]
    required_props: List[str] = ["secretName", "shareName"]

    readOnly: Optional[bool] = None
    secretName: str
    secretNamespace: Optional[str] = None
    shareName: str

    def __init__(
        self,
        secretName: str,
        shareName: str,
        readOnly: Optional[bool] = None,
        secretNamespace: Optional[str] = None,
    ):
        super().__init__()
        if secretName is not None:
            self.secretName = secretName
        if shareName is not None:
            self.shareName = shareName
        if readOnly is not None:
            self.readOnly = readOnly
        if secretNamespace is not None:
            self.secretNamespace = secretNamespace


class io__k8s__api__core__v1__AzureFileVolumeSource(K8STemplatable):
    """AzureFile represents an Azure File Service mount on the host and bind mount to the pod."""

    props: List[str] = ["readOnly", "secretName", "shareName"]
    required_props: List[str] = ["secretName", "shareName"]

    readOnly: Optional[bool] = None
    secretName: str
    shareName: str

    def __init__(
        self, secretName: str, shareName: str, readOnly: Optional[bool] = None
    ):
        super().__init__()
        if secretName is not None:
            self.secretName = secretName
        if shareName is not None:
            self.shareName = shareName
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__Capabilities(K8STemplatable):
    """Adds and removes POSIX capabilities from running containers."""

    props: List[str] = ["add", "drop"]
    required_props: List[str] = []

    add: Optional[List[str]] = None
    drop: Optional[List[str]] = None

    def __init__(
        self, add: Optional[List[str]] = None, drop: Optional[List[str]] = None
    ):
        super().__init__()
        if add is not None:
            self.add = add
        if drop is not None:
            self.drop = drop


class io__k8s__api__core__v1__ClientIPConfig(K8STemplatable):
    """ClientIPConfig represents the configurations of Client IP based session affinity."""

    props: List[str] = ["timeoutSeconds"]
    required_props: List[str] = []

    timeoutSeconds: Optional[int] = None

    def __init__(self, timeoutSeconds: Optional[int] = None):
        super().__init__()
        if timeoutSeconds is not None:
            self.timeoutSeconds = timeoutSeconds


class io__k8s__api__core__v1__ComponentCondition(K8STemplatable):
    """Information about the condition of a component."""

    props: List[str] = ["error", "message", "status", "type"]
    required_props: List[str] = ["type", "status"]

    error: Optional[str] = None
    message: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        error: Optional[str] = None,
        message: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if error is not None:
            self.error = error
        if message is not None:
            self.message = message


class io__k8s__api__core__v1__ConfigMapEnvSource(K8STemplatable):
    """ConfigMapEnvSource selects a ConfigMap to populate the environment variables with.

    The contents of the target ConfigMap's Data field will represent the key-value pairs as environment variables."""

    props: List[str] = ["name", "optional"]
    required_props: List[str] = []

    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(self, name: Optional[str] = None, optional: Optional[bool] = None):
        super().__init__()
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__ConfigMapKeySelector(K8STemplatable):
    """Selects a key from a ConfigMap."""

    props: List[str] = ["key", "name", "optional"]
    required_props: List[str] = ["key"]

    key: str
    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(
        self, key: str, name: Optional[str] = None, optional: Optional[bool] = None
    ):
        super().__init__()
        if key is not None:
            self.key = key
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__ConfigMapNodeConfigSource(K8STemplatable):
    """ConfigMapNodeConfigSource contains the information to reference a ConfigMap as a config source for the Node. This API is deprecated since 1.22: https://git.k8s.io/enhancements/keps/sig-node/281-dynamic-kubelet-configuration"""

    props: List[str] = [
        "kubeletConfigKey",
        "name",
        "namespace",
        "resourceVersion",
        "uid",
    ]
    required_props: List[str] = ["namespace", "name", "kubeletConfigKey"]

    kubeletConfigKey: str
    name: str
    namespace: str
    resourceVersion: Optional[str] = None
    uid: Optional[str] = None

    def __init__(
        self,
        kubeletConfigKey: str,
        name: str,
        namespace: str,
        resourceVersion: Optional[str] = None,
        uid: Optional[str] = None,
    ):
        super().__init__()
        if kubeletConfigKey is not None:
            self.kubeletConfigKey = kubeletConfigKey
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if resourceVersion is not None:
            self.resourceVersion = resourceVersion
        if uid is not None:
            self.uid = uid


class io__k8s__api__core__v1__ContainerImage(K8STemplatable):
    """Describe a container image"""

    props: List[str] = ["names", "sizeBytes"]
    required_props: List[str] = []

    names: Optional[List[str]] = None
    sizeBytes: Optional[int] = None

    def __init__(
        self, names: Optional[List[str]] = None, sizeBytes: Optional[int] = None
    ):
        super().__init__()
        if names is not None:
            self.names = names
        if sizeBytes is not None:
            self.sizeBytes = sizeBytes


class io__k8s__api__core__v1__ContainerPort(K8STemplatable):
    """ContainerPort represents a network port in a single container."""

    props: List[str] = ["containerPort", "hostIP", "hostPort", "name", "protocol"]
    required_props: List[str] = ["containerPort"]

    containerPort: int
    hostIP: Optional[str] = None
    hostPort: Optional[int] = None
    name: Optional[str] = None
    protocol: Optional[str] = None

    def __init__(
        self,
        containerPort: int,
        hostIP: Optional[str] = None,
        hostPort: Optional[int] = None,
        name: Optional[str] = None,
        protocol: Optional[str] = None,
    ):
        super().__init__()
        if containerPort is not None:
            self.containerPort = containerPort
        if hostIP is not None:
            self.hostIP = hostIP
        if hostPort is not None:
            self.hostPort = hostPort
        if name is not None:
            self.name = name
        if protocol is not None:
            self.protocol = protocol


class io__k8s__api__core__v1__ContainerStateWaiting(K8STemplatable):
    """ContainerStateWaiting is a waiting state of a container."""

    props: List[str] = ["message", "reason"]
    required_props: List[str] = []

    message: Optional[str] = None
    reason: Optional[str] = None

    def __init__(self, message: Optional[str] = None, reason: Optional[str] = None):
        super().__init__()
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__DaemonEndpoint(K8STemplatable):
    """DaemonEndpoint contains information about a single Daemon endpoint."""

    props: List[str] = ["Port"]
    required_props: List[str] = ["Port"]

    Port: int

    def __init__(self, Port: int):
        super().__init__()
        if Port is not None:
            self.Port = Port


class io__k8s__api__core__v1__EndpointPort(K8STemplatable):
    """EndpointPort is a tuple that describes a single port."""

    props: List[str] = ["appProtocol", "name", "port", "protocol"]
    required_props: List[str] = ["port"]

    appProtocol: Optional[str] = None
    name: Optional[str] = None
    port: int
    protocol: Optional[str] = None

    def __init__(
        self,
        port: int,
        appProtocol: Optional[str] = None,
        name: Optional[str] = None,
        protocol: Optional[str] = None,
    ):
        super().__init__()
        if port is not None:
            self.port = port
        if appProtocol is not None:
            self.appProtocol = appProtocol
        if name is not None:
            self.name = name
        if protocol is not None:
            self.protocol = protocol


class io__k8s__api__core__v1__EventSource(K8STemplatable):
    """EventSource contains information for an event."""

    props: List[str] = ["component", "host"]
    required_props: List[str] = []

    component: Optional[str] = None
    host: Optional[str] = None

    def __init__(self, component: Optional[str] = None, host: Optional[str] = None):
        super().__init__()
        if component is not None:
            self.component = component
        if host is not None:
            self.host = host


class io__k8s__api__core__v1__ExecAction(K8STemplatable):
    """ExecAction describes a "run in container" action."""

    props: List[str] = ["command"]
    required_props: List[str] = []

    command: Optional[List[str]] = None

    def __init__(self, command: Optional[List[str]] = None):
        super().__init__()
        if command is not None:
            self.command = command


class io__k8s__api__core__v1__FCVolumeSource(K8STemplatable):
    """Represents a Fibre Channel volume. Fibre Channel volumes can only be mounted as read/write once. Fibre Channel volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["fsType", "lun", "readOnly", "targetWWNs", "wwids"]
    required_props: List[str] = []

    fsType: Optional[str] = None
    lun: Optional[int] = None
    readOnly: Optional[bool] = None
    targetWWNs: Optional[List[str]] = None
    wwids: Optional[List[str]] = None

    def __init__(
        self,
        fsType: Optional[str] = None,
        lun: Optional[int] = None,
        readOnly: Optional[bool] = None,
        targetWWNs: Optional[List[str]] = None,
        wwids: Optional[List[str]] = None,
    ):
        super().__init__()
        if fsType is not None:
            self.fsType = fsType
        if lun is not None:
            self.lun = lun
        if readOnly is not None:
            self.readOnly = readOnly
        if targetWWNs is not None:
            self.targetWWNs = targetWWNs
        if wwids is not None:
            self.wwids = wwids


class io__k8s__api__core__v1__FlockerVolumeSource(K8STemplatable):
    """Represents a Flocker volume mounted by the Flocker agent. One and only one of datasetName and datasetUUID should be set. Flocker volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["datasetName", "datasetUUID"]
    required_props: List[str] = []

    datasetName: Optional[str] = None
    datasetUUID: Optional[str] = None

    def __init__(
        self, datasetName: Optional[str] = None, datasetUUID: Optional[str] = None
    ):
        super().__init__()
        if datasetName is not None:
            self.datasetName = datasetName
        if datasetUUID is not None:
            self.datasetUUID = datasetUUID


class io__k8s__api__core__v1__GCEPersistentDiskVolumeSource(K8STemplatable):
    """Represents a Persistent Disk resource in Google Compute Engine.

    A GCE PD must exist before mounting to a container. The disk must also be in the same GCE project and zone as the kubelet. A GCE PD can only be mounted as read/write once or read-only many times. GCE PDs support ownership management and SELinux relabeling."""

    props: List[str] = ["fsType", "partition", "pdName", "readOnly"]
    required_props: List[str] = ["pdName"]

    fsType: Optional[str] = None
    partition: Optional[int] = None
    pdName: str
    readOnly: Optional[bool] = None

    def __init__(
        self,
        pdName: str,
        fsType: Optional[str] = None,
        partition: Optional[int] = None,
        readOnly: Optional[bool] = None,
    ):
        super().__init__()
        if pdName is not None:
            self.pdName = pdName
        if fsType is not None:
            self.fsType = fsType
        if partition is not None:
            self.partition = partition
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__GRPCAction(K8STemplatable):
    """None"""

    props: List[str] = ["port", "service"]
    required_props: List[str] = ["port"]

    port: int
    service: Optional[str] = None

    def __init__(self, port: int, service: Optional[str] = None):
        super().__init__()
        if port is not None:
            self.port = port
        if service is not None:
            self.service = service


class io__k8s__api__core__v1__GitRepoVolumeSource(K8STemplatable):
    """Represents a volume that is populated with the contents of a git repository. Git repo volumes do not support ownership management. Git repo volumes support SELinux relabeling.

    DEPRECATED: GitRepo is deprecated. To provision a container with a git repo, mount an EmptyDir into an InitContainer that clones the repo using git, then mount the EmptyDir into the Pod's container."""

    props: List[str] = ["directory", "repository", "revision"]
    required_props: List[str] = ["repository"]

    directory: Optional[str] = None
    repository: str
    revision: Optional[str] = None

    def __init__(
        self,
        repository: str,
        directory: Optional[str] = None,
        revision: Optional[str] = None,
    ):
        super().__init__()
        if repository is not None:
            self.repository = repository
        if directory is not None:
            self.directory = directory
        if revision is not None:
            self.revision = revision


class io__k8s__api__core__v1__GlusterfsPersistentVolumeSource(K8STemplatable):
    """Represents a Glusterfs mount that lasts the lifetime of a pod. Glusterfs volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["endpoints", "endpointsNamespace", "path", "readOnly"]
    required_props: List[str] = ["endpoints", "path"]

    endpoints: str
    endpointsNamespace: Optional[str] = None
    path: str
    readOnly: Optional[bool] = None

    def __init__(
        self,
        endpoints: str,
        path: str,
        endpointsNamespace: Optional[str] = None,
        readOnly: Optional[bool] = None,
    ):
        super().__init__()
        if endpoints is not None:
            self.endpoints = endpoints
        if path is not None:
            self.path = path
        if endpointsNamespace is not None:
            self.endpointsNamespace = endpointsNamespace
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__GlusterfsVolumeSource(K8STemplatable):
    """Represents a Glusterfs mount that lasts the lifetime of a pod. Glusterfs volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["endpoints", "path", "readOnly"]
    required_props: List[str] = ["endpoints", "path"]

    endpoints: str
    path: str
    readOnly: Optional[bool] = None

    def __init__(self, endpoints: str, path: str, readOnly: Optional[bool] = None):
        super().__init__()
        if endpoints is not None:
            self.endpoints = endpoints
        if path is not None:
            self.path = path
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__HTTPHeader(K8STemplatable):
    """HTTPHeader describes a custom header to be used in HTTP probes"""

    props: List[str] = ["name", "value"]
    required_props: List[str] = ["name", "value"]

    name: str
    value: str

    def __init__(self, name: str, value: str):
        super().__init__()
        if name is not None:
            self.name = name
        if value is not None:
            self.value = value


class io__k8s__api__core__v1__HostAlias(K8STemplatable):
    """HostAlias holds the mapping between IP and hostnames that will be injected as an entry in the pod's hosts file."""

    props: List[str] = ["hostnames", "ip"]
    required_props: List[str] = []

    hostnames: Optional[List[str]] = None
    ip: Optional[str] = None

    def __init__(self, hostnames: Optional[List[str]] = None, ip: Optional[str] = None):
        super().__init__()
        if hostnames is not None:
            self.hostnames = hostnames
        if ip is not None:
            self.ip = ip


class io__k8s__api__core__v1__HostPathVolumeSource(K8STemplatable):
    """Represents a host path mapped into a pod. Host path volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["path", "type"]
    required_props: List[str] = ["path"]

    path: str
    type: Optional[str] = None

    def __init__(self, path: str, type: Optional[str] = None):
        super().__init__()
        if path is not None:
            self.path = path
        if type is not None:
            self.type = type


class io__k8s__api__core__v1__KeyToPath(K8STemplatable):
    """Maps a string key to a path within a volume."""

    props: List[str] = ["key", "mode", "path"]
    required_props: List[str] = ["key", "path"]

    key: str
    mode: Optional[int] = None
    path: str

    def __init__(self, key: str, path: str, mode: Optional[int] = None):
        super().__init__()
        if key is not None:
            self.key = key
        if path is not None:
            self.path = path
        if mode is not None:
            self.mode = mode


class io__k8s__api__core__v1__LimitRangeItem(K8STemplatable):
    """LimitRangeItem defines a min/max usage limit for any resource that matches on kind."""

    props: List[str] = ["defaultRequest", "max", "maxLimitRequestRatio", "min", "type"]
    required_props: List[str] = ["type"]

    defaultRequest: Any
    max: Any
    maxLimitRequestRatio: Any
    min: Any
    type: str

    def __init__(
        self,
        type: str,
        defaultRequest: Any = None,
        max: Any = None,
        maxLimitRequestRatio: Any = None,
        min: Any = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if defaultRequest is not None:
            self.defaultRequest = defaultRequest
        if max is not None:
            self.max = max
        if maxLimitRequestRatio is not None:
            self.maxLimitRequestRatio = maxLimitRequestRatio
        if min is not None:
            self.min = min


class io__k8s__api__core__v1__LimitRangeSpec(K8STemplatable):
    """LimitRangeSpec defines a min/max usage limit for resources that match on kind."""

    props: List[str] = ["limits"]
    required_props: List[str] = ["limits"]

    limits: List[io__k8s__api__core__v1__LimitRangeItem]

    def __init__(self, limits: List[io__k8s__api__core__v1__LimitRangeItem]):
        super().__init__()
        if limits is not None:
            self.limits = limits


class io__k8s__api__core__v1__LocalObjectReference(K8STemplatable):
    """LocalObjectReference contains enough information to let you locate the referenced object inside the same namespace."""

    props: List[str] = ["name"]
    required_props: List[str] = []

    name: Optional[str] = None

    def __init__(self, name: Optional[str] = None):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__core__v1__LocalVolumeSource(K8STemplatable):
    """Local represents directly-attached storage with node affinity (Beta feature)"""

    props: List[str] = ["fsType", "path"]
    required_props: List[str] = ["path"]

    fsType: Optional[str] = None
    path: str

    def __init__(self, path: str, fsType: Optional[str] = None):
        super().__init__()
        if path is not None:
            self.path = path
        if fsType is not None:
            self.fsType = fsType


class io__k8s__api__core__v1__NFSVolumeSource(K8STemplatable):
    """Represents an NFS mount that lasts the lifetime of a pod. NFS volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["path", "readOnly", "server"]
    required_props: List[str] = ["server", "path"]

    path: str
    readOnly: Optional[bool] = None
    server: str

    def __init__(self, path: str, server: str, readOnly: Optional[bool] = None):
        super().__init__()
        if path is not None:
            self.path = path
        if server is not None:
            self.server = server
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__NamespaceSpec(K8STemplatable):
    """NamespaceSpec describes the attributes on a Namespace."""

    props: List[str] = ["finalizers"]
    required_props: List[str] = []

    finalizers: Optional[List[str]] = None

    def __init__(self, finalizers: Optional[List[str]] = None):
        super().__init__()
        if finalizers is not None:
            self.finalizers = finalizers


class io__k8s__api__core__v1__NodeAddress(K8STemplatable):
    """NodeAddress contains information for the node's address."""

    props: List[str] = ["address", "type"]
    required_props: List[str] = ["type", "address"]

    address: str
    type: str

    def __init__(self, address: str, type: str):
        super().__init__()
        if address is not None:
            self.address = address
        if type is not None:
            self.type = type


class io__k8s__api__core__v1__NodeConfigSource(K8STemplatable):
    """NodeConfigSource specifies a source of node configuration. Exactly one subfield (excluding metadata) must be non-nil. This API is deprecated since 1.22"""

    props: List[str] = ["configMap"]
    required_props: List[str] = []

    configMap: Optional[io__k8s__api__core__v1__ConfigMapNodeConfigSource] = None

    def __init__(
        self,
        configMap: Optional[io__k8s__api__core__v1__ConfigMapNodeConfigSource] = None,
    ):
        super().__init__()
        if configMap is not None:
            self.configMap = configMap


class io__k8s__api__core__v1__NodeConfigStatus(K8STemplatable):
    """NodeConfigStatus describes the status of the config assigned by Node.Spec.ConfigSource."""

    props: List[str] = ["active", "assigned", "error", "lastKnownGood"]
    required_props: List[str] = []

    active: Optional[io__k8s__api__core__v1__NodeConfigSource] = None
    assigned: Optional[io__k8s__api__core__v1__NodeConfigSource] = None
    error: Optional[str] = None
    lastKnownGood: Optional[io__k8s__api__core__v1__NodeConfigSource] = None

    def __init__(
        self,
        active: Optional[io__k8s__api__core__v1__NodeConfigSource] = None,
        assigned: Optional[io__k8s__api__core__v1__NodeConfigSource] = None,
        error: Optional[str] = None,
        lastKnownGood: Optional[io__k8s__api__core__v1__NodeConfigSource] = None,
    ):
        super().__init__()
        if active is not None:
            self.active = active
        if assigned is not None:
            self.assigned = assigned
        if error is not None:
            self.error = error
        if lastKnownGood is not None:
            self.lastKnownGood = lastKnownGood


class io__k8s__api__core__v1__NodeDaemonEndpoints(K8STemplatable):
    """NodeDaemonEndpoints lists ports opened by daemons running on the Node."""

    props: List[str] = ["kubeletEndpoint"]
    required_props: List[str] = []

    kubeletEndpoint: Optional[io__k8s__api__core__v1__DaemonEndpoint] = None

    def __init__(
        self, kubeletEndpoint: Optional[io__k8s__api__core__v1__DaemonEndpoint] = None
    ):
        super().__init__()
        if kubeletEndpoint is not None:
            self.kubeletEndpoint = kubeletEndpoint


class io__k8s__api__core__v1__NodeSelectorRequirement(K8STemplatable):
    """A node selector requirement is a selector that contains values, a key, and an operator that relates the key and values."""

    props: List[str] = ["key", "operator", "values"]
    required_props: List[str] = ["key", "operator"]

    key: str
    operator: str
    values: Optional[List[str]] = None

    def __init__(self, key: str, operator: str, values: Optional[List[str]] = None):
        super().__init__()
        if key is not None:
            self.key = key
        if operator is not None:
            self.operator = operator
        if values is not None:
            self.values = values


class io__k8s__api__core__v1__NodeSelectorTerm(K8STemplatable):
    """A null or empty node selector term matches no objects. The requirements of them are ANDed. The TopologySelectorTerm type implements a subset of the NodeSelectorTerm."""

    props: List[str] = ["matchExpressions", "matchFields"]
    required_props: List[str] = []

    matchExpressions: Optional[
        List[io__k8s__api__core__v1__NodeSelectorRequirement]
    ] = None
    matchFields: Optional[List[io__k8s__api__core__v1__NodeSelectorRequirement]] = None

    def __init__(
        self,
        matchExpressions: Optional[
            List[io__k8s__api__core__v1__NodeSelectorRequirement]
        ] = None,
        matchFields: Optional[
            List[io__k8s__api__core__v1__NodeSelectorRequirement]
        ] = None,
    ):
        super().__init__()
        if matchExpressions is not None:
            self.matchExpressions = matchExpressions
        if matchFields is not None:
            self.matchFields = matchFields


class io__k8s__api__core__v1__NodeSystemInfo(K8STemplatable):
    """NodeSystemInfo is a set of ids/uuids to uniquely identify the node."""

    props: List[str] = [
        "architecture",
        "bootID",
        "containerRuntimeVersion",
        "kernelVersion",
        "kubeProxyVersion",
        "kubeletVersion",
        "machineID",
        "operatingSystem",
        "osImage",
        "systemUUID",
    ]
    required_props: List[str] = [
        "machineID",
        "systemUUID",
        "bootID",
        "kernelVersion",
        "osImage",
        "containerRuntimeVersion",
        "kubeletVersion",
        "kubeProxyVersion",
        "operatingSystem",
        "architecture",
    ]

    architecture: str
    bootID: str
    containerRuntimeVersion: str
    kernelVersion: str
    kubeProxyVersion: str
    kubeletVersion: str
    machineID: str
    operatingSystem: str
    osImage: str
    systemUUID: str

    def __init__(
        self,
        architecture: str,
        bootID: str,
        containerRuntimeVersion: str,
        kernelVersion: str,
        kubeProxyVersion: str,
        kubeletVersion: str,
        machineID: str,
        operatingSystem: str,
        osImage: str,
        systemUUID: str,
    ):
        super().__init__()
        if architecture is not None:
            self.architecture = architecture
        if bootID is not None:
            self.bootID = bootID
        if containerRuntimeVersion is not None:
            self.containerRuntimeVersion = containerRuntimeVersion
        if kernelVersion is not None:
            self.kernelVersion = kernelVersion
        if kubeProxyVersion is not None:
            self.kubeProxyVersion = kubeProxyVersion
        if kubeletVersion is not None:
            self.kubeletVersion = kubeletVersion
        if machineID is not None:
            self.machineID = machineID
        if operatingSystem is not None:
            self.operatingSystem = operatingSystem
        if osImage is not None:
            self.osImage = osImage
        if systemUUID is not None:
            self.systemUUID = systemUUID


class io__k8s__api__core__v1__ObjectFieldSelector(K8STemplatable):
    """ObjectFieldSelector selects an APIVersioned field of an object."""

    props: List[str] = ["apiVersion", "fieldPath"]
    required_props: List[str] = ["fieldPath"]

    apiVersion: Optional[str] = None
    fieldPath: str

    def __init__(self, fieldPath: str, apiVersion: Optional[str] = None):
        super().__init__()
        if fieldPath is not None:
            self.fieldPath = fieldPath
        if apiVersion is not None:
            self.apiVersion = apiVersion


class io__k8s__api__core__v1__ObjectReference(K8STemplatable):
    """ObjectReference contains enough information to let you inspect or modify the referred object."""

    props: List[str] = [
        "apiVersion",
        "fieldPath",
        "kind",
        "name",
        "namespace",
        "resourceVersion",
        "uid",
    ]
    required_props: List[str] = []

    apiVersion: Optional[str] = None
    fieldPath: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    namespace: Optional[str] = None
    resourceVersion: Optional[str] = None
    uid: Optional[str] = None

    def __init__(
        self,
        apiVersion: Optional[str] = None,
        fieldPath: Optional[str] = None,
        kind: Optional[str] = None,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        resourceVersion: Optional[str] = None,
        uid: Optional[str] = None,
    ):
        super().__init__()
        if apiVersion is not None:
            self.apiVersion = apiVersion
        if fieldPath is not None:
            self.fieldPath = fieldPath
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if resourceVersion is not None:
            self.resourceVersion = resourceVersion
        if uid is not None:
            self.uid = uid


class io__k8s__api__core__v1__PersistentVolumeClaimVolumeSource(K8STemplatable):
    """PersistentVolumeClaimVolumeSource references the user's PVC in the same namespace. This volume finds the bound PV and mounts that volume for the pod. A PersistentVolumeClaimVolumeSource is, essentially, a wrapper around another type of volume that is owned by someone else (the system)."""

    props: List[str] = ["claimName", "readOnly"]
    required_props: List[str] = ["claimName"]

    claimName: str
    readOnly: Optional[bool] = None

    def __init__(self, claimName: str, readOnly: Optional[bool] = None):
        super().__init__()
        if claimName is not None:
            self.claimName = claimName
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__PersistentVolumeStatus(K8STemplatable):
    """PersistentVolumeStatus is the current status of a persistent volume."""

    props: List[str] = ["message", "phase", "reason"]
    required_props: List[str] = []

    message: Optional[str] = None
    phase: Optional[str] = None
    reason: Optional[str] = None

    def __init__(
        self,
        message: Optional[str] = None,
        phase: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if message is not None:
            self.message = message
        if phase is not None:
            self.phase = phase
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource(K8STemplatable):
    """Represents a Photon Controller persistent disk resource."""

    props: List[str] = ["fsType", "pdID"]
    required_props: List[str] = ["pdID"]

    fsType: Optional[str] = None
    pdID: str

    def __init__(self, pdID: str, fsType: Optional[str] = None):
        super().__init__()
        if pdID is not None:
            self.pdID = pdID
        if fsType is not None:
            self.fsType = fsType


class io__k8s__api__core__v1__PodDNSConfigOption(K8STemplatable):
    """PodDNSConfigOption defines DNS resolver options of a pod."""

    props: List[str] = ["name", "value"]
    required_props: List[str] = []

    name: Optional[str] = None
    value: Optional[str] = None

    def __init__(self, name: Optional[str] = None, value: Optional[str] = None):
        super().__init__()
        if name is not None:
            self.name = name
        if value is not None:
            self.value = value


class io__k8s__api__core__v1__PodIP(K8STemplatable):
    """IP address information for entries in the (plural) PodIPs field. Each entry includes:
    IP: An IP address allocated to the pod. Routable at least within the cluster."""

    props: List[str] = ["ip"]
    required_props: List[str] = []

    ip: Optional[str] = None

    def __init__(self, ip: Optional[str] = None):
        super().__init__()
        if ip is not None:
            self.ip = ip


class io__k8s__api__core__v1__PodOS(K8STemplatable):
    """PodOS defines the OS parameters of a pod."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__core__v1__PodReadinessGate(K8STemplatable):
    """PodReadinessGate contains the reference to a pod condition"""

    props: List[str] = ["conditionType"]
    required_props: List[str] = ["conditionType"]

    conditionType: str

    def __init__(self, conditionType: str):
        super().__init__()
        if conditionType is not None:
            self.conditionType = conditionType


class io__k8s__api__core__v1__PortStatus(K8STemplatable):
    """None"""

    props: List[str] = ["error", "port", "protocol"]
    required_props: List[str] = ["port", "protocol"]

    error: Optional[str] = None
    port: int
    protocol: str

    def __init__(self, port: int, protocol: str, error: Optional[str] = None):
        super().__init__()
        if port is not None:
            self.port = port
        if protocol is not None:
            self.protocol = protocol
        if error is not None:
            self.error = error


class io__k8s__api__core__v1__PortworxVolumeSource(K8STemplatable):
    """PortworxVolumeSource represents a Portworx volume resource."""

    props: List[str] = ["fsType", "readOnly", "volumeID"]
    required_props: List[str] = ["volumeID"]

    fsType: Optional[str] = None
    readOnly: Optional[bool] = None
    volumeID: str

    def __init__(
        self,
        volumeID: str,
        fsType: Optional[str] = None,
        readOnly: Optional[bool] = None,
    ):
        super().__init__()
        if volumeID is not None:
            self.volumeID = volumeID
        if fsType is not None:
            self.fsType = fsType
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__core__v1__PreferredSchedulingTerm(K8STemplatable):
    """An empty preferred scheduling term matches all objects with implicit weight 0 (i.e. it's a no-op). A null preferred scheduling term matches no objects (i.e. is also a no-op)."""

    props: List[str] = ["preference", "weight"]
    required_props: List[str] = ["weight", "preference"]

    preference: io__k8s__api__core__v1__NodeSelectorTerm
    weight: int

    def __init__(
        self, preference: io__k8s__api__core__v1__NodeSelectorTerm, weight: int
    ):
        super().__init__()
        if preference is not None:
            self.preference = preference
        if weight is not None:
            self.weight = weight


class io__k8s__api__core__v1__QuobyteVolumeSource(K8STemplatable):
    """Represents a Quobyte mount that lasts the lifetime of a pod. Quobyte volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = ["group", "readOnly", "registry", "tenant", "user", "volume"]
    required_props: List[str] = ["registry", "volume"]

    group: Optional[str] = None
    readOnly: Optional[bool] = None
    registry: str
    tenant: Optional[str] = None
    user: Optional[str] = None
    volume: str

    def __init__(
        self,
        registry: str,
        volume: str,
        group: Optional[str] = None,
        readOnly: Optional[bool] = None,
        tenant: Optional[str] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if registry is not None:
            self.registry = registry
        if volume is not None:
            self.volume = volume
        if group is not None:
            self.group = group
        if readOnly is not None:
            self.readOnly = readOnly
        if tenant is not None:
            self.tenant = tenant
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__RBDVolumeSource(K8STemplatable):
    """Represents a Rados Block Device mount that lasts the lifetime of a pod. RBD volumes support ownership management and SELinux relabeling."""

    props: List[str] = [
        "fsType",
        "image",
        "keyring",
        "monitors",
        "pool",
        "readOnly",
        "secretRef",
        "user",
    ]
    required_props: List[str] = ["monitors", "image"]

    fsType: Optional[str] = None
    image: str
    keyring: Optional[str] = None
    monitors: List[str]
    pool: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    user: Optional[str] = None

    def __init__(
        self,
        image: str,
        monitors: List[str],
        fsType: Optional[str] = None,
        keyring: Optional[str] = None,
        pool: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if image is not None:
            self.image = image
        if monitors is not None:
            self.monitors = monitors
        if fsType is not None:
            self.fsType = fsType
        if keyring is not None:
            self.keyring = keyring
        if pool is not None:
            self.pool = pool
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__ResourceQuotaStatus(K8STemplatable):
    """ResourceQuotaStatus defines the enforced hard limits and observed use."""

    props: List[str] = ["hard", "used"]
    required_props: List[str] = []

    hard: Any
    used: Any

    def __init__(self, hard: Any = None, used: Any = None):
        super().__init__()
        if hard is not None:
            self.hard = hard
        if used is not None:
            self.used = used


class io__k8s__api__core__v1__ResourceRequirements(K8STemplatable):
    """ResourceRequirements describes the compute resource requirements."""

    props: List[str] = ["limits", "requests"]
    required_props: List[str] = []

    limits: Any
    requests: Any

    def __init__(self, limits: Any = None, requests: Any = None):
        super().__init__()
        if limits is not None:
            self.limits = limits
        if requests is not None:
            self.requests = requests


class io__k8s__api__core__v1__SELinuxOptions(K8STemplatable):
    """SELinuxOptions are the labels to be applied to the container"""

    props: List[str] = ["level", "role", "type", "user"]
    required_props: List[str] = []

    level: Optional[str] = None
    role: Optional[str] = None
    type: Optional[str] = None
    user: Optional[str] = None

    def __init__(
        self,
        level: Optional[str] = None,
        role: Optional[str] = None,
        type: Optional[str] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if level is not None:
            self.level = level
        if role is not None:
            self.role = role
        if type is not None:
            self.type = type
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__ScaleIOVolumeSource(K8STemplatable):
    """ScaleIOVolumeSource represents a persistent ScaleIO volume"""

    props: List[str] = [
        "fsType",
        "gateway",
        "protectionDomain",
        "readOnly",
        "secretRef",
        "sslEnabled",
        "storageMode",
        "storagePool",
        "system",
        "volumeName",
    ]
    required_props: List[str] = ["gateway", "system", "secretRef"]

    fsType: Optional[str] = None
    gateway: str
    protectionDomain: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: io__k8s__api__core__v1__LocalObjectReference
    sslEnabled: Optional[bool] = None
    storageMode: Optional[str] = None
    storagePool: Optional[str] = None
    system: str
    volumeName: Optional[str] = None

    def __init__(
        self,
        gateway: str,
        secretRef: io__k8s__api__core__v1__LocalObjectReference,
        system: str,
        fsType: Optional[str] = None,
        protectionDomain: Optional[str] = None,
        readOnly: Optional[bool] = None,
        sslEnabled: Optional[bool] = None,
        storageMode: Optional[str] = None,
        storagePool: Optional[str] = None,
        volumeName: Optional[str] = None,
    ):
        super().__init__()
        if gateway is not None:
            self.gateway = gateway
        if secretRef is not None:
            self.secretRef = secretRef
        if system is not None:
            self.system = system
        if fsType is not None:
            self.fsType = fsType
        if protectionDomain is not None:
            self.protectionDomain = protectionDomain
        if readOnly is not None:
            self.readOnly = readOnly
        if sslEnabled is not None:
            self.sslEnabled = sslEnabled
        if storageMode is not None:
            self.storageMode = storageMode
        if storagePool is not None:
            self.storagePool = storagePool
        if volumeName is not None:
            self.volumeName = volumeName


class io__k8s__api__core__v1__ScopedResourceSelectorRequirement(K8STemplatable):
    """A scoped-resource selector requirement is a selector that contains values, a scope name, and an operator that relates the scope name and values."""

    props: List[str] = ["operator", "scopeName", "values"]
    required_props: List[str] = ["scopeName", "operator"]

    operator: str
    scopeName: str
    values: Optional[List[str]] = None

    def __init__(
        self, operator: str, scopeName: str, values: Optional[List[str]] = None
    ):
        super().__init__()
        if operator is not None:
            self.operator = operator
        if scopeName is not None:
            self.scopeName = scopeName
        if values is not None:
            self.values = values


class io__k8s__api__core__v1__SeccompProfile(K8STemplatable):
    """SeccompProfile defines a pod/container's seccomp profile settings. Only one profile source may be set."""

    props: List[str] = ["localhostProfile", "type"]
    required_props: List[str] = ["type"]

    localhostProfile: Optional[str] = None
    type: str

    def __init__(self, type: str, localhostProfile: Optional[str] = None):
        super().__init__()
        if type is not None:
            self.type = type
        if localhostProfile is not None:
            self.localhostProfile = localhostProfile


class io__k8s__api__core__v1__SecretEnvSource(K8STemplatable):
    """SecretEnvSource selects a Secret to populate the environment variables with.

    The contents of the target Secret's Data field will represent the key-value pairs as environment variables."""

    props: List[str] = ["name", "optional"]
    required_props: List[str] = []

    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(self, name: Optional[str] = None, optional: Optional[bool] = None):
        super().__init__()
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__SecretKeySelector(K8STemplatable):
    """SecretKeySelector selects a key of a Secret."""

    props: List[str] = ["key", "name", "optional"]
    required_props: List[str] = ["key"]

    key: str
    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(
        self, key: str, name: Optional[str] = None, optional: Optional[bool] = None
    ):
        super().__init__()
        if key is not None:
            self.key = key
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__SecretProjection(K8STemplatable):
    """Adapts a secret into a projected volume.

    The contents of the target Secret's Data field will be presented in a projected volume as files using the keys in the Data field as the file names. Note that this is identical to a secret volume source without the default mode."""

    props: List[str] = ["items", "name", "optional"]
    required_props: List[str] = []

    items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None
    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(
        self,
        items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None,
        name: Optional[str] = None,
        optional: Optional[bool] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__SecretReference(K8STemplatable):
    """SecretReference represents a Secret Reference. It has enough information to retrieve secret in any namespace"""

    props: List[str] = ["name", "namespace"]
    required_props: List[str] = []

    name: Optional[str] = None
    namespace: Optional[str] = None

    def __init__(self, name: Optional[str] = None, namespace: Optional[str] = None):
        super().__init__()
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace


class io__k8s__api__core__v1__SecretVolumeSource(K8STemplatable):
    """Adapts a Secret into a volume.

    The contents of the target Secret's Data field will be presented in a volume as files using the keys in the Data field as the file names. Secret volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["defaultMode", "items", "optional", "secretName"]
    required_props: List[str] = []

    defaultMode: Optional[int] = None
    items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None
    optional: Optional[bool] = None
    secretName: Optional[str] = None

    def __init__(
        self,
        defaultMode: Optional[int] = None,
        items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None,
        optional: Optional[bool] = None,
        secretName: Optional[str] = None,
    ):
        super().__init__()
        if defaultMode is not None:
            self.defaultMode = defaultMode
        if items is not None:
            self.items = items
        if optional is not None:
            self.optional = optional
        if secretName is not None:
            self.secretName = secretName


class io__k8s__api__core__v1__ServiceAccountTokenProjection(K8STemplatable):
    """ServiceAccountTokenProjection represents a projected service account token volume. This projection can be used to insert a service account token into the pods runtime filesystem for use against APIs (Kubernetes API Server or otherwise)."""

    props: List[str] = ["audience", "expirationSeconds", "path"]
    required_props: List[str] = ["path"]

    audience: Optional[str] = None
    expirationSeconds: Optional[int] = None
    path: str

    def __init__(
        self,
        path: str,
        audience: Optional[str] = None,
        expirationSeconds: Optional[int] = None,
    ):
        super().__init__()
        if path is not None:
            self.path = path
        if audience is not None:
            self.audience = audience
        if expirationSeconds is not None:
            self.expirationSeconds = expirationSeconds


class io__k8s__api__core__v1__SessionAffinityConfig(K8STemplatable):
    """SessionAffinityConfig represents the configurations of session affinity."""

    props: List[str] = ["clientIP"]
    required_props: List[str] = []

    clientIP: Optional[io__k8s__api__core__v1__ClientIPConfig] = None

    def __init__(
        self, clientIP: Optional[io__k8s__api__core__v1__ClientIPConfig] = None
    ):
        super().__init__()
        if clientIP is not None:
            self.clientIP = clientIP


class io__k8s__api__core__v1__StorageOSPersistentVolumeSource(K8STemplatable):
    """Represents a StorageOS persistent volume resource."""

    props: List[str] = [
        "fsType",
        "readOnly",
        "secretRef",
        "volumeName",
        "volumeNamespace",
    ]
    required_props: List[str] = []

    fsType: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__ObjectReference] = None
    volumeName: Optional[str] = None
    volumeNamespace: Optional[str] = None

    def __init__(
        self,
        fsType: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        volumeName: Optional[str] = None,
        volumeNamespace: Optional[str] = None,
    ):
        super().__init__()
        if fsType is not None:
            self.fsType = fsType
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef
        if volumeName is not None:
            self.volumeName = volumeName
        if volumeNamespace is not None:
            self.volumeNamespace = volumeNamespace


class io__k8s__api__core__v1__StorageOSVolumeSource(K8STemplatable):
    """Represents a StorageOS persistent volume resource."""

    props: List[str] = [
        "fsType",
        "readOnly",
        "secretRef",
        "volumeName",
        "volumeNamespace",
    ]
    required_props: List[str] = []

    fsType: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    volumeName: Optional[str] = None
    volumeNamespace: Optional[str] = None

    def __init__(
        self,
        fsType: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
        volumeName: Optional[str] = None,
        volumeNamespace: Optional[str] = None,
    ):
        super().__init__()
        if fsType is not None:
            self.fsType = fsType
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef
        if volumeName is not None:
            self.volumeName = volumeName
        if volumeNamespace is not None:
            self.volumeNamespace = volumeNamespace


class io__k8s__api__core__v1__Sysctl(K8STemplatable):
    """Sysctl defines a kernel parameter to be set"""

    props: List[str] = ["name", "value"]
    required_props: List[str] = ["name", "value"]

    name: str
    value: str

    def __init__(self, name: str, value: str):
        super().__init__()
        if name is not None:
            self.name = name
        if value is not None:
            self.value = value


class io__k8s__api__core__v1__Toleration(K8STemplatable):
    """The pod this Toleration is attached to tolerates any taint that matches the triple <key,value,effect> using the matching operator <operator>."""

    props: List[str] = ["effect", "key", "operator", "tolerationSeconds", "value"]
    required_props: List[str] = []

    effect: Optional[str] = None
    key: Optional[str] = None
    operator: Optional[str] = None
    tolerationSeconds: Optional[int] = None
    value: Optional[str] = None

    def __init__(
        self,
        effect: Optional[str] = None,
        key: Optional[str] = None,
        operator: Optional[str] = None,
        tolerationSeconds: Optional[int] = None,
        value: Optional[str] = None,
    ):
        super().__init__()
        if effect is not None:
            self.effect = effect
        if key is not None:
            self.key = key
        if operator is not None:
            self.operator = operator
        if tolerationSeconds is not None:
            self.tolerationSeconds = tolerationSeconds
        if value is not None:
            self.value = value


class io__k8s__api__core__v1__TopologySelectorLabelRequirement(K8STemplatable):
    """A topology selector requirement is a selector that matches given label. This is an alpha feature and may change in the future."""

    props: List[str] = ["key", "values"]
    required_props: List[str] = ["key", "values"]

    key: str
    values: List[str]

    def __init__(self, key: str, values: List[str]):
        super().__init__()
        if key is not None:
            self.key = key
        if values is not None:
            self.values = values


class io__k8s__api__core__v1__TopologySelectorTerm(K8STemplatable):
    """A topology selector term represents the result of label queries. A null or empty topology selector term matches no objects. The requirements of them are ANDed. It provides a subset of functionality as NodeSelectorTerm. This is an alpha feature and may change in the future."""

    props: List[str] = ["matchLabelExpressions"]
    required_props: List[str] = []

    matchLabelExpressions: Optional[
        List[io__k8s__api__core__v1__TopologySelectorLabelRequirement]
    ] = None

    def __init__(
        self,
        matchLabelExpressions: Optional[
            List[io__k8s__api__core__v1__TopologySelectorLabelRequirement]
        ] = None,
    ):
        super().__init__()
        if matchLabelExpressions is not None:
            self.matchLabelExpressions = matchLabelExpressions


class io__k8s__api__core__v1__TypedLocalObjectReference(K8STemplatable):
    """TypedLocalObjectReference contains enough information to let you locate the typed referenced object inside the same namespace."""

    props: List[str] = ["apiGroup", "kind", "name"]
    required_props: List[str] = ["kind", "name"]

    apiGroup: Optional[str] = None
    kind: str
    name: str

    def __init__(self, kind: str, name: str, apiGroup: Optional[str] = None):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiGroup is not None:
            self.apiGroup = apiGroup


class io__k8s__api__core__v1__VolumeDevice(K8STemplatable):
    """volumeDevice describes a mapping of a raw block device within a container."""

    props: List[str] = ["devicePath", "name"]
    required_props: List[str] = ["name", "devicePath"]

    devicePath: str
    name: str

    def __init__(self, devicePath: str, name: str):
        super().__init__()
        if devicePath is not None:
            self.devicePath = devicePath
        if name is not None:
            self.name = name


class io__k8s__api__core__v1__VolumeMount(K8STemplatable):
    """VolumeMount describes a mounting of a Volume within a container."""

    props: List[str] = [
        "mountPath",
        "mountPropagation",
        "name",
        "readOnly",
        "subPath",
        "subPathExpr",
    ]
    required_props: List[str] = ["name", "mountPath"]

    mountPath: str
    mountPropagation: Optional[str] = None
    name: str
    readOnly: Optional[bool] = None
    subPath: Optional[str] = None
    subPathExpr: Optional[str] = None

    def __init__(
        self,
        mountPath: str,
        name: str,
        mountPropagation: Optional[str] = None,
        readOnly: Optional[bool] = None,
        subPath: Optional[str] = None,
        subPathExpr: Optional[str] = None,
    ):
        super().__init__()
        if mountPath is not None:
            self.mountPath = mountPath
        if name is not None:
            self.name = name
        if mountPropagation is not None:
            self.mountPropagation = mountPropagation
        if readOnly is not None:
            self.readOnly = readOnly
        if subPath is not None:
            self.subPath = subPath
        if subPathExpr is not None:
            self.subPathExpr = subPathExpr


class io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource(K8STemplatable):
    """Represents a vSphere volume resource."""

    props: List[str] = ["fsType", "storagePolicyID", "storagePolicyName", "volumePath"]
    required_props: List[str] = ["volumePath"]

    fsType: Optional[str] = None
    storagePolicyID: Optional[str] = None
    storagePolicyName: Optional[str] = None
    volumePath: str

    def __init__(
        self,
        volumePath: str,
        fsType: Optional[str] = None,
        storagePolicyID: Optional[str] = None,
        storagePolicyName: Optional[str] = None,
    ):
        super().__init__()
        if volumePath is not None:
            self.volumePath = volumePath
        if fsType is not None:
            self.fsType = fsType
        if storagePolicyID is not None:
            self.storagePolicyID = storagePolicyID
        if storagePolicyName is not None:
            self.storagePolicyName = storagePolicyName


class io__k8s__api__core__v1__WindowsSecurityContextOptions(K8STemplatable):
    """WindowsSecurityContextOptions contain Windows-specific options and credentials."""

    props: List[str] = [
        "gmsaCredentialSpec",
        "gmsaCredentialSpecName",
        "hostProcess",
        "runAsUserName",
    ]
    required_props: List[str] = []

    gmsaCredentialSpec: Optional[str] = None
    gmsaCredentialSpecName: Optional[str] = None
    hostProcess: Optional[bool] = None
    runAsUserName: Optional[str] = None

    def __init__(
        self,
        gmsaCredentialSpec: Optional[str] = None,
        gmsaCredentialSpecName: Optional[str] = None,
        hostProcess: Optional[bool] = None,
        runAsUserName: Optional[str] = None,
    ):
        super().__init__()
        if gmsaCredentialSpec is not None:
            self.gmsaCredentialSpec = gmsaCredentialSpec
        if gmsaCredentialSpecName is not None:
            self.gmsaCredentialSpecName = gmsaCredentialSpecName
        if hostProcess is not None:
            self.hostProcess = hostProcess
        if runAsUserName is not None:
            self.runAsUserName = runAsUserName


class io__k8s__api__discovery__v1__EndpointConditions(K8STemplatable):
    """EndpointConditions represents the current condition of an endpoint."""

    props: List[str] = ["ready", "serving", "terminating"]
    required_props: List[str] = []

    ready: Optional[bool] = None
    serving: Optional[bool] = None
    terminating: Optional[bool] = None

    def __init__(
        self,
        ready: Optional[bool] = None,
        serving: Optional[bool] = None,
        terminating: Optional[bool] = None,
    ):
        super().__init__()
        if ready is not None:
            self.ready = ready
        if serving is not None:
            self.serving = serving
        if terminating is not None:
            self.terminating = terminating


class io__k8s__api__discovery__v1__EndpointPort(K8STemplatable):
    """EndpointPort represents a Port used by an EndpointSlice"""

    props: List[str] = ["appProtocol", "name", "port", "protocol"]
    required_props: List[str] = []

    appProtocol: Optional[str] = None
    name: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None

    def __init__(
        self,
        appProtocol: Optional[str] = None,
        name: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
    ):
        super().__init__()
        if appProtocol is not None:
            self.appProtocol = appProtocol
        if name is not None:
            self.name = name
        if port is not None:
            self.port = port
        if protocol is not None:
            self.protocol = protocol


class io__k8s__api__discovery__v1__ForZone(K8STemplatable):
    """ForZone provides information about which zones should consume this endpoint."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__discovery__v1beta1__EndpointConditions(K8STemplatable):
    """EndpointConditions represents the current condition of an endpoint."""

    props: List[str] = ["ready", "serving", "terminating"]
    required_props: List[str] = []

    ready: Optional[bool] = None
    serving: Optional[bool] = None
    terminating: Optional[bool] = None

    def __init__(
        self,
        ready: Optional[bool] = None,
        serving: Optional[bool] = None,
        terminating: Optional[bool] = None,
    ):
        super().__init__()
        if ready is not None:
            self.ready = ready
        if serving is not None:
            self.serving = serving
        if terminating is not None:
            self.terminating = terminating


class io__k8s__api__discovery__v1beta1__EndpointPort(K8STemplatable):
    """EndpointPort represents a Port used by an EndpointSlice"""

    props: List[str] = ["appProtocol", "name", "port", "protocol"]
    required_props: List[str] = []

    appProtocol: Optional[str] = None
    name: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None

    def __init__(
        self,
        appProtocol: Optional[str] = None,
        name: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
    ):
        super().__init__()
        if appProtocol is not None:
            self.appProtocol = appProtocol
        if name is not None:
            self.name = name
        if port is not None:
            self.port = port
        if protocol is not None:
            self.protocol = protocol


class io__k8s__api__discovery__v1beta1__ForZone(K8STemplatable):
    """ForZone provides information about which zones should consume this endpoint."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta1__FlowDistinguisherMethod(K8STemplatable):
    """FlowDistinguisherMethod specifies the method of a flow distinguisher."""

    props: List[str] = ["type"]
    required_props: List[str] = ["type"]

    type: str

    def __init__(self, type: str):
        super().__init__()
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta1__GroupSubject(K8STemplatable):
    """GroupSubject holds detailed information for group-kind subject."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta1__NonResourcePolicyRule(K8STemplatable):
    """NonResourcePolicyRule is a predicate that matches non-resource requests according to their verb and the target non-resource URL. A NonResourcePolicyRule matches a request if and only if both (a) at least one member of verbs matches the request and (b) at least one member of nonResourceURLs matches the request."""

    props: List[str] = ["nonResourceURLs", "verbs"]
    required_props: List[str] = ["verbs", "nonResourceURLs"]

    nonResourceURLs: List[str]
    verbs: List[str]

    def __init__(self, nonResourceURLs: List[str], verbs: List[str]):
        super().__init__()
        if nonResourceURLs is not None:
            self.nonResourceURLs = nonResourceURLs
        if verbs is not None:
            self.verbs = verbs


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationReference(
    K8STemplatable
):
    """PriorityLevelConfigurationReference contains information that points to the "request-priority" being used."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta1__QueuingConfiguration(K8STemplatable):
    """QueuingConfiguration holds the configuration parameters for queuing"""

    props: List[str] = ["handSize", "queueLengthLimit", "queues"]
    required_props: List[str] = []

    handSize: Optional[int] = None
    queueLengthLimit: Optional[int] = None
    queues: Optional[int] = None

    def __init__(
        self,
        handSize: Optional[int] = None,
        queueLengthLimit: Optional[int] = None,
        queues: Optional[int] = None,
    ):
        super().__init__()
        if handSize is not None:
            self.handSize = handSize
        if queueLengthLimit is not None:
            self.queueLengthLimit = queueLengthLimit
        if queues is not None:
            self.queues = queues


class io__k8s__api__flowcontrol__v1beta1__ResourcePolicyRule(K8STemplatable):
    """ResourcePolicyRule is a predicate that matches some resource requests, testing the request's verb and the target resource. A ResourcePolicyRule matches a resource request if and only if: (a) at least one member of verbs matches the request, (b) at least one member of apiGroups matches the request, (c) at least one member of resources matches the request, and (d) either (d1) the request does not specify a namespace (i.e., `Namespace==""`) and clusterScope is true or (d2) the request specifies a namespace and least one member of namespaces matches the request's namespace."""

    props: List[str] = ["apiGroups", "clusterScope", "namespaces", "resources", "verbs"]
    required_props: List[str] = ["verbs", "apiGroups", "resources"]

    apiGroups: List[str]
    clusterScope: Optional[bool] = None
    namespaces: Optional[List[str]] = None
    resources: List[str]
    verbs: List[str]

    def __init__(
        self,
        apiGroups: List[str],
        resources: List[str],
        verbs: List[str],
        clusterScope: Optional[bool] = None,
        namespaces: Optional[List[str]] = None,
    ):
        super().__init__()
        if apiGroups is not None:
            self.apiGroups = apiGroups
        if resources is not None:
            self.resources = resources
        if verbs is not None:
            self.verbs = verbs
        if clusterScope is not None:
            self.clusterScope = clusterScope
        if namespaces is not None:
            self.namespaces = namespaces


class io__k8s__api__flowcontrol__v1beta1__ServiceAccountSubject(K8STemplatable):
    """ServiceAccountSubject holds detailed information for service-account-kind subject."""

    props: List[str] = ["name", "namespace"]
    required_props: List[str] = ["namespace", "name"]

    name: str
    namespace: str

    def __init__(self, name: str, namespace: str):
        super().__init__()
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace


class io__k8s__api__flowcontrol__v1beta1__UserSubject(K8STemplatable):
    """UserSubject holds detailed information for user-kind subject."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta2__FlowDistinguisherMethod(K8STemplatable):
    """FlowDistinguisherMethod specifies the method of a flow distinguisher."""

    props: List[str] = ["type"]
    required_props: List[str] = ["type"]

    type: str

    def __init__(self, type: str):
        super().__init__()
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta2__GroupSubject(K8STemplatable):
    """GroupSubject holds detailed information for group-kind subject."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta2__NonResourcePolicyRule(K8STemplatable):
    """NonResourcePolicyRule is a predicate that matches non-resource requests according to their verb and the target non-resource URL. A NonResourcePolicyRule matches a request if and only if both (a) at least one member of verbs matches the request and (b) at least one member of nonResourceURLs matches the request."""

    props: List[str] = ["nonResourceURLs", "verbs"]
    required_props: List[str] = ["verbs", "nonResourceURLs"]

    nonResourceURLs: List[str]
    verbs: List[str]

    def __init__(self, nonResourceURLs: List[str], verbs: List[str]):
        super().__init__()
        if nonResourceURLs is not None:
            self.nonResourceURLs = nonResourceURLs
        if verbs is not None:
            self.verbs = verbs


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationReference(
    K8STemplatable
):
    """PriorityLevelConfigurationReference contains information that points to the "request-priority" being used."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__flowcontrol__v1beta2__QueuingConfiguration(K8STemplatable):
    """QueuingConfiguration holds the configuration parameters for queuing"""

    props: List[str] = ["handSize", "queueLengthLimit", "queues"]
    required_props: List[str] = []

    handSize: Optional[int] = None
    queueLengthLimit: Optional[int] = None
    queues: Optional[int] = None

    def __init__(
        self,
        handSize: Optional[int] = None,
        queueLengthLimit: Optional[int] = None,
        queues: Optional[int] = None,
    ):
        super().__init__()
        if handSize is not None:
            self.handSize = handSize
        if queueLengthLimit is not None:
            self.queueLengthLimit = queueLengthLimit
        if queues is not None:
            self.queues = queues


class io__k8s__api__flowcontrol__v1beta2__ResourcePolicyRule(K8STemplatable):
    """ResourcePolicyRule is a predicate that matches some resource requests, testing the request's verb and the target resource. A ResourcePolicyRule matches a resource request if and only if: (a) at least one member of verbs matches the request, (b) at least one member of apiGroups matches the request, (c) at least one member of resources matches the request, and (d) either (d1) the request does not specify a namespace (i.e., `Namespace==""`) and clusterScope is true or (d2) the request specifies a namespace and least one member of namespaces matches the request's namespace."""

    props: List[str] = ["apiGroups", "clusterScope", "namespaces", "resources", "verbs"]
    required_props: List[str] = ["verbs", "apiGroups", "resources"]

    apiGroups: List[str]
    clusterScope: Optional[bool] = None
    namespaces: Optional[List[str]] = None
    resources: List[str]
    verbs: List[str]

    def __init__(
        self,
        apiGroups: List[str],
        resources: List[str],
        verbs: List[str],
        clusterScope: Optional[bool] = None,
        namespaces: Optional[List[str]] = None,
    ):
        super().__init__()
        if apiGroups is not None:
            self.apiGroups = apiGroups
        if resources is not None:
            self.resources = resources
        if verbs is not None:
            self.verbs = verbs
        if clusterScope is not None:
            self.clusterScope = clusterScope
        if namespaces is not None:
            self.namespaces = namespaces


class io__k8s__api__flowcontrol__v1beta2__ServiceAccountSubject(K8STemplatable):
    """ServiceAccountSubject holds detailed information for service-account-kind subject."""

    props: List[str] = ["name", "namespace"]
    required_props: List[str] = ["namespace", "name"]

    name: str
    namespace: str

    def __init__(self, name: str, namespace: str):
        super().__init__()
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace


class io__k8s__api__flowcontrol__v1beta2__UserSubject(K8STemplatable):
    """UserSubject holds detailed information for user-kind subject."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__networking__v1__IPBlock(K8STemplatable):
    """IPBlock describes a particular CIDR (Ex. "192.168.1.1/24","2001:db9::/64") that is allowed to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs that should not be included within this rule."""

    props: List[str] = ["cidr", "k8s_except"]
    required_props: List[str] = ["cidr"]

    cidr: str
    k8s_except: Optional[List[str]] = None

    def __init__(self, cidr: str, k8s_except: Optional[List[str]] = None):
        super().__init__()
        if cidr is not None:
            self.cidr = cidr
        if k8s_except is not None:
            self.k8s_except = k8s_except


class io__k8s__api__networking__v1__IngressClassParametersReference(K8STemplatable):
    """IngressClassParametersReference identifies an API object. This can be used to specify a cluster or namespace-scoped resource."""

    props: List[str] = ["apiGroup", "kind", "name", "namespace", "scope"]
    required_props: List[str] = ["kind", "name"]

    apiGroup: Optional[str] = None
    kind: str
    name: str
    namespace: Optional[str] = None
    scope: Optional[str] = None

    def __init__(
        self,
        kind: str,
        name: str,
        apiGroup: Optional[str] = None,
        namespace: Optional[str] = None,
        scope: Optional[str] = None,
    ):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiGroup is not None:
            self.apiGroup = apiGroup
        if namespace is not None:
            self.namespace = namespace
        if scope is not None:
            self.scope = scope


class io__k8s__api__networking__v1__IngressClassSpec(K8STemplatable):
    """IngressClassSpec provides information about the class of an Ingress."""

    props: List[str] = ["controller", "parameters"]
    required_props: List[str] = []

    controller: Optional[str] = None
    parameters: Optional[
        io__k8s__api__networking__v1__IngressClassParametersReference
    ] = None

    def __init__(
        self,
        controller: Optional[str] = None,
        parameters: Optional[
            io__k8s__api__networking__v1__IngressClassParametersReference
        ] = None,
    ):
        super().__init__()
        if controller is not None:
            self.controller = controller
        if parameters is not None:
            self.parameters = parameters


class io__k8s__api__networking__v1__IngressTLS(K8STemplatable):
    """IngressTLS describes the transport layer security associated with an Ingress."""

    props: List[str] = ["hosts", "secretName"]
    required_props: List[str] = []

    hosts: Optional[List[str]] = None
    secretName: Optional[str] = None

    def __init__(
        self, hosts: Optional[List[str]] = None, secretName: Optional[str] = None
    ):
        super().__init__()
        if hosts is not None:
            self.hosts = hosts
        if secretName is not None:
            self.secretName = secretName


class io__k8s__api__networking__v1__ServiceBackendPort(K8STemplatable):
    """ServiceBackendPort is the service port being referenced."""

    props: List[str] = ["name", "number"]
    required_props: List[str] = []

    name: Optional[str] = None
    number: Optional[int] = None

    def __init__(self, name: Optional[str] = None, number: Optional[int] = None):
        super().__init__()
        if name is not None:
            self.name = name
        if number is not None:
            self.number = number


class io__k8s__api__node__v1__Overhead(K8STemplatable):
    """Overhead structure represents the resource overhead associated with running a pod."""

    props: List[str] = ["podFixed"]
    required_props: List[str] = []

    podFixed: Any

    def __init__(self, podFixed: Any = None):
        super().__init__()
        if podFixed is not None:
            self.podFixed = podFixed


class io__k8s__api__node__v1__Scheduling(K8STemplatable):
    """Scheduling specifies the scheduling constraints for nodes supporting a RuntimeClass."""

    props: List[str] = ["nodeSelector", "tolerations"]
    required_props: List[str] = []

    nodeSelector: Any
    tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None

    def __init__(
        self,
        nodeSelector: Any = None,
        tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None,
    ):
        super().__init__()
        if nodeSelector is not None:
            self.nodeSelector = nodeSelector
        if tolerations is not None:
            self.tolerations = tolerations


class io__k8s__api__node__v1beta1__Overhead(K8STemplatable):
    """Overhead structure represents the resource overhead associated with running a pod."""

    props: List[str] = ["podFixed"]
    required_props: List[str] = []

    podFixed: Any

    def __init__(self, podFixed: Any = None):
        super().__init__()
        if podFixed is not None:
            self.podFixed = podFixed


class io__k8s__api__node__v1beta1__Scheduling(K8STemplatable):
    """Scheduling specifies the scheduling constraints for nodes supporting a RuntimeClass."""

    props: List[str] = ["nodeSelector", "tolerations"]
    required_props: List[str] = []

    nodeSelector: Any
    tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None

    def __init__(
        self,
        nodeSelector: Any = None,
        tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None,
    ):
        super().__init__()
        if nodeSelector is not None:
            self.nodeSelector = nodeSelector
        if tolerations is not None:
            self.tolerations = tolerations


class io__k8s__api__policy__v1beta1__AllowedCSIDriver(K8STemplatable):
    """AllowedCSIDriver represents a single inline CSI Driver that is allowed to be used."""

    props: List[str] = ["name"]
    required_props: List[str] = ["name"]

    name: str

    def __init__(self, name: str):
        super().__init__()
        if name is not None:
            self.name = name


class io__k8s__api__policy__v1beta1__AllowedFlexVolume(K8STemplatable):
    """AllowedFlexVolume represents a single Flexvolume that is allowed to be used."""

    props: List[str] = ["driver"]
    required_props: List[str] = ["driver"]

    driver: str

    def __init__(self, driver: str):
        super().__init__()
        if driver is not None:
            self.driver = driver


class io__k8s__api__policy__v1beta1__AllowedHostPath(K8STemplatable):
    """AllowedHostPath defines the host volume conditions that will be enabled by a policy for pods to use. It requires the path prefix to be defined."""

    props: List[str] = ["pathPrefix", "readOnly"]
    required_props: List[str] = []

    pathPrefix: Optional[str] = None
    readOnly: Optional[bool] = None

    def __init__(
        self, pathPrefix: Optional[str] = None, readOnly: Optional[bool] = None
    ):
        super().__init__()
        if pathPrefix is not None:
            self.pathPrefix = pathPrefix
        if readOnly is not None:
            self.readOnly = readOnly


class io__k8s__api__policy__v1beta1__HostPortRange(K8STemplatable):
    """HostPortRange defines a range of host ports that will be enabled by a policy for pods to use.  It requires both the start and end to be defined."""

    props: List[str] = ["max", "min"]
    required_props: List[str] = ["min", "max"]

    max: int
    min: int

    def __init__(self, max: int, min: int):
        super().__init__()
        if max is not None:
            self.max = max
        if min is not None:
            self.min = min


class io__k8s__api__policy__v1beta1__IDRange(K8STemplatable):
    """IDRange provides a min/max of an allowed range of IDs."""

    props: List[str] = ["max", "min"]
    required_props: List[str] = ["min", "max"]

    max: int
    min: int

    def __init__(self, max: int, min: int):
        super().__init__()
        if max is not None:
            self.max = max
        if min is not None:
            self.min = min


class io__k8s__api__policy__v1beta1__RunAsGroupStrategyOptions(K8STemplatable):
    """RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy."""

    props: List[str] = ["ranges", "rule"]
    required_props: List[str] = ["rule"]

    ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None
    rule: str

    def __init__(
        self,
        rule: str,
        ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None,
    ):
        super().__init__()
        if rule is not None:
            self.rule = rule
        if ranges is not None:
            self.ranges = ranges


class io__k8s__api__policy__v1beta1__RunAsUserStrategyOptions(K8STemplatable):
    """RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy."""

    props: List[str] = ["ranges", "rule"]
    required_props: List[str] = ["rule"]

    ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None
    rule: str

    def __init__(
        self,
        rule: str,
        ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None,
    ):
        super().__init__()
        if rule is not None:
            self.rule = rule
        if ranges is not None:
            self.ranges = ranges


class io__k8s__api__policy__v1beta1__RuntimeClassStrategyOptions(K8STemplatable):
    """RuntimeClassStrategyOptions define the strategy that will dictate the allowable RuntimeClasses for a pod."""

    props: List[str] = ["allowedRuntimeClassNames", "defaultRuntimeClassName"]
    required_props: List[str] = ["allowedRuntimeClassNames"]

    allowedRuntimeClassNames: List[str]
    defaultRuntimeClassName: Optional[str] = None

    def __init__(
        self,
        allowedRuntimeClassNames: List[str],
        defaultRuntimeClassName: Optional[str] = None,
    ):
        super().__init__()
        if allowedRuntimeClassNames is not None:
            self.allowedRuntimeClassNames = allowedRuntimeClassNames
        if defaultRuntimeClassName is not None:
            self.defaultRuntimeClassName = defaultRuntimeClassName


class io__k8s__api__policy__v1beta1__SELinuxStrategyOptions(K8STemplatable):
    """SELinuxStrategyOptions defines the strategy type and any options used to create the strategy."""

    props: List[str] = ["rule", "seLinuxOptions"]
    required_props: List[str] = ["rule"]

    rule: str
    seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None

    def __init__(
        self,
        rule: str,
        seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None,
    ):
        super().__init__()
        if rule is not None:
            self.rule = rule
        if seLinuxOptions is not None:
            self.seLinuxOptions = seLinuxOptions


class io__k8s__api__policy__v1beta1__SupplementalGroupsStrategyOptions(K8STemplatable):
    """SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy."""

    props: List[str] = ["ranges", "rule"]
    required_props: List[str] = []

    ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None
    rule: Optional[str] = None

    def __init__(
        self,
        ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None,
        rule: Optional[str] = None,
    ):
        super().__init__()
        if ranges is not None:
            self.ranges = ranges
        if rule is not None:
            self.rule = rule


class io__k8s__api__rbac__v1__PolicyRule(K8STemplatable):
    """PolicyRule holds information that describes a policy rule, but does not contain information about who the rule applies to or which namespace the rule applies to."""

    props: List[str] = [
        "apiGroups",
        "nonResourceURLs",
        "resourceNames",
        "resources",
        "verbs",
    ]
    required_props: List[str] = ["verbs"]

    apiGroups: Optional[List[str]] = None
    nonResourceURLs: Optional[List[str]] = None
    resourceNames: Optional[List[str]] = None
    resources: Optional[List[str]] = None
    verbs: List[str]

    def __init__(
        self,
        verbs: List[str],
        apiGroups: Optional[List[str]] = None,
        nonResourceURLs: Optional[List[str]] = None,
        resourceNames: Optional[List[str]] = None,
        resources: Optional[List[str]] = None,
    ):
        super().__init__()
        if verbs is not None:
            self.verbs = verbs
        if apiGroups is not None:
            self.apiGroups = apiGroups
        if nonResourceURLs is not None:
            self.nonResourceURLs = nonResourceURLs
        if resourceNames is not None:
            self.resourceNames = resourceNames
        if resources is not None:
            self.resources = resources


class io__k8s__api__rbac__v1__RoleRef(K8STemplatable):
    """RoleRef contains information that points to the role being used"""

    props: List[str] = ["apiGroup", "kind", "name"]
    required_props: List[str] = ["apiGroup", "kind", "name"]

    apiGroup: str
    kind: str
    name: str

    def __init__(self, apiGroup: str, kind: str, name: str):
        super().__init__()
        if apiGroup is not None:
            self.apiGroup = apiGroup
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name


class io__k8s__api__rbac__v1__Subject(K8STemplatable):
    """Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference, or a value for non-objects such as user and group names."""

    props: List[str] = ["apiGroup", "kind", "name", "namespace"]
    required_props: List[str] = ["kind", "name"]

    apiGroup: Optional[str] = None
    kind: str
    name: str
    namespace: Optional[str] = None

    def __init__(
        self,
        kind: str,
        name: str,
        apiGroup: Optional[str] = None,
        namespace: Optional[str] = None,
    ):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if apiGroup is not None:
            self.apiGroup = apiGroup
        if namespace is not None:
            self.namespace = namespace


class io__k8s__api__storage__v1__TokenRequest(K8STemplatable):
    """TokenRequest contains parameters of a service account token."""

    props: List[str] = ["audience", "expirationSeconds"]
    required_props: List[str] = ["audience"]

    audience: str
    expirationSeconds: Optional[int] = None

    def __init__(self, audience: str, expirationSeconds: Optional[int] = None):
        super().__init__()
        if audience is not None:
            self.audience = audience
        if expirationSeconds is not None:
            self.expirationSeconds = expirationSeconds


class io__k8s__api__storage__v1__VolumeNodeResources(K8STemplatable):
    """VolumeNodeResources is a set of resource limits for scheduling of volumes."""

    props: List[str] = ["count"]
    required_props: List[str] = []

    count: Optional[int] = None

    def __init__(self, count: Optional[int] = None):
        super().__init__()
        if count is not None:
            self.count = count


class io__k8s__apimachinery__pkg__api__resource__Quantity(K8STemplatable):
    """Quantity is a fixed-point representation of a number. It provides convenient marshaling/unmarshaling in JSON and YAML, in addition to String() and AsInt64() accessors.

    The serialization format is:

    <quantity>        ::= <signedNumber><suffix>
      (Note that <suffix> may be empty, from the "" case in <decimalSI>.)
    <digit>           ::= 0 | 1 | ... | 9 <digits>          ::= <digit> | <digit><digits> <number>          ::= <digits> | <digits>.<digits> | <digits>. | .<digits> <sign>            ::= "+" | "-" <signedNumber>    ::= <number> | <sign><number> <suffix>          ::= <binarySI> | <decimalExponent> | <decimalSI> <binarySI>        ::= Ki | Mi | Gi | Ti | Pi | Ei
      (International System of units; See: http://physics.nist.gov/cuu/Units/binary.html)
    <decimalSI>       ::= m | "" | k | M | G | T | P | E
      (Note that 1024 = 1Ki but 1000 = 1k; I didn't choose the capitalization.)
    <decimalExponent> ::= "e" <signedNumber> | "E" <signedNumber>

    No matter which of the three exponent forms is used, no quantity may represent a number greater than 2^63-1 in magnitude, nor may it have more than 3 decimal places. Numbers larger or more precise will be capped or rounded up. (E.g.: 0.1m will rounded up to 1m.) This may be extended in the future if we require larger or smaller quantities.

    When a Quantity is parsed from a string, it will remember the type of suffix it had, and will use the same type again when it is serialized.

    Before serializing, Quantity will be put in "canonical form". This means that Exponent/suffix will be adjusted up or down (with a corresponding increase or decrease in Mantissa) such that:
      a. No precision is lost
      b. No fractional digits will be emitted
      c. The exponent (or suffix) is as large as possible.
    The sign will be omitted unless the number is negative.

    Examples:
      1.5 will be serialized as "1500m"
      1.5Gi will be serialized as "1536Mi"

    Note that the quantity will NEVER be internally represented by a floating point number. That is the whole point of this exercise.

    Non-canonical values will still parse as long as they are well formed, but will be re-emitted in their canonical form. (So always use canonical form, or don't diff.)

    This format is intended to make it difficult to use these numbers without writing some sort of special handling code in the hopes that that will cause implementors to also use a fixed point implementation."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__apis__meta__v1__APIResource(K8STemplatable):
    """APIResource specifies the name of a resource and whether it is namespaced."""

    props: List[str] = [
        "categories",
        "group",
        "kind",
        "name",
        "namespaced",
        "shortNames",
        "singularName",
        "storageVersionHash",
        "verbs",
        "version",
    ]
    required_props: List[str] = ["name", "singularName", "namespaced", "kind", "verbs"]

    categories: Optional[List[str]] = None
    group: Optional[str] = None
    kind: str
    name: str
    namespaced: bool
    shortNames: Optional[List[str]] = None
    singularName: str
    storageVersionHash: Optional[str] = None
    verbs: List[str]
    version: Optional[str] = None

    def __init__(
        self,
        kind: str,
        name: str,
        namespaced: bool,
        singularName: str,
        verbs: List[str],
        categories: Optional[List[str]] = None,
        group: Optional[str] = None,
        shortNames: Optional[List[str]] = None,
        storageVersionHash: Optional[str] = None,
        version: Optional[str] = None,
    ):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if namespaced is not None:
            self.namespaced = namespaced
        if singularName is not None:
            self.singularName = singularName
        if verbs is not None:
            self.verbs = verbs
        if categories is not None:
            self.categories = categories
        if group is not None:
            self.group = group
        if shortNames is not None:
            self.shortNames = shortNames
        if storageVersionHash is not None:
            self.storageVersionHash = storageVersionHash
        if version is not None:
            self.version = version


class io__k8s__apimachinery__pkg__apis__meta__v1__APIResourceList(K8STemplatable):
    """APIResourceList is a list of APIResource, it is used to expose the name of the resources supported in a specific group and version, and if the resource is namespaced."""

    apiVersion: str = "v1"
    kind: str = "APIResourceList"

    props: List[str] = ["apiVersion", "groupVersion", "kind", "resources"]
    required_props: List[str] = ["groupVersion", "resources"]

    groupVersion: str
    resources: List[io__k8s__apimachinery__pkg__apis__meta__v1__APIResource]

    def __init__(
        self,
        groupVersion: str,
        resources: List[io__k8s__apimachinery__pkg__apis__meta__v1__APIResource],
    ):
        super().__init__()
        if groupVersion is not None:
            self.groupVersion = groupVersion
        if resources is not None:
            self.resources = resources


class io__k8s__apimachinery__pkg__apis__meta__v1__FieldsV1(K8STemplatable):
    """FieldsV1 stores a set of fields in a data structure like a Trie, in JSON format.

    Each key is either a '.' representing the field itself, and will always map to an empty set, or a string representing a sub-field or item. The string will follow one of these four formats: 'f:<name>', where <name> is the name of a field in a struct, or key in a map 'v:<value>', where <value> is the exact json formatted value of a list item 'i:<index>', where <index> is position of a item in a list 'k:<keys>', where <keys> is a map of  a list item's key fields to their unique values If a key maps to an empty Fields value, the field that key represents is part of the set.

    The exact format is defined in sigs.k8s.io/structured-merge-diff"""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery(
    K8STemplatable
):
    """GroupVersion contains the "group/version" and "version" string of a version. It is made a struct to keep extensibility."""

    props: List[str] = ["groupVersion", "version"]
    required_props: List[str] = ["groupVersion", "version"]

    groupVersion: str
    version: str

    def __init__(self, groupVersion: str, version: str):
        super().__init__()
        if groupVersion is not None:
            self.groupVersion = groupVersion
        if version is not None:
            self.version = version


class io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelectorRequirement(
    K8STemplatable
):
    """A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values."""

    props: List[str] = ["key", "operator", "values"]
    required_props: List[str] = ["key", "operator"]

    key: str
    operator: str
    values: Optional[List[str]] = None

    def __init__(self, key: str, operator: str, values: Optional[List[str]] = None):
        super().__init__()
        if key is not None:
            self.key = key
        if operator is not None:
            self.operator = operator
        if values is not None:
            self.values = values


class io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta(K8STemplatable):
    """ListMeta describes metadata that synthetic resources must have, including lists and various status objects. A resource may have only one of {ObjectMeta, ListMeta}."""

    props: List[str] = [
        "k8s_continue",
        "remainingItemCount",
        "resourceVersion",
        "selfLink",
    ]
    required_props: List[str] = []

    k8s_continue: Optional[str] = None
    remainingItemCount: Optional[int] = None
    resourceVersion: Optional[str] = None
    selfLink: Optional[str] = None

    def __init__(
        self,
        k8s_continue: Optional[str] = None,
        remainingItemCount: Optional[int] = None,
        resourceVersion: Optional[str] = None,
        selfLink: Optional[str] = None,
    ):
        super().__init__()
        if k8s_continue is not None:
            self.k8s_continue = k8s_continue
        if remainingItemCount is not None:
            self.remainingItemCount = remainingItemCount
        if resourceVersion is not None:
            self.resourceVersion = resourceVersion
        if selfLink is not None:
            self.selfLink = selfLink


class io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime(K8STemplatable):
    """MicroTime is version of Time with microsecond level precision."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__apis__meta__v1__OwnerReference(K8STemplatable):
    """OwnerReference contains enough information to let you identify an owning object. An owning object must be in the same namespace as the dependent, or be cluster-scoped, so there is no namespace field."""

    props: List[str] = [
        "apiVersion",
        "blockOwnerDeletion",
        "controller",
        "kind",
        "name",
        "uid",
    ]
    required_props: List[str] = ["apiVersion", "kind", "name", "uid"]

    apiVersion: str
    blockOwnerDeletion: Optional[bool] = None
    controller: Optional[bool] = None
    kind: str
    name: str
    uid: str

    def __init__(
        self,
        apiVersion: str,
        kind: str,
        name: str,
        uid: str,
        blockOwnerDeletion: Optional[bool] = None,
        controller: Optional[bool] = None,
    ):
        super().__init__()
        if apiVersion is not None:
            self.apiVersion = apiVersion
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if uid is not None:
            self.uid = uid
        if blockOwnerDeletion is not None:
            self.blockOwnerDeletion = blockOwnerDeletion
        if controller is not None:
            self.controller = controller


class io__k8s__apimachinery__pkg__apis__meta__v1__Patch(K8STemplatable):
    """Patch is provided to give a concrete name and type to the Kubernetes PATCH request body."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__apis__meta__v1__Preconditions(K8STemplatable):
    """Preconditions must be fulfilled before an operation (update, delete, etc.) is carried out."""

    props: List[str] = ["resourceVersion", "uid"]
    required_props: List[str] = []

    resourceVersion: Optional[str] = None
    uid: Optional[str] = None

    def __init__(
        self, resourceVersion: Optional[str] = None, uid: Optional[str] = None
    ):
        super().__init__()
        if resourceVersion is not None:
            self.resourceVersion = resourceVersion
        if uid is not None:
            self.uid = uid


class io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR(
    K8STemplatable
):
    """ServerAddressByClientCIDR helps the client to determine the server address that they should use, depending on the clientCIDR that they match."""

    props: List[str] = ["clientCIDR", "serverAddress"]
    required_props: List[str] = ["clientCIDR", "serverAddress"]

    clientCIDR: str
    serverAddress: str

    def __init__(self, clientCIDR: str, serverAddress: str):
        super().__init__()
        if clientCIDR is not None:
            self.clientCIDR = clientCIDR
        if serverAddress is not None:
            self.serverAddress = serverAddress


class io__k8s__apimachinery__pkg__apis__meta__v1__StatusCause(K8STemplatable):
    """StatusCause provides more information about an api.Status failure, including cases when multiple errors are encountered."""

    props: List[str] = ["field", "message", "reason"]
    required_props: List[str] = []

    field: Optional[str] = None
    message: Optional[str] = None
    reason: Optional[str] = None

    def __init__(
        self,
        field: Optional[str] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if field is not None:
            self.field = field
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__apimachinery__pkg__apis__meta__v1__StatusDetails(K8STemplatable):
    """StatusDetails is a set of additional properties that MAY be set by the server to provide additional information about a response. The Reason field of a Status object defines what attributes will be set. Clients must ignore fields that do not match the defined type of each attribute, and should assume that any attribute may be empty, invalid, or under defined."""

    props: List[str] = ["causes", "group", "kind", "name", "retryAfterSeconds", "uid"]
    required_props: List[str] = []

    causes: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__StatusCause]
    ] = None
    group: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    retryAfterSeconds: Optional[int] = None
    uid: Optional[str] = None

    def __init__(
        self,
        causes: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__StatusCause]
        ] = None,
        group: Optional[str] = None,
        kind: Optional[str] = None,
        name: Optional[str] = None,
        retryAfterSeconds: Optional[int] = None,
        uid: Optional[str] = None,
    ):
        super().__init__()
        if causes is not None:
            self.causes = causes
        if group is not None:
            self.group = group
        if kind is not None:
            self.kind = kind
        if name is not None:
            self.name = name
        if retryAfterSeconds is not None:
            self.retryAfterSeconds = retryAfterSeconds
        if uid is not None:
            self.uid = uid


class io__k8s__apimachinery__pkg__apis__meta__v1__Time(K8STemplatable):
    """Time is a wrapper around time.Time which supports correct marshaling to YAML and JSON.  Wrappers are provided for many of the factory methods that the time package offers."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__runtime__RawExtension(K8STemplatable):
    """RawExtension is used to hold extensions in external versions.

    To use this, make a field which has RawExtension as its type in your external, versioned struct, and Object in your internal struct. You also need to register your various plugin types.

    // Internal package: type MyAPIObject struct {
            runtime.TypeMeta `json:",inline"`
            MyPlugin runtime.Object `json:"myPlugin"`
    } type PluginA struct {
            AOption string `json:"aOption"`
    }

    // External package: type MyAPIObject struct {
            runtime.TypeMeta `json:",inline"`
            MyPlugin runtime.RawExtension `json:"myPlugin"`
    } type PluginA struct {
            AOption string `json:"aOption"`
    }

    // On the wire, the JSON will look something like this: {
            "kind":"MyAPIObject",
            "apiVersion":"v1",
            "myPlugin": {
                    "kind":"PluginA",
                    "aOption":"foo",
            },
    }

    So what happens? Decode first uses json or yaml to unmarshal the serialized data into your external MyAPIObject. That causes the raw JSON to be stored, but not unpacked. The next step is to copy (using pkg/conversion) into the internal struct. The runtime package's DefaultScheme has conversion functions installed which will unpack the JSON stored in RawExtension, turning it into the correct object type, and storing it in the Object. (TODO: In the case where the object is of an unknown type, a runtime.Unknown object will be created and stored.)"""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__util__intstr__IntOrString(K8STemplatable):
    """IntOrString is a type that can hold an int32 or a string.  When used in JSON or YAML marshalling and unmarshalling, it produces or consumes the inner type.  This allows you to have, for example, a JSON field that can accept a name or number."""

    props: List[str] = []
    required_props: List[str] = []


class io__k8s__apimachinery__pkg__version__Info(K8STemplatable):
    """Info contains versioning information. how we'll want to distribute that information."""

    props: List[str] = [
        "buildDate",
        "compiler",
        "gitCommit",
        "gitTreeState",
        "gitVersion",
        "goVersion",
        "major",
        "minor",
        "platform",
    ]
    required_props: List[str] = [
        "major",
        "minor",
        "gitVersion",
        "gitCommit",
        "gitTreeState",
        "buildDate",
        "goVersion",
        "compiler",
        "platform",
    ]

    buildDate: str
    compiler: str
    gitCommit: str
    gitTreeState: str
    gitVersion: str
    goVersion: str
    major: str
    minor: str
    platform: str

    def __init__(
        self,
        buildDate: str,
        compiler: str,
        gitCommit: str,
        gitTreeState: str,
        gitVersion: str,
        goVersion: str,
        major: str,
        minor: str,
        platform: str,
    ):
        super().__init__()
        if buildDate is not None:
            self.buildDate = buildDate
        if compiler is not None:
            self.compiler = compiler
        if gitCommit is not None:
            self.gitCommit = gitCommit
        if gitTreeState is not None:
            self.gitTreeState = gitTreeState
        if gitVersion is not None:
            self.gitVersion = gitVersion
        if goVersion is not None:
            self.goVersion = goVersion
        if major is not None:
            self.major = major
        if minor is not None:
            self.minor = minor
        if platform is not None:
            self.platform = platform


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceCondition(
    K8STemplatable
):
    """APIServiceCondition describes the state of an APIService at a particular point"""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceStatus(
    K8STemplatable
):
    """APIServiceStatus contains derived information about an API server"""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[
            io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceCondition
        ]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[
                io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceCondition
            ]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__ServiceReference(
    K8STemplatable
):
    """ServiceReference holds a reference to Service.legacy.k8s.io"""

    props: List[str] = ["name", "namespace", "port"]
    required_props: List[str] = []

    name: Optional[str] = None
    namespace: Optional[str] = None
    port: Optional[int] = None

    def __init__(
        self,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        port: Optional[int] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if port is not None:
            self.port = port


class io__k8s__api__apiserverinternal__v1alpha1__StorageVersionCondition(
    K8STemplatable
):
    """Describes the state of the storageVersion at a certain point."""

    props: List[str] = [
        "lastTransitionTime",
        "message",
        "observedGeneration",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status", "reason"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    observedGeneration: Optional[int] = None
    reason: str
    status: str
    type: str

    def __init__(
        self,
        reason: str,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__apiserverinternal__v1alpha1__StorageVersionStatus(K8STemplatable):
    """API server instances report the versions they can decode and the version they encode objects to when persisting objects in the backend."""

    props: List[str] = ["commonEncodingVersion", "conditions", "storageVersions"]
    required_props: List[str] = []

    commonEncodingVersion: Optional[str] = None
    conditions: Optional[
        List[io__k8s__api__apiserverinternal__v1alpha1__StorageVersionCondition]
    ] = None
    storageVersions: Optional[
        List[io__k8s__api__apiserverinternal__v1alpha1__ServerStorageVersion]
    ] = None

    def __init__(
        self,
        commonEncodingVersion: Optional[str] = None,
        conditions: Optional[
            List[io__k8s__api__apiserverinternal__v1alpha1__StorageVersionCondition]
        ] = None,
        storageVersions: Optional[
            List[io__k8s__api__apiserverinternal__v1alpha1__ServerStorageVersion]
        ] = None,
    ):
        super().__init__()
        if commonEncodingVersion is not None:
            self.commonEncodingVersion = commonEncodingVersion
        if conditions is not None:
            self.conditions = conditions
        if storageVersions is not None:
            self.storageVersions = storageVersions


class io__k8s__api__apps__v1__DaemonSetCondition(K8STemplatable):
    """DaemonSetCondition describes the state of a DaemonSet at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__apps__v1__DaemonSetStatus(K8STemplatable):
    """DaemonSetStatus represents the current status of a daemon set."""

    props: List[str] = [
        "collisionCount",
        "conditions",
        "currentNumberScheduled",
        "desiredNumberScheduled",
        "numberAvailable",
        "numberMisscheduled",
        "numberReady",
        "numberUnavailable",
        "observedGeneration",
        "updatedNumberScheduled",
    ]
    required_props: List[str] = [
        "currentNumberScheduled",
        "numberMisscheduled",
        "desiredNumberScheduled",
        "numberReady",
    ]

    collisionCount: Optional[int] = None
    conditions: Optional[List[io__k8s__api__apps__v1__DaemonSetCondition]] = None
    currentNumberScheduled: int
    desiredNumberScheduled: int
    numberAvailable: Optional[int] = None
    numberMisscheduled: int
    numberReady: int
    numberUnavailable: Optional[int] = None
    observedGeneration: Optional[int] = None
    updatedNumberScheduled: Optional[int] = None

    def __init__(
        self,
        currentNumberScheduled: int,
        desiredNumberScheduled: int,
        numberMisscheduled: int,
        numberReady: int,
        collisionCount: Optional[int] = None,
        conditions: Optional[List[io__k8s__api__apps__v1__DaemonSetCondition]] = None,
        numberAvailable: Optional[int] = None,
        numberUnavailable: Optional[int] = None,
        observedGeneration: Optional[int] = None,
        updatedNumberScheduled: Optional[int] = None,
    ):
        super().__init__()
        if currentNumberScheduled is not None:
            self.currentNumberScheduled = currentNumberScheduled
        if desiredNumberScheduled is not None:
            self.desiredNumberScheduled = desiredNumberScheduled
        if numberMisscheduled is not None:
            self.numberMisscheduled = numberMisscheduled
        if numberReady is not None:
            self.numberReady = numberReady
        if collisionCount is not None:
            self.collisionCount = collisionCount
        if conditions is not None:
            self.conditions = conditions
        if numberAvailable is not None:
            self.numberAvailable = numberAvailable
        if numberUnavailable is not None:
            self.numberUnavailable = numberUnavailable
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration
        if updatedNumberScheduled is not None:
            self.updatedNumberScheduled = updatedNumberScheduled


class io__k8s__api__apps__v1__DeploymentCondition(K8STemplatable):
    """DeploymentCondition describes the state of a deployment at a certain point."""

    props: List[str] = [
        "lastTransitionTime",
        "lastUpdateTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    lastUpdateTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastUpdateTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if lastUpdateTime is not None:
            self.lastUpdateTime = lastUpdateTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__apps__v1__DeploymentStatus(K8STemplatable):
    """DeploymentStatus is the most recently observed status of the Deployment."""

    props: List[str] = [
        "availableReplicas",
        "collisionCount",
        "conditions",
        "observedGeneration",
        "readyReplicas",
        "replicas",
        "unavailableReplicas",
        "updatedReplicas",
    ]
    required_props: List[str] = []

    availableReplicas: Optional[int] = None
    collisionCount: Optional[int] = None
    conditions: Optional[List[io__k8s__api__apps__v1__DeploymentCondition]] = None
    observedGeneration: Optional[int] = None
    readyReplicas: Optional[int] = None
    replicas: Optional[int] = None
    unavailableReplicas: Optional[int] = None
    updatedReplicas: Optional[int] = None

    def __init__(
        self,
        availableReplicas: Optional[int] = None,
        collisionCount: Optional[int] = None,
        conditions: Optional[List[io__k8s__api__apps__v1__DeploymentCondition]] = None,
        observedGeneration: Optional[int] = None,
        readyReplicas: Optional[int] = None,
        replicas: Optional[int] = None,
        unavailableReplicas: Optional[int] = None,
        updatedReplicas: Optional[int] = None,
    ):
        super().__init__()
        if availableReplicas is not None:
            self.availableReplicas = availableReplicas
        if collisionCount is not None:
            self.collisionCount = collisionCount
        if conditions is not None:
            self.conditions = conditions
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration
        if readyReplicas is not None:
            self.readyReplicas = readyReplicas
        if replicas is not None:
            self.replicas = replicas
        if unavailableReplicas is not None:
            self.unavailableReplicas = unavailableReplicas
        if updatedReplicas is not None:
            self.updatedReplicas = updatedReplicas


class io__k8s__api__apps__v1__ReplicaSetCondition(K8STemplatable):
    """ReplicaSetCondition describes the state of a replica set at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__apps__v1__ReplicaSetStatus(K8STemplatable):
    """ReplicaSetStatus represents the current status of a ReplicaSet."""

    props: List[str] = [
        "availableReplicas",
        "conditions",
        "fullyLabeledReplicas",
        "observedGeneration",
        "readyReplicas",
        "replicas",
    ]
    required_props: List[str] = ["replicas"]

    availableReplicas: Optional[int] = None
    conditions: Optional[List[io__k8s__api__apps__v1__ReplicaSetCondition]] = None
    fullyLabeledReplicas: Optional[int] = None
    observedGeneration: Optional[int] = None
    readyReplicas: Optional[int] = None
    replicas: int

    def __init__(
        self,
        replicas: int,
        availableReplicas: Optional[int] = None,
        conditions: Optional[List[io__k8s__api__apps__v1__ReplicaSetCondition]] = None,
        fullyLabeledReplicas: Optional[int] = None,
        observedGeneration: Optional[int] = None,
        readyReplicas: Optional[int] = None,
    ):
        super().__init__()
        if replicas is not None:
            self.replicas = replicas
        if availableReplicas is not None:
            self.availableReplicas = availableReplicas
        if conditions is not None:
            self.conditions = conditions
        if fullyLabeledReplicas is not None:
            self.fullyLabeledReplicas = fullyLabeledReplicas
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration
        if readyReplicas is not None:
            self.readyReplicas = readyReplicas


class io__k8s__api__apps__v1__RollingUpdateDaemonSet(K8STemplatable):
    """Spec to control the desired behavior of daemon set rolling update."""

    props: List[str] = ["maxSurge", "maxUnavailable"]
    required_props: List[str] = []

    maxSurge: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None
    maxUnavailable: Optional[
        io__k8s__apimachinery__pkg__util__intstr__IntOrString
    ] = None

    def __init__(
        self,
        maxSurge: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        maxUnavailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
    ):
        super().__init__()
        if maxSurge is not None:
            self.maxSurge = maxSurge
        if maxUnavailable is not None:
            self.maxUnavailable = maxUnavailable


class io__k8s__api__apps__v1__RollingUpdateDeployment(K8STemplatable):
    """Spec to control the desired behavior of rolling update."""

    props: List[str] = ["maxSurge", "maxUnavailable"]
    required_props: List[str] = []

    maxSurge: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None
    maxUnavailable: Optional[
        io__k8s__apimachinery__pkg__util__intstr__IntOrString
    ] = None

    def __init__(
        self,
        maxSurge: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        maxUnavailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
    ):
        super().__init__()
        if maxSurge is not None:
            self.maxSurge = maxSurge
        if maxUnavailable is not None:
            self.maxUnavailable = maxUnavailable


class io__k8s__api__apps__v1__RollingUpdateStatefulSetStrategy(K8STemplatable):
    """RollingUpdateStatefulSetStrategy is used to communicate parameter for RollingUpdateStatefulSetStrategyType."""

    props: List[str] = ["maxUnavailable", "partition"]
    required_props: List[str] = []

    maxUnavailable: Optional[
        io__k8s__apimachinery__pkg__util__intstr__IntOrString
    ] = None
    partition: Optional[int] = None

    def __init__(
        self,
        maxUnavailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        partition: Optional[int] = None,
    ):
        super().__init__()
        if maxUnavailable is not None:
            self.maxUnavailable = maxUnavailable
        if partition is not None:
            self.partition = partition


class io__k8s__api__apps__v1__StatefulSetCondition(K8STemplatable):
    """StatefulSetCondition describes the state of a statefulset at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__apps__v1__StatefulSetStatus(K8STemplatable):
    """StatefulSetStatus represents the current state of a StatefulSet."""

    props: List[str] = [
        "availableReplicas",
        "collisionCount",
        "conditions",
        "currentReplicas",
        "currentRevision",
        "observedGeneration",
        "readyReplicas",
        "replicas",
        "updateRevision",
        "updatedReplicas",
    ]
    required_props: List[str] = ["replicas"]

    availableReplicas: Optional[int] = None
    collisionCount: Optional[int] = None
    conditions: Optional[List[io__k8s__api__apps__v1__StatefulSetCondition]] = None
    currentReplicas: Optional[int] = None
    currentRevision: Optional[str] = None
    observedGeneration: Optional[int] = None
    readyReplicas: Optional[int] = None
    replicas: int
    updateRevision: Optional[str] = None
    updatedReplicas: Optional[int] = None

    def __init__(
        self,
        replicas: int,
        availableReplicas: Optional[int] = None,
        collisionCount: Optional[int] = None,
        conditions: Optional[List[io__k8s__api__apps__v1__StatefulSetCondition]] = None,
        currentReplicas: Optional[int] = None,
        currentRevision: Optional[str] = None,
        observedGeneration: Optional[int] = None,
        readyReplicas: Optional[int] = None,
        updateRevision: Optional[str] = None,
        updatedReplicas: Optional[int] = None,
    ):
        super().__init__()
        if replicas is not None:
            self.replicas = replicas
        if availableReplicas is not None:
            self.availableReplicas = availableReplicas
        if collisionCount is not None:
            self.collisionCount = collisionCount
        if conditions is not None:
            self.conditions = conditions
        if currentReplicas is not None:
            self.currentReplicas = currentReplicas
        if currentRevision is not None:
            self.currentRevision = currentRevision
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration
        if readyReplicas is not None:
            self.readyReplicas = readyReplicas
        if updateRevision is not None:
            self.updateRevision = updateRevision
        if updatedReplicas is not None:
            self.updatedReplicas = updatedReplicas


class io__k8s__api__apps__v1__StatefulSetUpdateStrategy(K8STemplatable):
    """StatefulSetUpdateStrategy indicates the strategy that the StatefulSet controller will use to perform updates. It includes any additional parameters necessary to perform the update for the indicated strategy."""

    props: List[str] = ["rollingUpdate", "type"]
    required_props: List[str] = []

    rollingUpdate: Optional[
        io__k8s__api__apps__v1__RollingUpdateStatefulSetStrategy
    ] = None
    type: Optional[str] = None

    def __init__(
        self,
        rollingUpdate: Optional[
            io__k8s__api__apps__v1__RollingUpdateStatefulSetStrategy
        ] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if rollingUpdate is not None:
            self.rollingUpdate = rollingUpdate
        if type is not None:
            self.type = type


class io__k8s__api__authentication__v1__TokenRequestStatus(K8STemplatable):
    """TokenRequestStatus is the result of a token request."""

    props: List[str] = ["expirationTimestamp", "token"]
    required_props: List[str] = ["token", "expirationTimestamp"]

    expirationTimestamp: io__k8s__apimachinery__pkg__apis__meta__v1__Time
    token: str

    def __init__(
        self,
        expirationTimestamp: io__k8s__apimachinery__pkg__apis__meta__v1__Time,
        token: str,
    ):
        super().__init__()
        if expirationTimestamp is not None:
            self.expirationTimestamp = expirationTimestamp
        if token is not None:
            self.token = token


class io__k8s__api__authentication__v1__TokenReviewStatus(K8STemplatable):
    """TokenReviewStatus is the result of the token authentication request."""

    props: List[str] = ["audiences", "authenticated", "error", "user"]
    required_props: List[str] = []

    audiences: Optional[List[str]] = None
    authenticated: Optional[bool] = None
    error: Optional[str] = None
    user: Optional[io__k8s__api__authentication__v1__UserInfo] = None

    def __init__(
        self,
        audiences: Optional[List[str]] = None,
        authenticated: Optional[bool] = None,
        error: Optional[str] = None,
        user: Optional[io__k8s__api__authentication__v1__UserInfo] = None,
    ):
        super().__init__()
        if audiences is not None:
            self.audiences = audiences
        if authenticated is not None:
            self.authenticated = authenticated
        if error is not None:
            self.error = error
        if user is not None:
            self.user = user


class io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerStatus(K8STemplatable):
    """current status of a horizontal pod autoscaler"""

    props: List[str] = [
        "currentCPUUtilizationPercentage",
        "currentReplicas",
        "desiredReplicas",
        "lastScaleTime",
        "observedGeneration",
    ]
    required_props: List[str] = ["currentReplicas", "desiredReplicas"]

    currentCPUUtilizationPercentage: Optional[int] = None
    currentReplicas: int
    desiredReplicas: int
    lastScaleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        currentReplicas: int,
        desiredReplicas: int,
        currentCPUUtilizationPercentage: Optional[int] = None,
        lastScaleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if currentReplicas is not None:
            self.currentReplicas = currentReplicas
        if desiredReplicas is not None:
            self.desiredReplicas = desiredReplicas
        if currentCPUUtilizationPercentage is not None:
            self.currentCPUUtilizationPercentage = currentCPUUtilizationPercentage
        if lastScaleTime is not None:
            self.lastScaleTime = lastScaleTime
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerCondition(K8STemplatable):
    """HorizontalPodAutoscalerCondition describes the state of a HorizontalPodAutoscaler at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__autoscaling__v2__MetricTarget(K8STemplatable):
    """MetricTarget defines the target value, average value, or average utilization of a specific metric"""

    props: List[str] = ["averageUtilization", "averageValue", "type", "value"]
    required_props: List[str] = ["type"]

    averageUtilization: Optional[int] = None
    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    type: str
    value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        type: str,
        averageUtilization: Optional[int] = None,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if averageUtilization is not None:
            self.averageUtilization = averageUtilization
        if averageValue is not None:
            self.averageValue = averageValue
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2__MetricValueStatus(K8STemplatable):
    """MetricValueStatus holds the current value for a metric"""

    props: List[str] = ["averageUtilization", "averageValue", "value"]
    required_props: List[str] = []

    averageUtilization: Optional[int] = None
    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        averageUtilization: Optional[int] = None,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if averageUtilization is not None:
            self.averageUtilization = averageUtilization
        if averageValue is not None:
            self.averageValue = averageValue
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2__ResourceMetricSource(K8STemplatable):
    """ResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = ["name", "target"]
    required_props: List[str] = ["name", "target"]

    name: str
    target: io__k8s__api__autoscaling__v2__MetricTarget

    def __init__(self, name: str, target: io__k8s__api__autoscaling__v2__MetricTarget):
        super().__init__()
        if name is not None:
            self.name = name
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2__ResourceMetricStatus(K8STemplatable):
    """ResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = ["current", "name"]
    required_props: List[str] = ["name", "current"]

    current: io__k8s__api__autoscaling__v2__MetricValueStatus
    name: str

    def __init__(
        self, current: io__k8s__api__autoscaling__v2__MetricValueStatus, name: str
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if name is not None:
            self.name = name


class io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricSource(K8STemplatable):
    """ContainerResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = [
        "container",
        "name",
        "targetAverageUtilization",
        "targetAverageValue",
    ]
    required_props: List[str] = ["name", "container"]

    container: str
    name: str
    targetAverageUtilization: Optional[int] = None
    targetAverageValue: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None

    def __init__(
        self,
        container: str,
        name: str,
        targetAverageUtilization: Optional[int] = None,
        targetAverageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if name is not None:
            self.name = name
        if targetAverageUtilization is not None:
            self.targetAverageUtilization = targetAverageUtilization
        if targetAverageValue is not None:
            self.targetAverageValue = targetAverageValue


class io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricStatus(K8STemplatable):
    """ContainerResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing a single container in each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = [
        "container",
        "currentAverageUtilization",
        "currentAverageValue",
        "name",
    ]
    required_props: List[str] = ["name", "currentAverageValue", "container"]

    container: str
    currentAverageUtilization: Optional[int] = None
    currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity
    name: str

    def __init__(
        self,
        container: str,
        currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        name: str,
        currentAverageUtilization: Optional[int] = None,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if currentAverageValue is not None:
            self.currentAverageValue = currentAverageValue
        if name is not None:
            self.name = name
        if currentAverageUtilization is not None:
            self.currentAverageUtilization = currentAverageUtilization


class io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerCondition(
    K8STemplatable
):
    """HorizontalPodAutoscalerCondition describes the state of a HorizontalPodAutoscaler at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__autoscaling__v2beta1__ResourceMetricSource(K8STemplatable):
    """ResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = ["name", "targetAverageUtilization", "targetAverageValue"]
    required_props: List[str] = ["name"]

    name: str
    targetAverageUtilization: Optional[int] = None
    targetAverageValue: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None

    def __init__(
        self,
        name: str,
        targetAverageUtilization: Optional[int] = None,
        targetAverageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if targetAverageUtilization is not None:
            self.targetAverageUtilization = targetAverageUtilization
        if targetAverageValue is not None:
            self.targetAverageValue = targetAverageValue


class io__k8s__api__autoscaling__v2beta1__ResourceMetricStatus(K8STemplatable):
    """ResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = ["currentAverageUtilization", "currentAverageValue", "name"]
    required_props: List[str] = ["name", "currentAverageValue"]

    currentAverageUtilization: Optional[int] = None
    currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity
    name: str

    def __init__(
        self,
        currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        name: str,
        currentAverageUtilization: Optional[int] = None,
    ):
        super().__init__()
        if currentAverageValue is not None:
            self.currentAverageValue = currentAverageValue
        if name is not None:
            self.name = name
        if currentAverageUtilization is not None:
            self.currentAverageUtilization = currentAverageUtilization


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerCondition(
    K8STemplatable
):
    """HorizontalPodAutoscalerCondition describes the state of a HorizontalPodAutoscaler at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__autoscaling__v2beta2__MetricTarget(K8STemplatable):
    """MetricTarget defines the target value, average value, or average utilization of a specific metric"""

    props: List[str] = ["averageUtilization", "averageValue", "type", "value"]
    required_props: List[str] = ["type"]

    averageUtilization: Optional[int] = None
    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    type: str
    value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        type: str,
        averageUtilization: Optional[int] = None,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if averageUtilization is not None:
            self.averageUtilization = averageUtilization
        if averageValue is not None:
            self.averageValue = averageValue
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2beta2__MetricValueStatus(K8STemplatable):
    """MetricValueStatus holds the current value for a metric"""

    props: List[str] = ["averageUtilization", "averageValue", "value"]
    required_props: List[str] = []

    averageUtilization: Optional[int] = None
    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        averageUtilization: Optional[int] = None,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        value: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if averageUtilization is not None:
            self.averageUtilization = averageUtilization
        if averageValue is not None:
            self.averageValue = averageValue
        if value is not None:
            self.value = value


class io__k8s__api__autoscaling__v2beta2__ResourceMetricSource(K8STemplatable):
    """ResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = ["name", "target"]
    required_props: List[str] = ["name", "target"]

    name: str
    target: io__k8s__api__autoscaling__v2beta2__MetricTarget

    def __init__(
        self, name: str, target: io__k8s__api__autoscaling__v2beta2__MetricTarget
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2beta2__ResourceMetricStatus(K8STemplatable):
    """ResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = ["current", "name"]
    required_props: List[str] = ["name", "current"]

    current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus
    name: str

    def __init__(
        self, current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus, name: str
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if name is not None:
            self.name = name


class io__k8s__api__batch__v1__CronJobStatus(K8STemplatable):
    """CronJobStatus represents the current state of a cron job."""

    props: List[str] = ["active", "lastScheduleTime", "lastSuccessfulTime"]
    required_props: List[str] = []

    active: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None
    lastScheduleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastSuccessfulTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None

    def __init__(
        self,
        active: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None,
        lastScheduleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastSuccessfulTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
    ):
        super().__init__()
        if active is not None:
            self.active = active
        if lastScheduleTime is not None:
            self.lastScheduleTime = lastScheduleTime
        if lastSuccessfulTime is not None:
            self.lastSuccessfulTime = lastSuccessfulTime


class io__k8s__api__batch__v1__JobCondition(K8STemplatable):
    """JobCondition describes current state of a job."""

    props: List[str] = [
        "lastProbeTime",
        "lastTransitionTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastProbeTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastProbeTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastProbeTime is not None:
            self.lastProbeTime = lastProbeTime
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__batch__v1__JobStatus(K8STemplatable):
    """JobStatus represents the current state of a Job."""

    props: List[str] = [
        "active",
        "completedIndexes",
        "completionTime",
        "conditions",
        "failed",
        "ready",
        "startTime",
        "succeeded",
        "uncountedTerminatedPods",
    ]
    required_props: List[str] = []

    active: Optional[int] = None
    completedIndexes: Optional[str] = None
    completionTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    conditions: Optional[List[io__k8s__api__batch__v1__JobCondition]] = None
    failed: Optional[int] = None
    ready: Optional[int] = None
    startTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    succeeded: Optional[int] = None
    uncountedTerminatedPods: Optional[
        io__k8s__api__batch__v1__UncountedTerminatedPods
    ] = None

    def __init__(
        self,
        active: Optional[int] = None,
        completedIndexes: Optional[str] = None,
        completionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        conditions: Optional[List[io__k8s__api__batch__v1__JobCondition]] = None,
        failed: Optional[int] = None,
        ready: Optional[int] = None,
        startTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
        succeeded: Optional[int] = None,
        uncountedTerminatedPods: Optional[
            io__k8s__api__batch__v1__UncountedTerminatedPods
        ] = None,
    ):
        super().__init__()
        if active is not None:
            self.active = active
        if completedIndexes is not None:
            self.completedIndexes = completedIndexes
        if completionTime is not None:
            self.completionTime = completionTime
        if conditions is not None:
            self.conditions = conditions
        if failed is not None:
            self.failed = failed
        if ready is not None:
            self.ready = ready
        if startTime is not None:
            self.startTime = startTime
        if succeeded is not None:
            self.succeeded = succeeded
        if uncountedTerminatedPods is not None:
            self.uncountedTerminatedPods = uncountedTerminatedPods


class io__k8s__api__batch__v1beta1__CronJobStatus(K8STemplatable):
    """CronJobStatus represents the current state of a cron job."""

    props: List[str] = ["active", "lastScheduleTime", "lastSuccessfulTime"]
    required_props: List[str] = []

    active: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None
    lastScheduleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastSuccessfulTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None

    def __init__(
        self,
        active: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None,
        lastScheduleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastSuccessfulTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
    ):
        super().__init__()
        if active is not None:
            self.active = active
        if lastScheduleTime is not None:
            self.lastScheduleTime = lastScheduleTime
        if lastSuccessfulTime is not None:
            self.lastSuccessfulTime = lastSuccessfulTime


class io__k8s__api__certificates__v1__CertificateSigningRequestCondition(
    K8STemplatable
):
    """CertificateSigningRequestCondition describes a condition of a CertificateSigningRequest object"""

    props: List[str] = [
        "lastTransitionTime",
        "lastUpdateTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    lastUpdateTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastUpdateTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if lastUpdateTime is not None:
            self.lastUpdateTime = lastUpdateTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__certificates__v1__CertificateSigningRequestStatus(K8STemplatable):
    """CertificateSigningRequestStatus contains conditions used to indicate approved/denied/failed status of the request, and the issued certificate."""

    props: List[str] = ["certificate", "conditions"]
    required_props: List[str] = []

    certificate: Optional[str] = None
    conditions: Optional[
        List[io__k8s__api__certificates__v1__CertificateSigningRequestCondition]
    ] = None

    def __init__(
        self,
        certificate: Optional[str] = None,
        conditions: Optional[
            List[io__k8s__api__certificates__v1__CertificateSigningRequestCondition]
        ] = None,
    ):
        super().__init__()
        if certificate is not None:
            self.certificate = certificate
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__coordination__v1__LeaseSpec(K8STemplatable):
    """LeaseSpec is a specification of a Lease."""

    props: List[str] = [
        "acquireTime",
        "holderIdentity",
        "leaseDurationSeconds",
        "leaseTransitions",
        "renewTime",
    ]
    required_props: List[str] = []

    acquireTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime] = None
    holderIdentity: Optional[str] = None
    leaseDurationSeconds: Optional[int] = None
    leaseTransitions: Optional[int] = None
    renewTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime] = None

    def __init__(
        self,
        acquireTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
        ] = None,
        holderIdentity: Optional[str] = None,
        leaseDurationSeconds: Optional[int] = None,
        leaseTransitions: Optional[int] = None,
        renewTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
        ] = None,
    ):
        super().__init__()
        if acquireTime is not None:
            self.acquireTime = acquireTime
        if holderIdentity is not None:
            self.holderIdentity = holderIdentity
        if leaseDurationSeconds is not None:
            self.leaseDurationSeconds = leaseDurationSeconds
        if leaseTransitions is not None:
            self.leaseTransitions = leaseTransitions
        if renewTime is not None:
            self.renewTime = renewTime


class io__k8s__api__core__v1__CSIPersistentVolumeSource(K8STemplatable):
    """Represents storage that is managed by an external CSI volume driver (Beta feature)"""

    props: List[str] = [
        "controllerExpandSecretRef",
        "controllerPublishSecretRef",
        "driver",
        "fsType",
        "nodePublishSecretRef",
        "nodeStageSecretRef",
        "readOnly",
        "volumeAttributes",
        "volumeHandle",
    ]
    required_props: List[str] = ["driver", "volumeHandle"]

    controllerExpandSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    controllerPublishSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    driver: str
    fsType: Optional[str] = None
    nodePublishSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    nodeStageSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    readOnly: Optional[bool] = None
    volumeAttributes: Any
    volumeHandle: str

    def __init__(
        self,
        driver: str,
        volumeHandle: str,
        controllerExpandSecretRef: Optional[
            io__k8s__api__core__v1__SecretReference
        ] = None,
        controllerPublishSecretRef: Optional[
            io__k8s__api__core__v1__SecretReference
        ] = None,
        fsType: Optional[str] = None,
        nodePublishSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
        nodeStageSecretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
        readOnly: Optional[bool] = None,
        volumeAttributes: Any = None,
    ):
        super().__init__()
        if driver is not None:
            self.driver = driver
        if volumeHandle is not None:
            self.volumeHandle = volumeHandle
        if controllerExpandSecretRef is not None:
            self.controllerExpandSecretRef = controllerExpandSecretRef
        if controllerPublishSecretRef is not None:
            self.controllerPublishSecretRef = controllerPublishSecretRef
        if fsType is not None:
            self.fsType = fsType
        if nodePublishSecretRef is not None:
            self.nodePublishSecretRef = nodePublishSecretRef
        if nodeStageSecretRef is not None:
            self.nodeStageSecretRef = nodeStageSecretRef
        if readOnly is not None:
            self.readOnly = readOnly
        if volumeAttributes is not None:
            self.volumeAttributes = volumeAttributes


class io__k8s__api__core__v1__CSIVolumeSource(K8STemplatable):
    """Represents a source location of a volume to mount, managed by an external CSI driver"""

    props: List[str] = [
        "driver",
        "fsType",
        "nodePublishSecretRef",
        "readOnly",
        "volumeAttributes",
    ]
    required_props: List[str] = ["driver"]

    driver: str
    fsType: Optional[str] = None
    nodePublishSecretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    readOnly: Optional[bool] = None
    volumeAttributes: Any

    def __init__(
        self,
        driver: str,
        fsType: Optional[str] = None,
        nodePublishSecretRef: Optional[
            io__k8s__api__core__v1__LocalObjectReference
        ] = None,
        readOnly: Optional[bool] = None,
        volumeAttributes: Any = None,
    ):
        super().__init__()
        if driver is not None:
            self.driver = driver
        if fsType is not None:
            self.fsType = fsType
        if nodePublishSecretRef is not None:
            self.nodePublishSecretRef = nodePublishSecretRef
        if readOnly is not None:
            self.readOnly = readOnly
        if volumeAttributes is not None:
            self.volumeAttributes = volumeAttributes


class io__k8s__api__core__v1__CephFSPersistentVolumeSource(K8STemplatable):
    """Represents a Ceph Filesystem mount that lasts the lifetime of a pod Cephfs volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = [
        "monitors",
        "path",
        "readOnly",
        "secretFile",
        "secretRef",
        "user",
    ]
    required_props: List[str] = ["monitors"]

    monitors: List[str]
    path: Optional[str] = None
    readOnly: Optional[bool] = None
    secretFile: Optional[str] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    user: Optional[str] = None

    def __init__(
        self,
        monitors: List[str],
        path: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretFile: Optional[str] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if monitors is not None:
            self.monitors = monitors
        if path is not None:
            self.path = path
        if readOnly is not None:
            self.readOnly = readOnly
        if secretFile is not None:
            self.secretFile = secretFile
        if secretRef is not None:
            self.secretRef = secretRef
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__CephFSVolumeSource(K8STemplatable):
    """Represents a Ceph Filesystem mount that lasts the lifetime of a pod Cephfs volumes do not support ownership management or SELinux relabeling."""

    props: List[str] = [
        "monitors",
        "path",
        "readOnly",
        "secretFile",
        "secretRef",
        "user",
    ]
    required_props: List[str] = ["monitors"]

    monitors: List[str]
    path: Optional[str] = None
    readOnly: Optional[bool] = None
    secretFile: Optional[str] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    user: Optional[str] = None

    def __init__(
        self,
        monitors: List[str],
        path: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretFile: Optional[str] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if monitors is not None:
            self.monitors = monitors
        if path is not None:
            self.path = path
        if readOnly is not None:
            self.readOnly = readOnly
        if secretFile is not None:
            self.secretFile = secretFile
        if secretRef is not None:
            self.secretRef = secretRef
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__CinderPersistentVolumeSource(K8STemplatable):
    """Represents a cinder volume resource in Openstack. A Cinder volume must exist before mounting to a container. The volume must also be in the same region as the kubelet. Cinder volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["fsType", "readOnly", "secretRef", "volumeID"]
    required_props: List[str] = ["volumeID"]

    fsType: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    volumeID: str

    def __init__(
        self,
        volumeID: str,
        fsType: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
    ):
        super().__init__()
        if volumeID is not None:
            self.volumeID = volumeID
        if fsType is not None:
            self.fsType = fsType
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__CinderVolumeSource(K8STemplatable):
    """Represents a cinder volume resource in Openstack. A Cinder volume must exist before mounting to a container. The volume must also be in the same region as the kubelet. Cinder volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["fsType", "readOnly", "secretRef", "volumeID"]
    required_props: List[str] = ["volumeID"]

    fsType: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    volumeID: str

    def __init__(
        self,
        volumeID: str,
        fsType: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
    ):
        super().__init__()
        if volumeID is not None:
            self.volumeID = volumeID
        if fsType is not None:
            self.fsType = fsType
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__ConfigMapProjection(K8STemplatable):
    """Adapts a ConfigMap into a projected volume.

    The contents of the target ConfigMap's Data field will be presented in a projected volume as files using the keys in the Data field as the file names, unless the items element is populated with specific mappings of keys to paths. Note that this is identical to a configmap volume source without the default mode."""

    props: List[str] = ["items", "name", "optional"]
    required_props: List[str] = []

    items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None
    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(
        self,
        items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None,
        name: Optional[str] = None,
        optional: Optional[bool] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__ConfigMapVolumeSource(K8STemplatable):
    """Adapts a ConfigMap into a volume.

    The contents of the target ConfigMap's Data field will be presented in a volume as files using the keys in the Data field as the file names, unless the items element is populated with specific mappings of keys to paths. ConfigMap volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["defaultMode", "items", "name", "optional"]
    required_props: List[str] = []

    defaultMode: Optional[int] = None
    items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None
    name: Optional[str] = None
    optional: Optional[bool] = None

    def __init__(
        self,
        defaultMode: Optional[int] = None,
        items: Optional[List[io__k8s__api__core__v1__KeyToPath]] = None,
        name: Optional[str] = None,
        optional: Optional[bool] = None,
    ):
        super().__init__()
        if defaultMode is not None:
            self.defaultMode = defaultMode
        if items is not None:
            self.items = items
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional


class io__k8s__api__core__v1__ContainerStateRunning(K8STemplatable):
    """ContainerStateRunning is a running state of a container."""

    props: List[str] = ["startedAt"]
    required_props: List[str] = []

    startedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None

    def __init__(
        self,
        startedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
    ):
        super().__init__()
        if startedAt is not None:
            self.startedAt = startedAt


class io__k8s__api__core__v1__ContainerStateTerminated(K8STemplatable):
    """ContainerStateTerminated is a terminated state of a container."""

    props: List[str] = [
        "containerID",
        "exitCode",
        "finishedAt",
        "message",
        "reason",
        "signal",
        "startedAt",
    ]
    required_props: List[str] = ["exitCode"]

    containerID: Optional[str] = None
    exitCode: int
    finishedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    signal: Optional[int] = None
    startedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None

    def __init__(
        self,
        exitCode: int,
        containerID: Optional[str] = None,
        finishedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        signal: Optional[int] = None,
        startedAt: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
    ):
        super().__init__()
        if exitCode is not None:
            self.exitCode = exitCode
        if containerID is not None:
            self.containerID = containerID
        if finishedAt is not None:
            self.finishedAt = finishedAt
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if signal is not None:
            self.signal = signal
        if startedAt is not None:
            self.startedAt = startedAt


class io__k8s__api__core__v1__EmptyDirVolumeSource(K8STemplatable):
    """Represents an empty directory for a pod. Empty directory volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["medium", "sizeLimit"]
    required_props: List[str] = []

    medium: Optional[str] = None
    sizeLimit: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        medium: Optional[str] = None,
        sizeLimit: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if medium is not None:
            self.medium = medium
        if sizeLimit is not None:
            self.sizeLimit = sizeLimit


class io__k8s__api__core__v1__EndpointAddress(K8STemplatable):
    """EndpointAddress is a tuple that describes single IP address."""

    props: List[str] = ["hostname", "ip", "nodeName", "targetRef"]
    required_props: List[str] = ["ip"]

    hostname: Optional[str] = None
    ip: str
    nodeName: Optional[str] = None
    targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None

    def __init__(
        self,
        ip: str,
        hostname: Optional[str] = None,
        nodeName: Optional[str] = None,
        targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None,
    ):
        super().__init__()
        if ip is not None:
            self.ip = ip
        if hostname is not None:
            self.hostname = hostname
        if nodeName is not None:
            self.nodeName = nodeName
        if targetRef is not None:
            self.targetRef = targetRef


class io__k8s__api__core__v1__EndpointSubset(K8STemplatable):
    """EndpointSubset is a group of addresses with a common set of ports. The expanded set of endpoints is the Cartesian product of Addresses x Ports. For example, given:
      {
        Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
        Ports:     [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
      }
    The resulting set of endpoints can be viewed as:
        a: [ 10.10.1.1:8675, 10.10.2.2:8675 ],
        b: [ 10.10.1.1:309, 10.10.2.2:309 ]"""

    props: List[str] = ["addresses", "notReadyAddresses", "ports"]
    required_props: List[str] = []

    addresses: Optional[List[io__k8s__api__core__v1__EndpointAddress]] = None
    notReadyAddresses: Optional[List[io__k8s__api__core__v1__EndpointAddress]] = None
    ports: Optional[List[io__k8s__api__core__v1__EndpointPort]] = None

    def __init__(
        self,
        addresses: Optional[List[io__k8s__api__core__v1__EndpointAddress]] = None,
        notReadyAddresses: Optional[
            List[io__k8s__api__core__v1__EndpointAddress]
        ] = None,
        ports: Optional[List[io__k8s__api__core__v1__EndpointPort]] = None,
    ):
        super().__init__()
        if addresses is not None:
            self.addresses = addresses
        if notReadyAddresses is not None:
            self.notReadyAddresses = notReadyAddresses
        if ports is not None:
            self.ports = ports


class io__k8s__api__core__v1__EnvFromSource(K8STemplatable):
    """EnvFromSource represents the source of a set of ConfigMaps"""

    props: List[str] = ["configMapRef", "prefix", "secretRef"]
    required_props: List[str] = []

    configMapRef: Optional[io__k8s__api__core__v1__ConfigMapEnvSource] = None
    prefix: Optional[str] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretEnvSource] = None

    def __init__(
        self,
        configMapRef: Optional[io__k8s__api__core__v1__ConfigMapEnvSource] = None,
        prefix: Optional[str] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretEnvSource] = None,
    ):
        super().__init__()
        if configMapRef is not None:
            self.configMapRef = configMapRef
        if prefix is not None:
            self.prefix = prefix
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__EventSeries(K8STemplatable):
    """EventSeries contain information on series of events, i.e. thing that was/is happening continuously for some time."""

    props: List[str] = ["count", "lastObservedTime"]
    required_props: List[str] = []

    count: Optional[int] = None
    lastObservedTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
    ] = None

    def __init__(
        self,
        count: Optional[int] = None,
        lastObservedTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
        ] = None,
    ):
        super().__init__()
        if count is not None:
            self.count = count
        if lastObservedTime is not None:
            self.lastObservedTime = lastObservedTime


class io__k8s__api__core__v1__FlexPersistentVolumeSource(K8STemplatable):
    """FlexPersistentVolumeSource represents a generic persistent volume resource that is provisioned/attached using an exec based plugin."""

    props: List[str] = ["driver", "fsType", "options", "readOnly", "secretRef"]
    required_props: List[str] = ["driver"]

    driver: str
    fsType: Optional[str] = None
    options: Any
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None

    def __init__(
        self,
        driver: str,
        fsType: Optional[str] = None,
        options: Any = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
    ):
        super().__init__()
        if driver is not None:
            self.driver = driver
        if fsType is not None:
            self.fsType = fsType
        if options is not None:
            self.options = options
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__FlexVolumeSource(K8STemplatable):
    """FlexVolume represents a generic volume resource that is provisioned/attached using an exec based plugin."""

    props: List[str] = ["driver", "fsType", "options", "readOnly", "secretRef"]
    required_props: List[str] = ["driver"]

    driver: str
    fsType: Optional[str] = None
    options: Any
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None

    def __init__(
        self,
        driver: str,
        fsType: Optional[str] = None,
        options: Any = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
    ):
        super().__init__()
        if driver is not None:
            self.driver = driver
        if fsType is not None:
            self.fsType = fsType
        if options is not None:
            self.options = options
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__HTTPGetAction(K8STemplatable):
    """HTTPGetAction describes an action based on HTTP Get requests."""

    props: List[str] = ["host", "httpHeaders", "path", "port", "scheme"]
    required_props: List[str] = ["port"]

    host: Optional[str] = None
    httpHeaders: Optional[List[io__k8s__api__core__v1__HTTPHeader]] = None
    path: Optional[str] = None
    port: io__k8s__apimachinery__pkg__util__intstr__IntOrString
    scheme: Optional[str] = None

    def __init__(
        self,
        port: io__k8s__apimachinery__pkg__util__intstr__IntOrString,
        host: Optional[str] = None,
        httpHeaders: Optional[List[io__k8s__api__core__v1__HTTPHeader]] = None,
        path: Optional[str] = None,
        scheme: Optional[str] = None,
    ):
        super().__init__()
        if port is not None:
            self.port = port
        if host is not None:
            self.host = host
        if httpHeaders is not None:
            self.httpHeaders = httpHeaders
        if path is not None:
            self.path = path
        if scheme is not None:
            self.scheme = scheme


class io__k8s__api__core__v1__ISCSIPersistentVolumeSource(K8STemplatable):
    """ISCSIPersistentVolumeSource represents an ISCSI disk. ISCSI volumes can only be mounted as read/write once. ISCSI volumes support ownership management and SELinux relabeling."""

    props: List[str] = [
        "chapAuthDiscovery",
        "chapAuthSession",
        "fsType",
        "initiatorName",
        "iqn",
        "iscsiInterface",
        "lun",
        "portals",
        "readOnly",
        "secretRef",
        "targetPortal",
    ]
    required_props: List[str] = ["targetPortal", "iqn", "lun"]

    chapAuthDiscovery: Optional[bool] = None
    chapAuthSession: Optional[bool] = None
    fsType: Optional[str] = None
    initiatorName: Optional[str] = None
    iqn: str
    iscsiInterface: Optional[str] = None
    lun: int
    portals: Optional[List[str]] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    targetPortal: str

    def __init__(
        self,
        iqn: str,
        lun: int,
        targetPortal: str,
        chapAuthDiscovery: Optional[bool] = None,
        chapAuthSession: Optional[bool] = None,
        fsType: Optional[str] = None,
        initiatorName: Optional[str] = None,
        iscsiInterface: Optional[str] = None,
        portals: Optional[List[str]] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
    ):
        super().__init__()
        if iqn is not None:
            self.iqn = iqn
        if lun is not None:
            self.lun = lun
        if targetPortal is not None:
            self.targetPortal = targetPortal
        if chapAuthDiscovery is not None:
            self.chapAuthDiscovery = chapAuthDiscovery
        if chapAuthSession is not None:
            self.chapAuthSession = chapAuthSession
        if fsType is not None:
            self.fsType = fsType
        if initiatorName is not None:
            self.initiatorName = initiatorName
        if iscsiInterface is not None:
            self.iscsiInterface = iscsiInterface
        if portals is not None:
            self.portals = portals
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__ISCSIVolumeSource(K8STemplatable):
    """Represents an ISCSI disk. ISCSI volumes can only be mounted as read/write once. ISCSI volumes support ownership management and SELinux relabeling."""

    props: List[str] = [
        "chapAuthDiscovery",
        "chapAuthSession",
        "fsType",
        "initiatorName",
        "iqn",
        "iscsiInterface",
        "lun",
        "portals",
        "readOnly",
        "secretRef",
        "targetPortal",
    ]
    required_props: List[str] = ["targetPortal", "iqn", "lun"]

    chapAuthDiscovery: Optional[bool] = None
    chapAuthSession: Optional[bool] = None
    fsType: Optional[str] = None
    initiatorName: Optional[str] = None
    iqn: str
    iscsiInterface: Optional[str] = None
    lun: int
    portals: Optional[List[str]] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None
    targetPortal: str

    def __init__(
        self,
        iqn: str,
        lun: int,
        targetPortal: str,
        chapAuthDiscovery: Optional[bool] = None,
        chapAuthSession: Optional[bool] = None,
        fsType: Optional[str] = None,
        initiatorName: Optional[str] = None,
        iscsiInterface: Optional[str] = None,
        portals: Optional[List[str]] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__LocalObjectReference] = None,
    ):
        super().__init__()
        if iqn is not None:
            self.iqn = iqn
        if lun is not None:
            self.lun = lun
        if targetPortal is not None:
            self.targetPortal = targetPortal
        if chapAuthDiscovery is not None:
            self.chapAuthDiscovery = chapAuthDiscovery
        if chapAuthSession is not None:
            self.chapAuthSession = chapAuthSession
        if fsType is not None:
            self.fsType = fsType
        if initiatorName is not None:
            self.initiatorName = initiatorName
        if iscsiInterface is not None:
            self.iscsiInterface = iscsiInterface
        if portals is not None:
            self.portals = portals
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef


class io__k8s__api__core__v1__LoadBalancerIngress(K8STemplatable):
    """LoadBalancerIngress represents the status of a load-balancer ingress point: traffic intended for the service should be sent to an ingress point."""

    props: List[str] = ["hostname", "ip", "ports"]
    required_props: List[str] = []

    hostname: Optional[str] = None
    ip: Optional[str] = None
    ports: Optional[List[io__k8s__api__core__v1__PortStatus]] = None

    def __init__(
        self,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        ports: Optional[List[io__k8s__api__core__v1__PortStatus]] = None,
    ):
        super().__init__()
        if hostname is not None:
            self.hostname = hostname
        if ip is not None:
            self.ip = ip
        if ports is not None:
            self.ports = ports


class io__k8s__api__core__v1__LoadBalancerStatus(K8STemplatable):
    """LoadBalancerStatus represents the status of a load-balancer."""

    props: List[str] = ["ingress"]
    required_props: List[str] = []

    ingress: Optional[List[io__k8s__api__core__v1__LoadBalancerIngress]] = None

    def __init__(
        self,
        ingress: Optional[List[io__k8s__api__core__v1__LoadBalancerIngress]] = None,
    ):
        super().__init__()
        if ingress is not None:
            self.ingress = ingress


class io__k8s__api__core__v1__NamespaceCondition(K8STemplatable):
    """NamespaceCondition contains details about state of namespace."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__NamespaceStatus(K8STemplatable):
    """NamespaceStatus is information about the current status of a Namespace."""

    props: List[str] = ["conditions", "phase"]
    required_props: List[str] = []

    conditions: Optional[List[io__k8s__api__core__v1__NamespaceCondition]] = None
    phase: Optional[str] = None

    def __init__(
        self,
        conditions: Optional[List[io__k8s__api__core__v1__NamespaceCondition]] = None,
        phase: Optional[str] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions
        if phase is not None:
            self.phase = phase


class io__k8s__api__core__v1__NodeCondition(K8STemplatable):
    """NodeCondition contains condition information for a node."""

    props: List[str] = [
        "lastHeartbeatTime",
        "lastTransitionTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastHeartbeatTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastHeartbeatTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastHeartbeatTime is not None:
            self.lastHeartbeatTime = lastHeartbeatTime
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__NodeSelector(K8STemplatable):
    """A node selector represents the union of the results of one or more label queries over a set of nodes; that is, it represents the OR of the selectors represented by the node selector terms."""

    props: List[str] = ["nodeSelectorTerms"]
    required_props: List[str] = ["nodeSelectorTerms"]

    nodeSelectorTerms: List[io__k8s__api__core__v1__NodeSelectorTerm]

    def __init__(
        self, nodeSelectorTerms: List[io__k8s__api__core__v1__NodeSelectorTerm]
    ):
        super().__init__()
        if nodeSelectorTerms is not None:
            self.nodeSelectorTerms = nodeSelectorTerms


class io__k8s__api__core__v1__NodeStatus(K8STemplatable):
    """NodeStatus is information about the current status of a node."""

    props: List[str] = [
        "addresses",
        "allocatable",
        "capacity",
        "conditions",
        "config",
        "daemonEndpoints",
        "images",
        "nodeInfo",
        "phase",
        "volumesAttached",
        "volumesInUse",
    ]
    required_props: List[str] = []

    addresses: Optional[List[io__k8s__api__core__v1__NodeAddress]] = None
    allocatable: Any
    capacity: Any
    conditions: Optional[List[io__k8s__api__core__v1__NodeCondition]] = None
    config: Optional[io__k8s__api__core__v1__NodeConfigStatus] = None
    daemonEndpoints: Optional[io__k8s__api__core__v1__NodeDaemonEndpoints] = None
    images: Optional[List[io__k8s__api__core__v1__ContainerImage]] = None
    nodeInfo: Optional[io__k8s__api__core__v1__NodeSystemInfo] = None
    phase: Optional[str] = None
    volumesAttached: Optional[List[io__k8s__api__core__v1__AttachedVolume]] = None
    volumesInUse: Optional[List[str]] = None

    def __init__(
        self,
        addresses: Optional[List[io__k8s__api__core__v1__NodeAddress]] = None,
        allocatable: Any = None,
        capacity: Any = None,
        conditions: Optional[List[io__k8s__api__core__v1__NodeCondition]] = None,
        config: Optional[io__k8s__api__core__v1__NodeConfigStatus] = None,
        daemonEndpoints: Optional[io__k8s__api__core__v1__NodeDaemonEndpoints] = None,
        images: Optional[List[io__k8s__api__core__v1__ContainerImage]] = None,
        nodeInfo: Optional[io__k8s__api__core__v1__NodeSystemInfo] = None,
        phase: Optional[str] = None,
        volumesAttached: Optional[List[io__k8s__api__core__v1__AttachedVolume]] = None,
        volumesInUse: Optional[List[str]] = None,
    ):
        super().__init__()
        if addresses is not None:
            self.addresses = addresses
        if allocatable is not None:
            self.allocatable = allocatable
        if capacity is not None:
            self.capacity = capacity
        if conditions is not None:
            self.conditions = conditions
        if config is not None:
            self.config = config
        if daemonEndpoints is not None:
            self.daemonEndpoints = daemonEndpoints
        if images is not None:
            self.images = images
        if nodeInfo is not None:
            self.nodeInfo = nodeInfo
        if phase is not None:
            self.phase = phase
        if volumesAttached is not None:
            self.volumesAttached = volumesAttached
        if volumesInUse is not None:
            self.volumesInUse = volumesInUse


class io__k8s__api__core__v1__PersistentVolumeClaimCondition(K8STemplatable):
    """PersistentVolumeClaimCondition contails details about state of pvc"""

    props: List[str] = [
        "lastProbeTime",
        "lastTransitionTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastProbeTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastProbeTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastProbeTime is not None:
            self.lastProbeTime = lastProbeTime
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__PersistentVolumeClaimStatus(K8STemplatable):
    """PersistentVolumeClaimStatus is the current status of a persistent volume claim."""

    props: List[str] = [
        "accessModes",
        "allocatedResources",
        "capacity",
        "conditions",
        "phase",
        "resizeStatus",
    ]
    required_props: List[str] = []

    accessModes: Optional[List[str]] = None
    allocatedResources: Any
    capacity: Any
    conditions: Optional[
        List[io__k8s__api__core__v1__PersistentVolumeClaimCondition]
    ] = None
    phase: Optional[str] = None
    resizeStatus: Optional[str] = None

    def __init__(
        self,
        accessModes: Optional[List[str]] = None,
        allocatedResources: Any = None,
        capacity: Any = None,
        conditions: Optional[
            List[io__k8s__api__core__v1__PersistentVolumeClaimCondition]
        ] = None,
        phase: Optional[str] = None,
        resizeStatus: Optional[str] = None,
    ):
        super().__init__()
        if accessModes is not None:
            self.accessModes = accessModes
        if allocatedResources is not None:
            self.allocatedResources = allocatedResources
        if capacity is not None:
            self.capacity = capacity
        if conditions is not None:
            self.conditions = conditions
        if phase is not None:
            self.phase = phase
        if resizeStatus is not None:
            self.resizeStatus = resizeStatus


class io__k8s__api__core__v1__PodCondition(K8STemplatable):
    """PodCondition contains details for the current condition of this pod."""

    props: List[str] = [
        "lastProbeTime",
        "lastTransitionTime",
        "message",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = ["type", "status"]

    lastProbeTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastProbeTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastProbeTime is not None:
            self.lastProbeTime = lastProbeTime
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__PodDNSConfig(K8STemplatable):
    """PodDNSConfig defines the DNS parameters of a pod in addition to those generated from DNSPolicy."""

    props: List[str] = ["nameservers", "options", "searches"]
    required_props: List[str] = []

    nameservers: Optional[List[str]] = None
    options: Optional[List[io__k8s__api__core__v1__PodDNSConfigOption]] = None
    searches: Optional[List[str]] = None

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        options: Optional[List[io__k8s__api__core__v1__PodDNSConfigOption]] = None,
        searches: Optional[List[str]] = None,
    ):
        super().__init__()
        if nameservers is not None:
            self.nameservers = nameservers
        if options is not None:
            self.options = options
        if searches is not None:
            self.searches = searches


class io__k8s__api__core__v1__PodSecurityContext(K8STemplatable):
    """PodSecurityContext holds pod-level security attributes and common container settings. Some fields are also present in container.securityContext.  Field values of container.securityContext take precedence over field values of PodSecurityContext."""

    props: List[str] = [
        "fsGroup",
        "fsGroupChangePolicy",
        "runAsGroup",
        "runAsNonRoot",
        "runAsUser",
        "seLinuxOptions",
        "seccompProfile",
        "supplementalGroups",
        "sysctls",
        "windowsOptions",
    ]
    required_props: List[str] = []

    fsGroup: Optional[int] = None
    fsGroupChangePolicy: Optional[str] = None
    runAsGroup: Optional[int] = None
    runAsNonRoot: Optional[bool] = None
    runAsUser: Optional[int] = None
    seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None
    seccompProfile: Optional[io__k8s__api__core__v1__SeccompProfile] = None
    supplementalGroups: Optional[List[int]] = None
    sysctls: Optional[List[io__k8s__api__core__v1__Sysctl]] = None
    windowsOptions: Optional[
        io__k8s__api__core__v1__WindowsSecurityContextOptions
    ] = None

    def __init__(
        self,
        fsGroup: Optional[int] = None,
        fsGroupChangePolicy: Optional[str] = None,
        runAsGroup: Optional[int] = None,
        runAsNonRoot: Optional[bool] = None,
        runAsUser: Optional[int] = None,
        seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None,
        seccompProfile: Optional[io__k8s__api__core__v1__SeccompProfile] = None,
        supplementalGroups: Optional[List[int]] = None,
        sysctls: Optional[List[io__k8s__api__core__v1__Sysctl]] = None,
        windowsOptions: Optional[
            io__k8s__api__core__v1__WindowsSecurityContextOptions
        ] = None,
    ):
        super().__init__()
        if fsGroup is not None:
            self.fsGroup = fsGroup
        if fsGroupChangePolicy is not None:
            self.fsGroupChangePolicy = fsGroupChangePolicy
        if runAsGroup is not None:
            self.runAsGroup = runAsGroup
        if runAsNonRoot is not None:
            self.runAsNonRoot = runAsNonRoot
        if runAsUser is not None:
            self.runAsUser = runAsUser
        if seLinuxOptions is not None:
            self.seLinuxOptions = seLinuxOptions
        if seccompProfile is not None:
            self.seccompProfile = seccompProfile
        if supplementalGroups is not None:
            self.supplementalGroups = supplementalGroups
        if sysctls is not None:
            self.sysctls = sysctls
        if windowsOptions is not None:
            self.windowsOptions = windowsOptions


class io__k8s__api__core__v1__RBDPersistentVolumeSource(K8STemplatable):
    """Represents a Rados Block Device mount that lasts the lifetime of a pod. RBD volumes support ownership management and SELinux relabeling."""

    props: List[str] = [
        "fsType",
        "image",
        "keyring",
        "monitors",
        "pool",
        "readOnly",
        "secretRef",
        "user",
    ]
    required_props: List[str] = ["monitors", "image"]

    fsType: Optional[str] = None
    image: str
    keyring: Optional[str] = None
    monitors: List[str]
    pool: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None
    user: Optional[str] = None

    def __init__(
        self,
        image: str,
        monitors: List[str],
        fsType: Optional[str] = None,
        keyring: Optional[str] = None,
        pool: Optional[str] = None,
        readOnly: Optional[bool] = None,
        secretRef: Optional[io__k8s__api__core__v1__SecretReference] = None,
        user: Optional[str] = None,
    ):
        super().__init__()
        if image is not None:
            self.image = image
        if monitors is not None:
            self.monitors = monitors
        if fsType is not None:
            self.fsType = fsType
        if keyring is not None:
            self.keyring = keyring
        if pool is not None:
            self.pool = pool
        if readOnly is not None:
            self.readOnly = readOnly
        if secretRef is not None:
            self.secretRef = secretRef
        if user is not None:
            self.user = user


class io__k8s__api__core__v1__ReplicationControllerCondition(K8STemplatable):
    """ReplicationControllerCondition describes the state of a replication controller at a certain point."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = ["type", "status"]

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: str
    type: str

    def __init__(
        self,
        status: str,
        type: str,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__()
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason


class io__k8s__api__core__v1__ReplicationControllerStatus(K8STemplatable):
    """ReplicationControllerStatus represents the current status of a replication controller."""

    props: List[str] = [
        "availableReplicas",
        "conditions",
        "fullyLabeledReplicas",
        "observedGeneration",
        "readyReplicas",
        "replicas",
    ]
    required_props: List[str] = ["replicas"]

    availableReplicas: Optional[int] = None
    conditions: Optional[
        List[io__k8s__api__core__v1__ReplicationControllerCondition]
    ] = None
    fullyLabeledReplicas: Optional[int] = None
    observedGeneration: Optional[int] = None
    readyReplicas: Optional[int] = None
    replicas: int

    def __init__(
        self,
        replicas: int,
        availableReplicas: Optional[int] = None,
        conditions: Optional[
            List[io__k8s__api__core__v1__ReplicationControllerCondition]
        ] = None,
        fullyLabeledReplicas: Optional[int] = None,
        observedGeneration: Optional[int] = None,
        readyReplicas: Optional[int] = None,
    ):
        super().__init__()
        if replicas is not None:
            self.replicas = replicas
        if availableReplicas is not None:
            self.availableReplicas = availableReplicas
        if conditions is not None:
            self.conditions = conditions
        if fullyLabeledReplicas is not None:
            self.fullyLabeledReplicas = fullyLabeledReplicas
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration
        if readyReplicas is not None:
            self.readyReplicas = readyReplicas


class io__k8s__api__core__v1__ResourceFieldSelector(K8STemplatable):
    """ResourceFieldSelector represents container resources (cpu, memory) and their output format"""

    props: List[str] = ["containerName", "divisor", "resource"]
    required_props: List[str] = ["resource"]

    containerName: Optional[str] = None
    divisor: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    resource: str

    def __init__(
        self,
        resource: str,
        containerName: Optional[str] = None,
        divisor: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
    ):
        super().__init__()
        if resource is not None:
            self.resource = resource
        if containerName is not None:
            self.containerName = containerName
        if divisor is not None:
            self.divisor = divisor


class io__k8s__api__core__v1__ScaleIOPersistentVolumeSource(K8STemplatable):
    """ScaleIOPersistentVolumeSource represents a persistent ScaleIO volume"""

    props: List[str] = [
        "fsType",
        "gateway",
        "protectionDomain",
        "readOnly",
        "secretRef",
        "sslEnabled",
        "storageMode",
        "storagePool",
        "system",
        "volumeName",
    ]
    required_props: List[str] = ["gateway", "system", "secretRef"]

    fsType: Optional[str] = None
    gateway: str
    protectionDomain: Optional[str] = None
    readOnly: Optional[bool] = None
    secretRef: io__k8s__api__core__v1__SecretReference
    sslEnabled: Optional[bool] = None
    storageMode: Optional[str] = None
    storagePool: Optional[str] = None
    system: str
    volumeName: Optional[str] = None

    def __init__(
        self,
        gateway: str,
        secretRef: io__k8s__api__core__v1__SecretReference,
        system: str,
        fsType: Optional[str] = None,
        protectionDomain: Optional[str] = None,
        readOnly: Optional[bool] = None,
        sslEnabled: Optional[bool] = None,
        storageMode: Optional[str] = None,
        storagePool: Optional[str] = None,
        volumeName: Optional[str] = None,
    ):
        super().__init__()
        if gateway is not None:
            self.gateway = gateway
        if secretRef is not None:
            self.secretRef = secretRef
        if system is not None:
            self.system = system
        if fsType is not None:
            self.fsType = fsType
        if protectionDomain is not None:
            self.protectionDomain = protectionDomain
        if readOnly is not None:
            self.readOnly = readOnly
        if sslEnabled is not None:
            self.sslEnabled = sslEnabled
        if storageMode is not None:
            self.storageMode = storageMode
        if storagePool is not None:
            self.storagePool = storagePool
        if volumeName is not None:
            self.volumeName = volumeName


class io__k8s__api__core__v1__ScopeSelector(K8STemplatable):
    """A scope selector represents the AND of the selectors represented by the scoped-resource selector requirements."""

    props: List[str] = ["matchExpressions"]
    required_props: List[str] = []

    matchExpressions: Optional[
        List[io__k8s__api__core__v1__ScopedResourceSelectorRequirement]
    ] = None

    def __init__(
        self,
        matchExpressions: Optional[
            List[io__k8s__api__core__v1__ScopedResourceSelectorRequirement]
        ] = None,
    ):
        super().__init__()
        if matchExpressions is not None:
            self.matchExpressions = matchExpressions


class io__k8s__api__core__v1__SecurityContext(K8STemplatable):
    """SecurityContext holds security configuration that will be applied to a container. Some fields are present in both SecurityContext and PodSecurityContext.  When both are set, the values in SecurityContext take precedence."""

    props: List[str] = [
        "allowPrivilegeEscalation",
        "capabilities",
        "privileged",
        "procMount",
        "readOnlyRootFilesystem",
        "runAsGroup",
        "runAsNonRoot",
        "runAsUser",
        "seLinuxOptions",
        "seccompProfile",
        "windowsOptions",
    ]
    required_props: List[str] = []

    allowPrivilegeEscalation: Optional[bool] = None
    capabilities: Optional[io__k8s__api__core__v1__Capabilities] = None
    privileged: Optional[bool] = None
    procMount: Optional[str] = None
    readOnlyRootFilesystem: Optional[bool] = None
    runAsGroup: Optional[int] = None
    runAsNonRoot: Optional[bool] = None
    runAsUser: Optional[int] = None
    seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None
    seccompProfile: Optional[io__k8s__api__core__v1__SeccompProfile] = None
    windowsOptions: Optional[
        io__k8s__api__core__v1__WindowsSecurityContextOptions
    ] = None

    def __init__(
        self,
        allowPrivilegeEscalation: Optional[bool] = None,
        capabilities: Optional[io__k8s__api__core__v1__Capabilities] = None,
        privileged: Optional[bool] = None,
        procMount: Optional[str] = None,
        readOnlyRootFilesystem: Optional[bool] = None,
        runAsGroup: Optional[int] = None,
        runAsNonRoot: Optional[bool] = None,
        runAsUser: Optional[int] = None,
        seLinuxOptions: Optional[io__k8s__api__core__v1__SELinuxOptions] = None,
        seccompProfile: Optional[io__k8s__api__core__v1__SeccompProfile] = None,
        windowsOptions: Optional[
            io__k8s__api__core__v1__WindowsSecurityContextOptions
        ] = None,
    ):
        super().__init__()
        if allowPrivilegeEscalation is not None:
            self.allowPrivilegeEscalation = allowPrivilegeEscalation
        if capabilities is not None:
            self.capabilities = capabilities
        if privileged is not None:
            self.privileged = privileged
        if procMount is not None:
            self.procMount = procMount
        if readOnlyRootFilesystem is not None:
            self.readOnlyRootFilesystem = readOnlyRootFilesystem
        if runAsGroup is not None:
            self.runAsGroup = runAsGroup
        if runAsNonRoot is not None:
            self.runAsNonRoot = runAsNonRoot
        if runAsUser is not None:
            self.runAsUser = runAsUser
        if seLinuxOptions is not None:
            self.seLinuxOptions = seLinuxOptions
        if seccompProfile is not None:
            self.seccompProfile = seccompProfile
        if windowsOptions is not None:
            self.windowsOptions = windowsOptions


class io__k8s__api__core__v1__ServicePort(K8STemplatable):
    """ServicePort contains information on service's port."""

    props: List[str] = [
        "appProtocol",
        "name",
        "nodePort",
        "port",
        "protocol",
        "targetPort",
    ]
    required_props: List[str] = ["port"]

    appProtocol: Optional[str] = None
    name: Optional[str] = None
    nodePort: Optional[int] = None
    port: int
    protocol: Optional[str] = None
    targetPort: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None

    def __init__(
        self,
        port: int,
        appProtocol: Optional[str] = None,
        name: Optional[str] = None,
        nodePort: Optional[int] = None,
        protocol: Optional[str] = None,
        targetPort: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
    ):
        super().__init__()
        if port is not None:
            self.port = port
        if appProtocol is not None:
            self.appProtocol = appProtocol
        if name is not None:
            self.name = name
        if nodePort is not None:
            self.nodePort = nodePort
        if protocol is not None:
            self.protocol = protocol
        if targetPort is not None:
            self.targetPort = targetPort


class io__k8s__api__core__v1__ServiceSpec(K8STemplatable):
    """ServiceSpec describes the attributes that a user creates on a service."""

    props: List[str] = [
        "allocateLoadBalancerNodePorts",
        "clusterIP",
        "clusterIPs",
        "externalIPs",
        "externalName",
        "externalTrafficPolicy",
        "healthCheckNodePort",
        "internalTrafficPolicy",
        "ipFamilies",
        "ipFamilyPolicy",
        "loadBalancerClass",
        "loadBalancerIP",
        "loadBalancerSourceRanges",
        "ports",
        "publishNotReadyAddresses",
        "selector",
        "sessionAffinity",
        "sessionAffinityConfig",
        "type",
    ]
    required_props: List[str] = []

    allocateLoadBalancerNodePorts: Optional[bool] = None
    clusterIP: Optional[str] = None
    clusterIPs: Optional[List[str]] = None
    externalIPs: Optional[List[str]] = None
    externalName: Optional[str] = None
    externalTrafficPolicy: Optional[str] = None
    healthCheckNodePort: Optional[int] = None
    internalTrafficPolicy: Optional[str] = None
    ipFamilies: Optional[List[str]] = None
    ipFamilyPolicy: Optional[str] = None
    loadBalancerClass: Optional[str] = None
    loadBalancerIP: Optional[str] = None
    loadBalancerSourceRanges: Optional[List[str]] = None
    ports: Optional[List[io__k8s__api__core__v1__ServicePort]] = None
    publishNotReadyAddresses: Optional[bool] = None
    selector: Any
    sessionAffinity: Optional[str] = None
    sessionAffinityConfig: Optional[
        io__k8s__api__core__v1__SessionAffinityConfig
    ] = None
    type: Optional[str] = None

    def __init__(
        self,
        allocateLoadBalancerNodePorts: Optional[bool] = None,
        clusterIP: Optional[str] = None,
        clusterIPs: Optional[List[str]] = None,
        externalIPs: Optional[List[str]] = None,
        externalName: Optional[str] = None,
        externalTrafficPolicy: Optional[str] = None,
        healthCheckNodePort: Optional[int] = None,
        internalTrafficPolicy: Optional[str] = None,
        ipFamilies: Optional[List[str]] = None,
        ipFamilyPolicy: Optional[str] = None,
        loadBalancerClass: Optional[str] = None,
        loadBalancerIP: Optional[str] = None,
        loadBalancerSourceRanges: Optional[List[str]] = None,
        ports: Optional[List[io__k8s__api__core__v1__ServicePort]] = None,
        publishNotReadyAddresses: Optional[bool] = None,
        selector: Any = None,
        sessionAffinity: Optional[str] = None,
        sessionAffinityConfig: Optional[
            io__k8s__api__core__v1__SessionAffinityConfig
        ] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if allocateLoadBalancerNodePorts is not None:
            self.allocateLoadBalancerNodePorts = allocateLoadBalancerNodePorts
        if clusterIP is not None:
            self.clusterIP = clusterIP
        if clusterIPs is not None:
            self.clusterIPs = clusterIPs
        if externalIPs is not None:
            self.externalIPs = externalIPs
        if externalName is not None:
            self.externalName = externalName
        if externalTrafficPolicy is not None:
            self.externalTrafficPolicy = externalTrafficPolicy
        if healthCheckNodePort is not None:
            self.healthCheckNodePort = healthCheckNodePort
        if internalTrafficPolicy is not None:
            self.internalTrafficPolicy = internalTrafficPolicy
        if ipFamilies is not None:
            self.ipFamilies = ipFamilies
        if ipFamilyPolicy is not None:
            self.ipFamilyPolicy = ipFamilyPolicy
        if loadBalancerClass is not None:
            self.loadBalancerClass = loadBalancerClass
        if loadBalancerIP is not None:
            self.loadBalancerIP = loadBalancerIP
        if loadBalancerSourceRanges is not None:
            self.loadBalancerSourceRanges = loadBalancerSourceRanges
        if ports is not None:
            self.ports = ports
        if publishNotReadyAddresses is not None:
            self.publishNotReadyAddresses = publishNotReadyAddresses
        if selector is not None:
            self.selector = selector
        if sessionAffinity is not None:
            self.sessionAffinity = sessionAffinity
        if sessionAffinityConfig is not None:
            self.sessionAffinityConfig = sessionAffinityConfig
        if type is not None:
            self.type = type


class io__k8s__api__core__v1__TCPSocketAction(K8STemplatable):
    """TCPSocketAction describes an action based on opening a socket"""

    props: List[str] = ["host", "port"]
    required_props: List[str] = ["port"]

    host: Optional[str] = None
    port: io__k8s__apimachinery__pkg__util__intstr__IntOrString

    def __init__(
        self,
        port: io__k8s__apimachinery__pkg__util__intstr__IntOrString,
        host: Optional[str] = None,
    ):
        super().__init__()
        if port is not None:
            self.port = port
        if host is not None:
            self.host = host


class io__k8s__api__core__v1__Taint(K8STemplatable):
    """The node this Taint is attached to has the "effect" on any pod that does not tolerate the Taint."""

    props: List[str] = ["effect", "key", "timeAdded", "value"]
    required_props: List[str] = ["key", "effect"]

    effect: str
    key: str
    timeAdded: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    value: Optional[str] = None

    def __init__(
        self,
        effect: str,
        key: str,
        timeAdded: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
        value: Optional[str] = None,
    ):
        super().__init__()
        if effect is not None:
            self.effect = effect
        if key is not None:
            self.key = key
        if timeAdded is not None:
            self.timeAdded = timeAdded
        if value is not None:
            self.value = value


class io__k8s__api__core__v1__VolumeNodeAffinity(K8STemplatable):
    """VolumeNodeAffinity defines constraints that limit what nodes this volume can be accessed from."""

    props: List[str] = ["required"]
    required_props: List[str] = []

    required: Optional[io__k8s__api__core__v1__NodeSelector] = None

    def __init__(self, required: Optional[io__k8s__api__core__v1__NodeSelector] = None):
        super().__init__()
        if required is not None:
            self.required = required


class io__k8s__api__discovery__v1__EndpointHints(K8STemplatable):
    """EndpointHints provides hints describing how an endpoint should be consumed."""

    props: List[str] = ["forZones"]
    required_props: List[str] = []

    forZones: Optional[List[io__k8s__api__discovery__v1__ForZone]] = None

    def __init__(
        self, forZones: Optional[List[io__k8s__api__discovery__v1__ForZone]] = None
    ):
        super().__init__()
        if forZones is not None:
            self.forZones = forZones


class io__k8s__api__discovery__v1beta1__EndpointHints(K8STemplatable):
    """EndpointHints provides hints describing how an endpoint should be consumed."""

    props: List[str] = ["forZones"]
    required_props: List[str] = []

    forZones: Optional[List[io__k8s__api__discovery__v1beta1__ForZone]] = None

    def __init__(
        self, forZones: Optional[List[io__k8s__api__discovery__v1beta1__ForZone]] = None
    ):
        super().__init__()
        if forZones is not None:
            self.forZones = forZones


class io__k8s__api__events__v1__EventSeries(K8STemplatable):
    """EventSeries contain information on series of events, i.e. thing that was/is happening continuously for some time. How often to update the EventSeries is up to the event reporters. The default event reporter in "k8s.io/client-go/tools/events/event_broadcaster.go" shows how this struct is updated on heartbeats and can guide customized reporter implementations."""

    props: List[str] = ["count", "lastObservedTime"]
    required_props: List[str] = ["count", "lastObservedTime"]

    count: int
    lastObservedTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime

    def __init__(
        self,
        count: int,
        lastObservedTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime,
    ):
        super().__init__()
        if count is not None:
            self.count = count
        if lastObservedTime is not None:
            self.lastObservedTime = lastObservedTime


class io__k8s__api__events__v1beta1__EventSeries(K8STemplatable):
    """EventSeries contain information on series of events, i.e. thing that was/is happening continuously for some time."""

    props: List[str] = ["count", "lastObservedTime"]
    required_props: List[str] = ["count", "lastObservedTime"]

    count: int
    lastObservedTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime

    def __init__(
        self,
        count: int,
        lastObservedTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime,
    ):
        super().__init__()
        if count is not None:
            self.count = count
        if lastObservedTime is not None:
            self.lastObservedTime = lastObservedTime


class io__k8s__api__flowcontrol__v1beta1__FlowSchemaCondition(K8STemplatable):
    """FlowSchemaCondition describes conditions for a FlowSchema."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = []

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None

    def __init__(
        self,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta1__FlowSchemaStatus(K8STemplatable):
    """FlowSchemaStatus represents the current state of a FlowSchema."""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__api__flowcontrol__v1beta1__FlowSchemaCondition]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[io__k8s__api__flowcontrol__v1beta1__FlowSchemaCondition]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__flowcontrol__v1beta1__LimitResponse(K8STemplatable):
    """LimitResponse defines how to handle requests that can not be executed right now."""

    props: List[str] = ["queuing", "type"]
    required_props: List[str] = ["type"]

    queuing: Optional[io__k8s__api__flowcontrol__v1beta1__QueuingConfiguration] = None
    type: str

    def __init__(
        self,
        type: str,
        queuing: Optional[
            io__k8s__api__flowcontrol__v1beta1__QueuingConfiguration
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if queuing is not None:
            self.queuing = queuing


class io__k8s__api__flowcontrol__v1beta1__LimitedPriorityLevelConfiguration(
    K8STemplatable
):
    """LimitedPriorityLevelConfiguration specifies how to handle requests that are subject to limits. It addresses two issues:
    * How are requests for this priority level limited?
    * What should be done with requests that exceed the limit?"""

    props: List[str] = ["assuredConcurrencyShares", "limitResponse"]
    required_props: List[str] = []

    assuredConcurrencyShares: Optional[int] = None
    limitResponse: Optional[io__k8s__api__flowcontrol__v1beta1__LimitResponse] = None

    def __init__(
        self,
        assuredConcurrencyShares: Optional[int] = None,
        limitResponse: Optional[
            io__k8s__api__flowcontrol__v1beta1__LimitResponse
        ] = None,
    ):
        super().__init__()
        if assuredConcurrencyShares is not None:
            self.assuredConcurrencyShares = assuredConcurrencyShares
        if limitResponse is not None:
            self.limitResponse = limitResponse


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationCondition(
    K8STemplatable
):
    """PriorityLevelConfigurationCondition defines the condition of priority level."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = []

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None

    def __init__(
        self,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationSpec(
    K8STemplatable
):
    """PriorityLevelConfigurationSpec specifies the configuration of a priority level."""

    props: List[str] = ["limited", "type"]
    required_props: List[str] = ["type"]

    limited: Optional[
        io__k8s__api__flowcontrol__v1beta1__LimitedPriorityLevelConfiguration
    ] = None
    type: str

    def __init__(
        self,
        type: str,
        limited: Optional[
            io__k8s__api__flowcontrol__v1beta1__LimitedPriorityLevelConfiguration
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if limited is not None:
            self.limited = limited


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationStatus(
    K8STemplatable
):
    """PriorityLevelConfigurationStatus represents the current state of a "request-priority"."""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationCondition]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[
                io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationCondition
            ]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__flowcontrol__v1beta1__Subject(K8STemplatable):
    """Subject matches the originator of a request, as identified by the request authentication system. There are three ways of matching an originator; by user, group, or service account."""

    props: List[str] = ["group", "kind", "serviceAccount", "user"]
    required_props: List[str] = ["kind"]

    group: Optional[io__k8s__api__flowcontrol__v1beta1__GroupSubject] = None
    kind: str
    serviceAccount: Optional[
        io__k8s__api__flowcontrol__v1beta1__ServiceAccountSubject
    ] = None
    user: Optional[io__k8s__api__flowcontrol__v1beta1__UserSubject] = None

    def __init__(
        self,
        kind: str,
        group: Optional[io__k8s__api__flowcontrol__v1beta1__GroupSubject] = None,
        serviceAccount: Optional[
            io__k8s__api__flowcontrol__v1beta1__ServiceAccountSubject
        ] = None,
        user: Optional[io__k8s__api__flowcontrol__v1beta1__UserSubject] = None,
    ):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if group is not None:
            self.group = group
        if serviceAccount is not None:
            self.serviceAccount = serviceAccount
        if user is not None:
            self.user = user


class io__k8s__api__flowcontrol__v1beta2__FlowSchemaCondition(K8STemplatable):
    """FlowSchemaCondition describes conditions for a FlowSchema."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = []

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None

    def __init__(
        self,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta2__FlowSchemaStatus(K8STemplatable):
    """FlowSchemaStatus represents the current state of a FlowSchema."""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__api__flowcontrol__v1beta2__FlowSchemaCondition]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[io__k8s__api__flowcontrol__v1beta2__FlowSchemaCondition]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__flowcontrol__v1beta2__LimitResponse(K8STemplatable):
    """LimitResponse defines how to handle requests that can not be executed right now."""

    props: List[str] = ["queuing", "type"]
    required_props: List[str] = ["type"]

    queuing: Optional[io__k8s__api__flowcontrol__v1beta2__QueuingConfiguration] = None
    type: str

    def __init__(
        self,
        type: str,
        queuing: Optional[
            io__k8s__api__flowcontrol__v1beta2__QueuingConfiguration
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if queuing is not None:
            self.queuing = queuing


class io__k8s__api__flowcontrol__v1beta2__LimitedPriorityLevelConfiguration(
    K8STemplatable
):
    """LimitedPriorityLevelConfiguration specifies how to handle requests that are subject to limits. It addresses two issues:
    * How are requests for this priority level limited?
    * What should be done with requests that exceed the limit?"""

    props: List[str] = ["assuredConcurrencyShares", "limitResponse"]
    required_props: List[str] = []

    assuredConcurrencyShares: Optional[int] = None
    limitResponse: Optional[io__k8s__api__flowcontrol__v1beta2__LimitResponse] = None

    def __init__(
        self,
        assuredConcurrencyShares: Optional[int] = None,
        limitResponse: Optional[
            io__k8s__api__flowcontrol__v1beta2__LimitResponse
        ] = None,
    ):
        super().__init__()
        if assuredConcurrencyShares is not None:
            self.assuredConcurrencyShares = assuredConcurrencyShares
        if limitResponse is not None:
            self.limitResponse = limitResponse


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationCondition(
    K8STemplatable
):
    """PriorityLevelConfigurationCondition defines the condition of priority level."""

    props: List[str] = ["lastTransitionTime", "message", "reason", "status", "type"]
    required_props: List[str] = []

    lastTransitionTime: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    message: Optional[str] = None
    reason: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None

    def __init__(
        self,
        lastTransitionTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationSpec(
    K8STemplatable
):
    """PriorityLevelConfigurationSpec specifies the configuration of a priority level."""

    props: List[str] = ["limited", "type"]
    required_props: List[str] = ["type"]

    limited: Optional[
        io__k8s__api__flowcontrol__v1beta2__LimitedPriorityLevelConfiguration
    ] = None
    type: str

    def __init__(
        self,
        type: str,
        limited: Optional[
            io__k8s__api__flowcontrol__v1beta2__LimitedPriorityLevelConfiguration
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if limited is not None:
            self.limited = limited


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationStatus(
    K8STemplatable
):
    """PriorityLevelConfigurationStatus represents the current state of a "request-priority"."""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationCondition]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[
                io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationCondition
            ]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__flowcontrol__v1beta2__Subject(K8STemplatable):
    """Subject matches the originator of a request, as identified by the request authentication system. There are three ways of matching an originator; by user, group, or service account."""

    props: List[str] = ["group", "kind", "serviceAccount", "user"]
    required_props: List[str] = ["kind"]

    group: Optional[io__k8s__api__flowcontrol__v1beta2__GroupSubject] = None
    kind: str
    serviceAccount: Optional[
        io__k8s__api__flowcontrol__v1beta2__ServiceAccountSubject
    ] = None
    user: Optional[io__k8s__api__flowcontrol__v1beta2__UserSubject] = None

    def __init__(
        self,
        kind: str,
        group: Optional[io__k8s__api__flowcontrol__v1beta2__GroupSubject] = None,
        serviceAccount: Optional[
            io__k8s__api__flowcontrol__v1beta2__ServiceAccountSubject
        ] = None,
        user: Optional[io__k8s__api__flowcontrol__v1beta2__UserSubject] = None,
    ):
        super().__init__()
        if kind is not None:
            self.kind = kind
        if group is not None:
            self.group = group
        if serviceAccount is not None:
            self.serviceAccount = serviceAccount
        if user is not None:
            self.user = user


class io__k8s__api__networking__v1__IngressServiceBackend(K8STemplatable):
    """IngressServiceBackend references a Kubernetes Service as a Backend."""

    props: List[str] = ["name", "port"]
    required_props: List[str] = ["name"]

    name: str
    port: Optional[io__k8s__api__networking__v1__ServiceBackendPort] = None

    def __init__(
        self,
        name: str,
        port: Optional[io__k8s__api__networking__v1__ServiceBackendPort] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if port is not None:
            self.port = port


class io__k8s__api__networking__v1__IngressStatus(K8STemplatable):
    """IngressStatus describe the current state of the Ingress."""

    props: List[str] = ["loadBalancer"]
    required_props: List[str] = []

    loadBalancer: Optional[io__k8s__api__core__v1__LoadBalancerStatus] = None

    def __init__(
        self, loadBalancer: Optional[io__k8s__api__core__v1__LoadBalancerStatus] = None
    ):
        super().__init__()
        if loadBalancer is not None:
            self.loadBalancer = loadBalancer


class io__k8s__api__networking__v1__NetworkPolicyPort(K8STemplatable):
    """NetworkPolicyPort describes a port to allow traffic on"""

    props: List[str] = ["endPort", "port", "protocol"]
    required_props: List[str] = []

    endPort: Optional[int] = None
    port: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None
    protocol: Optional[str] = None

    def __init__(
        self,
        endPort: Optional[int] = None,
        port: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None,
        protocol: Optional[str] = None,
    ):
        super().__init__()
        if endPort is not None:
            self.endPort = endPort
        if port is not None:
            self.port = port
        if protocol is not None:
            self.protocol = protocol


class io__k8s__api__policy__v1beta1__FSGroupStrategyOptions(K8STemplatable):
    """FSGroupStrategyOptions defines the strategy type and options used to create the strategy."""

    props: List[str] = ["ranges", "rule"]
    required_props: List[str] = []

    ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None
    rule: Optional[str] = None

    def __init__(
        self,
        ranges: Optional[List[io__k8s__api__policy__v1beta1__IDRange]] = None,
        rule: Optional[str] = None,
    ):
        super().__init__()
        if ranges is not None:
            self.ranges = ranges
        if rule is not None:
            self.rule = rule


class io__k8s__api__policy__v1beta1__PodSecurityPolicySpec(K8STemplatable):
    """PodSecurityPolicySpec defines the policy enforced."""

    props: List[str] = [
        "allowPrivilegeEscalation",
        "allowedCSIDrivers",
        "allowedCapabilities",
        "allowedFlexVolumes",
        "allowedHostPaths",
        "allowedProcMountTypes",
        "allowedUnsafeSysctls",
        "defaultAddCapabilities",
        "defaultAllowPrivilegeEscalation",
        "forbiddenSysctls",
        "fsGroup",
        "hostIPC",
        "hostNetwork",
        "hostPID",
        "hostPorts",
        "privileged",
        "readOnlyRootFilesystem",
        "requiredDropCapabilities",
        "runAsGroup",
        "runAsUser",
        "runtimeClass",
        "seLinux",
        "supplementalGroups",
        "volumes",
    ]
    required_props: List[str] = [
        "seLinux",
        "runAsUser",
        "supplementalGroups",
        "fsGroup",
    ]

    allowPrivilegeEscalation: Optional[bool] = None
    allowedCSIDrivers: Optional[
        List[io__k8s__api__policy__v1beta1__AllowedCSIDriver]
    ] = None
    allowedCapabilities: Optional[List[str]] = None
    allowedFlexVolumes: Optional[
        List[io__k8s__api__policy__v1beta1__AllowedFlexVolume]
    ] = None
    allowedHostPaths: Optional[
        List[io__k8s__api__policy__v1beta1__AllowedHostPath]
    ] = None
    allowedProcMountTypes: Optional[List[str]] = None
    allowedUnsafeSysctls: Optional[List[str]] = None
    defaultAddCapabilities: Optional[List[str]] = None
    defaultAllowPrivilegeEscalation: Optional[bool] = None
    forbiddenSysctls: Optional[List[str]] = None
    fsGroup: io__k8s__api__policy__v1beta1__FSGroupStrategyOptions
    hostIPC: Optional[bool] = None
    hostNetwork: Optional[bool] = None
    hostPID: Optional[bool] = None
    hostPorts: Optional[List[io__k8s__api__policy__v1beta1__HostPortRange]] = None
    privileged: Optional[bool] = None
    readOnlyRootFilesystem: Optional[bool] = None
    requiredDropCapabilities: Optional[List[str]] = None
    runAsGroup: Optional[
        io__k8s__api__policy__v1beta1__RunAsGroupStrategyOptions
    ] = None
    runAsUser: io__k8s__api__policy__v1beta1__RunAsUserStrategyOptions
    runtimeClass: Optional[
        io__k8s__api__policy__v1beta1__RuntimeClassStrategyOptions
    ] = None
    seLinux: io__k8s__api__policy__v1beta1__SELinuxStrategyOptions
    supplementalGroups: io__k8s__api__policy__v1beta1__SupplementalGroupsStrategyOptions
    volumes: Optional[List[str]] = None

    def __init__(
        self,
        fsGroup: io__k8s__api__policy__v1beta1__FSGroupStrategyOptions,
        runAsUser: io__k8s__api__policy__v1beta1__RunAsUserStrategyOptions,
        seLinux: io__k8s__api__policy__v1beta1__SELinuxStrategyOptions,
        supplementalGroups: io__k8s__api__policy__v1beta1__SupplementalGroupsStrategyOptions,
        allowPrivilegeEscalation: Optional[bool] = None,
        allowedCSIDrivers: Optional[
            List[io__k8s__api__policy__v1beta1__AllowedCSIDriver]
        ] = None,
        allowedCapabilities: Optional[List[str]] = None,
        allowedFlexVolumes: Optional[
            List[io__k8s__api__policy__v1beta1__AllowedFlexVolume]
        ] = None,
        allowedHostPaths: Optional[
            List[io__k8s__api__policy__v1beta1__AllowedHostPath]
        ] = None,
        allowedProcMountTypes: Optional[List[str]] = None,
        allowedUnsafeSysctls: Optional[List[str]] = None,
        defaultAddCapabilities: Optional[List[str]] = None,
        defaultAllowPrivilegeEscalation: Optional[bool] = None,
        forbiddenSysctls: Optional[List[str]] = None,
        hostIPC: Optional[bool] = None,
        hostNetwork: Optional[bool] = None,
        hostPID: Optional[bool] = None,
        hostPorts: Optional[List[io__k8s__api__policy__v1beta1__HostPortRange]] = None,
        privileged: Optional[bool] = None,
        readOnlyRootFilesystem: Optional[bool] = None,
        requiredDropCapabilities: Optional[List[str]] = None,
        runAsGroup: Optional[
            io__k8s__api__policy__v1beta1__RunAsGroupStrategyOptions
        ] = None,
        runtimeClass: Optional[
            io__k8s__api__policy__v1beta1__RuntimeClassStrategyOptions
        ] = None,
        volumes: Optional[List[str]] = None,
    ):
        super().__init__()
        if fsGroup is not None:
            self.fsGroup = fsGroup
        if runAsUser is not None:
            self.runAsUser = runAsUser
        if seLinux is not None:
            self.seLinux = seLinux
        if supplementalGroups is not None:
            self.supplementalGroups = supplementalGroups
        if allowPrivilegeEscalation is not None:
            self.allowPrivilegeEscalation = allowPrivilegeEscalation
        if allowedCSIDrivers is not None:
            self.allowedCSIDrivers = allowedCSIDrivers
        if allowedCapabilities is not None:
            self.allowedCapabilities = allowedCapabilities
        if allowedFlexVolumes is not None:
            self.allowedFlexVolumes = allowedFlexVolumes
        if allowedHostPaths is not None:
            self.allowedHostPaths = allowedHostPaths
        if allowedProcMountTypes is not None:
            self.allowedProcMountTypes = allowedProcMountTypes
        if allowedUnsafeSysctls is not None:
            self.allowedUnsafeSysctls = allowedUnsafeSysctls
        if defaultAddCapabilities is not None:
            self.defaultAddCapabilities = defaultAddCapabilities
        if defaultAllowPrivilegeEscalation is not None:
            self.defaultAllowPrivilegeEscalation = defaultAllowPrivilegeEscalation
        if forbiddenSysctls is not None:
            self.forbiddenSysctls = forbiddenSysctls
        if hostIPC is not None:
            self.hostIPC = hostIPC
        if hostNetwork is not None:
            self.hostNetwork = hostNetwork
        if hostPID is not None:
            self.hostPID = hostPID
        if hostPorts is not None:
            self.hostPorts = hostPorts
        if privileged is not None:
            self.privileged = privileged
        if readOnlyRootFilesystem is not None:
            self.readOnlyRootFilesystem = readOnlyRootFilesystem
        if requiredDropCapabilities is not None:
            self.requiredDropCapabilities = requiredDropCapabilities
        if runAsGroup is not None:
            self.runAsGroup = runAsGroup
        if runtimeClass is not None:
            self.runtimeClass = runtimeClass
        if volumes is not None:
            self.volumes = volumes


class io__k8s__api__storage__v1__CSIDriverSpec(K8STemplatable):
    """CSIDriverSpec is the specification of a CSIDriver."""

    props: List[str] = [
        "attachRequired",
        "fsGroupPolicy",
        "podInfoOnMount",
        "requiresRepublish",
        "storageCapacity",
        "tokenRequests",
        "volumeLifecycleModes",
    ]
    required_props: List[str] = []

    attachRequired: Optional[bool] = None
    fsGroupPolicy: Optional[str] = None
    podInfoOnMount: Optional[bool] = None
    requiresRepublish: Optional[bool] = None
    storageCapacity: Optional[bool] = None
    tokenRequests: Optional[List[io__k8s__api__storage__v1__TokenRequest]] = None
    volumeLifecycleModes: Optional[List[str]] = None

    def __init__(
        self,
        attachRequired: Optional[bool] = None,
        fsGroupPolicy: Optional[str] = None,
        podInfoOnMount: Optional[bool] = None,
        requiresRepublish: Optional[bool] = None,
        storageCapacity: Optional[bool] = None,
        tokenRequests: Optional[List[io__k8s__api__storage__v1__TokenRequest]] = None,
        volumeLifecycleModes: Optional[List[str]] = None,
    ):
        super().__init__()
        if attachRequired is not None:
            self.attachRequired = attachRequired
        if fsGroupPolicy is not None:
            self.fsGroupPolicy = fsGroupPolicy
        if podInfoOnMount is not None:
            self.podInfoOnMount = podInfoOnMount
        if requiresRepublish is not None:
            self.requiresRepublish = requiresRepublish
        if storageCapacity is not None:
            self.storageCapacity = storageCapacity
        if tokenRequests is not None:
            self.tokenRequests = tokenRequests
        if volumeLifecycleModes is not None:
            self.volumeLifecycleModes = volumeLifecycleModes


class io__k8s__api__storage__v1__CSINodeDriver(K8STemplatable):
    """CSINodeDriver holds information about the specification of one CSI driver installed on a node"""

    props: List[str] = ["allocatable", "name", "nodeID", "topologyKeys"]
    required_props: List[str] = ["name", "nodeID"]

    allocatable: Optional[io__k8s__api__storage__v1__VolumeNodeResources] = None
    name: str
    nodeID: str
    topologyKeys: Optional[List[str]] = None

    def __init__(
        self,
        name: str,
        nodeID: str,
        allocatable: Optional[io__k8s__api__storage__v1__VolumeNodeResources] = None,
        topologyKeys: Optional[List[str]] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if nodeID is not None:
            self.nodeID = nodeID
        if allocatable is not None:
            self.allocatable = allocatable
        if topologyKeys is not None:
            self.topologyKeys = topologyKeys


class io__k8s__api__storage__v1__CSINodeSpec(K8STemplatable):
    """CSINodeSpec holds information about the specification of all CSI drivers installed on a node"""

    props: List[str] = ["drivers"]
    required_props: List[str] = ["drivers"]

    drivers: List[io__k8s__api__storage__v1__CSINodeDriver]

    def __init__(self, drivers: List[io__k8s__api__storage__v1__CSINodeDriver]):
        super().__init__()
        if drivers is not None:
            self.drivers = drivers


class io__k8s__api__storage__v1__VolumeError(K8STemplatable):
    """VolumeError captures an error encountered during a volume operation."""

    props: List[str] = ["message", "time"]
    required_props: List[str] = []

    message: Optional[str] = None
    time: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None

    def __init__(
        self,
        message: Optional[str] = None,
        time: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
    ):
        super().__init__()
        if message is not None:
            self.message = message
        if time is not None:
            self.time = time


class io__k8s__apimachinery__pkg__apis__meta__v1__APIGroup(K8STemplatable):
    """APIGroup contains the name, the supported versions, and the preferred version of a group."""

    apiVersion: str = "v1"
    kind: str = "APIGroup"

    props: List[str] = [
        "apiVersion",
        "kind",
        "name",
        "preferredVersion",
        "serverAddressByClientCIDRs",
        "versions",
    ]
    required_props: List[str] = ["name", "versions"]

    name: str
    preferredVersion: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery
    ] = None
    serverAddressByClientCIDRs: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR]
    ] = None
    versions: List[io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery]

    def __init__(
        self,
        name: str,
        versions: List[
            io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery
        ],
        preferredVersion: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery
        ] = None,
        serverAddressByClientCIDRs: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR]
        ] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if versions is not None:
            self.versions = versions
        if preferredVersion is not None:
            self.preferredVersion = preferredVersion
        if serverAddressByClientCIDRs is not None:
            self.serverAddressByClientCIDRs = serverAddressByClientCIDRs


class io__k8s__apimachinery__pkg__apis__meta__v1__APIGroupList(K8STemplatable):
    """APIGroupList is a list of APIGroup, to allow clients to discover the API at /apis."""

    apiVersion: str = "v1"
    kind: str = "APIGroupList"

    props: List[str] = ["apiVersion", "groups", "kind"]
    required_props: List[str] = ["groups"]

    groups: List[io__k8s__apimachinery__pkg__apis__meta__v1__APIGroup]

    def __init__(
        self, groups: List[io__k8s__apimachinery__pkg__apis__meta__v1__APIGroup]
    ):
        super().__init__()
        if groups is not None:
            self.groups = groups


class io__k8s__apimachinery__pkg__apis__meta__v1__APIVersions(K8STemplatable):
    """APIVersions lists the versions that are available, to allow clients to discover the API at /api, which is the root path of the legacy v1 API."""

    apiVersion: str = "v1"
    kind: str = "APIVersions"

    props: List[str] = ["apiVersion", "kind", "serverAddressByClientCIDRs", "versions"]
    required_props: List[str] = ["versions", "serverAddressByClientCIDRs"]

    serverAddressByClientCIDRs: List[
        io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR
    ]
    versions: List[str]

    def __init__(
        self,
        serverAddressByClientCIDRs: List[
            io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR
        ],
        versions: List[str],
    ):
        super().__init__()
        if serverAddressByClientCIDRs is not None:
            self.serverAddressByClientCIDRs = serverAddressByClientCIDRs
        if versions is not None:
            self.versions = versions


class io__k8s__apimachinery__pkg__apis__meta__v1__Condition(K8STemplatable):
    """Condition contains details for one aspect of the current state of this API Resource."""

    props: List[str] = [
        "lastTransitionTime",
        "message",
        "observedGeneration",
        "reason",
        "status",
        "type",
    ]
    required_props: List[str] = [
        "type",
        "status",
        "lastTransitionTime",
        "reason",
        "message",
    ]

    lastTransitionTime: io__k8s__apimachinery__pkg__apis__meta__v1__Time
    message: str
    observedGeneration: Optional[int] = None
    reason: str
    status: str
    type: str

    def __init__(
        self,
        lastTransitionTime: io__k8s__apimachinery__pkg__apis__meta__v1__Time,
        message: str,
        reason: str,
        status: str,
        type: str,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if lastTransitionTime is not None:
            self.lastTransitionTime = lastTransitionTime
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status
        if type is not None:
            self.type = type
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__apimachinery__pkg__apis__meta__v1__DeleteOptions(K8STemplatable):
    """DeleteOptions may be provided when deleting an API object."""

    apiVersion: str = "v1"
    kind: str = "DeleteOptions"

    props: List[str] = [
        "apiVersion",
        "dryRun",
        "gracePeriodSeconds",
        "kind",
        "orphanDependents",
        "preconditions",
        "propagationPolicy",
    ]
    required_props: List[str] = []

    dryRun: Optional[List[str]] = None
    gracePeriodSeconds: Optional[int] = None
    orphanDependents: Optional[bool] = None
    preconditions: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Preconditions
    ] = None
    propagationPolicy: Optional[str] = None

    def __init__(
        self,
        dryRun: Optional[List[str]] = None,
        gracePeriodSeconds: Optional[int] = None,
        orphanDependents: Optional[bool] = None,
        preconditions: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Preconditions
        ] = None,
        propagationPolicy: Optional[str] = None,
    ):
        super().__init__()
        if dryRun is not None:
            self.dryRun = dryRun
        if gracePeriodSeconds is not None:
            self.gracePeriodSeconds = gracePeriodSeconds
        if orphanDependents is not None:
            self.orphanDependents = orphanDependents
        if preconditions is not None:
            self.preconditions = preconditions
        if propagationPolicy is not None:
            self.propagationPolicy = propagationPolicy


class io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector(K8STemplatable):
    """A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects."""

    props: List[str] = ["matchExpressions", "matchLabels"]
    required_props: List[str] = []

    matchExpressions: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelectorRequirement]
    ] = None
    matchLabels: Any

    def __init__(
        self,
        matchExpressions: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelectorRequirement]
        ] = None,
        matchLabels: Any = None,
    ):
        super().__init__()
        if matchExpressions is not None:
            self.matchExpressions = matchExpressions
        if matchLabels is not None:
            self.matchLabels = matchLabels


class io__k8s__apimachinery__pkg__apis__meta__v1__ManagedFieldsEntry(K8STemplatable):
    """ManagedFieldsEntry is a workflow-id, a FieldSet and the group version of the resource that the fieldset applies to."""

    props: List[str] = [
        "apiVersion",
        "fieldsType",
        "fieldsV1",
        "manager",
        "operation",
        "subresource",
        "time",
    ]
    required_props: List[str] = []

    apiVersion: Optional[str] = None
    fieldsType: Optional[str] = None
    fieldsV1: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__FieldsV1] = None
    manager: Optional[str] = None
    operation: Optional[str] = None
    subresource: Optional[str] = None
    time: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None

    def __init__(
        self,
        apiVersion: Optional[str] = None,
        fieldsType: Optional[str] = None,
        fieldsV1: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__FieldsV1] = None,
        manager: Optional[str] = None,
        operation: Optional[str] = None,
        subresource: Optional[str] = None,
        time: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
    ):
        super().__init__()
        if apiVersion is not None:
            self.apiVersion = apiVersion
        if fieldsType is not None:
            self.fieldsType = fieldsType
        if fieldsV1 is not None:
            self.fieldsV1 = fieldsV1
        if manager is not None:
            self.manager = manager
        if operation is not None:
            self.operation = operation
        if subresource is not None:
            self.subresource = subresource
        if time is not None:
            self.time = time


class io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta(K8STemplatable):
    """ObjectMeta is metadata that all persisted resources must have, which includes all objects users must create."""

    props: List[str] = [
        "annotations",
        "clusterName",
        "creationTimestamp",
        "deletionGracePeriodSeconds",
        "deletionTimestamp",
        "finalizers",
        "generateName",
        "generation",
        "labels",
        "managedFields",
        "name",
        "namespace",
        "ownerReferences",
        "resourceVersion",
        "selfLink",
        "uid",
    ]
    required_props: List[str] = []

    annotations: Any
    clusterName: Optional[str] = None
    creationTimestamp: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    deletionGracePeriodSeconds: Optional[int] = None
    deletionTimestamp: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    finalizers: Optional[List[str]] = None
    generateName: Optional[str] = None
    generation: Optional[int] = None
    labels: Any
    managedFields: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__ManagedFieldsEntry]
    ] = None
    name: Optional[str] = None
    namespace: Optional[str] = None
    ownerReferences: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__OwnerReference]
    ] = None
    resourceVersion: Optional[str] = None
    selfLink: Optional[str] = None
    uid: Optional[str] = None

    def __init__(
        self,
        annotations: Any = None,
        clusterName: Optional[str] = None,
        creationTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        deletionGracePeriodSeconds: Optional[int] = None,
        deletionTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        finalizers: Optional[List[str]] = None,
        generateName: Optional[str] = None,
        generation: Optional[int] = None,
        labels: Any = None,
        managedFields: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__ManagedFieldsEntry]
        ] = None,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        ownerReferences: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__OwnerReference]
        ] = None,
        resourceVersion: Optional[str] = None,
        selfLink: Optional[str] = None,
        uid: Optional[str] = None,
    ):
        super().__init__()
        if annotations is not None:
            self.annotations = annotations
        if clusterName is not None:
            self.clusterName = clusterName
        if creationTimestamp is not None:
            self.creationTimestamp = creationTimestamp
        if deletionGracePeriodSeconds is not None:
            self.deletionGracePeriodSeconds = deletionGracePeriodSeconds
        if deletionTimestamp is not None:
            self.deletionTimestamp = deletionTimestamp
        if finalizers is not None:
            self.finalizers = finalizers
        if generateName is not None:
            self.generateName = generateName
        if generation is not None:
            self.generation = generation
        if labels is not None:
            self.labels = labels
        if managedFields is not None:
            self.managedFields = managedFields
        if name is not None:
            self.name = name
        if namespace is not None:
            self.namespace = namespace
        if ownerReferences is not None:
            self.ownerReferences = ownerReferences
        if resourceVersion is not None:
            self.resourceVersion = resourceVersion
        if selfLink is not None:
            self.selfLink = selfLink
        if uid is not None:
            self.uid = uid


class io__k8s__apimachinery__pkg__apis__meta__v1__Status(K8STemplatable):
    """Status is a return value for calls that don't return other objects."""

    apiVersion: str = "v1"
    kind: str = "Status"

    props: List[str] = [
        "apiVersion",
        "code",
        "details",
        "kind",
        "message",
        "metadata",
        "reason",
        "status",
    ]
    required_props: List[str] = []

    code: Optional[int] = None
    details: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__StatusDetails] = None
    message: Optional[str] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None
    reason: Optional[str] = None
    status: Optional[str] = None

    def __init__(
        self,
        code: Optional[int] = None,
        details: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__StatusDetails
        ] = None,
        message: Optional[str] = None,
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
        reason: Optional[str] = None,
        status: Optional[str] = None,
    ):
        super().__init__()
        if code is not None:
            self.code = code
        if details is not None:
            self.details = details
        if message is not None:
            self.message = message
        if metadata is not None:
            self.metadata = metadata
        if reason is not None:
            self.reason = reason
        if status is not None:
            self.status = status


class io__k8s__apimachinery__pkg__apis__meta__v1__WatchEvent(K8STemplatable):
    """Event represents a single event to a watched resource."""

    apiVersion: str = "v1"
    kind: str = "WatchEvent"

    props: List[str] = ["object", "type"]
    required_props: List[str] = ["type", "object"]

    object: io__k8s__apimachinery__pkg__runtime__RawExtension
    type: str

    def __init__(
        self, object: io__k8s__apimachinery__pkg__runtime__RawExtension, type: str
    ):
        super().__init__()
        if object is not None:
            self.object = object
        if type is not None:
            self.type = type


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceSpec(
    K8STemplatable
):
    """APIServiceSpec contains information for locating and communicating with a server. Only https is supported, though you are able to disable certificate verification."""

    props: List[str] = [
        "caBundle",
        "group",
        "groupPriorityMinimum",
        "insecureSkipTLSVerify",
        "service",
        "version",
        "versionPriority",
    ]
    required_props: List[str] = ["groupPriorityMinimum", "versionPriority"]

    caBundle: Optional[str] = None
    group: Optional[str] = None
    groupPriorityMinimum: int
    insecureSkipTLSVerify: Optional[bool] = None
    service: Optional[
        io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__ServiceReference
    ] = None
    version: Optional[str] = None
    versionPriority: int

    def __init__(
        self,
        groupPriorityMinimum: int,
        versionPriority: int,
        caBundle: Optional[str] = None,
        group: Optional[str] = None,
        insecureSkipTLSVerify: Optional[bool] = None,
        service: Optional[
            io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__ServiceReference
        ] = None,
        version: Optional[str] = None,
    ):
        super().__init__()
        if groupPriorityMinimum is not None:
            self.groupPriorityMinimum = groupPriorityMinimum
        if versionPriority is not None:
            self.versionPriority = versionPriority
        if caBundle is not None:
            self.caBundle = caBundle
        if group is not None:
            self.group = group
        if insecureSkipTLSVerify is not None:
            self.insecureSkipTLSVerify = insecureSkipTLSVerify
        if service is not None:
            self.service = service
        if version is not None:
            self.version = version


class io__k8s__api__admissionregistration__v1__MutatingWebhook(K8STemplatable):
    """MutatingWebhook describes an admission webhook and the resources and operations it applies to."""

    props: List[str] = [
        "admissionReviewVersions",
        "clientConfig",
        "failurePolicy",
        "matchPolicy",
        "name",
        "namespaceSelector",
        "objectSelector",
        "reinvocationPolicy",
        "rules",
        "sideEffects",
        "timeoutSeconds",
    ]
    required_props: List[str] = [
        "name",
        "clientConfig",
        "sideEffects",
        "admissionReviewVersions",
    ]

    admissionReviewVersions: List[str]
    clientConfig: io__k8s__api__admissionregistration__v1__WebhookClientConfig
    failurePolicy: Optional[str] = None
    matchPolicy: Optional[str] = None
    name: str
    namespaceSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    objectSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    reinvocationPolicy: Optional[str] = None
    rules: Optional[
        List[io__k8s__api__admissionregistration__v1__RuleWithOperations]
    ] = None
    sideEffects: str
    timeoutSeconds: Optional[int] = None

    def __init__(
        self,
        admissionReviewVersions: List[str],
        clientConfig: io__k8s__api__admissionregistration__v1__WebhookClientConfig,
        name: str,
        sideEffects: str,
        failurePolicy: Optional[str] = None,
        matchPolicy: Optional[str] = None,
        namespaceSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        objectSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        reinvocationPolicy: Optional[str] = None,
        rules: Optional[
            List[io__k8s__api__admissionregistration__v1__RuleWithOperations]
        ] = None,
        timeoutSeconds: Optional[int] = None,
    ):
        super().__init__()
        if admissionReviewVersions is not None:
            self.admissionReviewVersions = admissionReviewVersions
        if clientConfig is not None:
            self.clientConfig = clientConfig
        if name is not None:
            self.name = name
        if sideEffects is not None:
            self.sideEffects = sideEffects
        if failurePolicy is not None:
            self.failurePolicy = failurePolicy
        if matchPolicy is not None:
            self.matchPolicy = matchPolicy
        if namespaceSelector is not None:
            self.namespaceSelector = namespaceSelector
        if objectSelector is not None:
            self.objectSelector = objectSelector
        if reinvocationPolicy is not None:
            self.reinvocationPolicy = reinvocationPolicy
        if rules is not None:
            self.rules = rules
        if timeoutSeconds is not None:
            self.timeoutSeconds = timeoutSeconds


class io__k8s__api__admissionregistration__v1__MutatingWebhookConfiguration(
    K8STemplatable
):
    """MutatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and may change the object."""

    apiVersion: str = "admissionregistration.k8s.io/v1"
    kind: str = "MutatingWebhookConfiguration"

    props: List[str] = ["apiVersion", "kind", "metadata", "webhooks"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    webhooks: Optional[
        List[io__k8s__api__admissionregistration__v1__MutatingWebhook]
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        webhooks: Optional[
            List[io__k8s__api__admissionregistration__v1__MutatingWebhook]
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if webhooks is not None:
            self.webhooks = webhooks


class io__k8s__api__admissionregistration__v1__MutatingWebhookConfigurationList(
    K8STemplatable
):
    """MutatingWebhookConfigurationList is a list of MutatingWebhookConfiguration."""

    apiVersion: str = "admissionregistration.k8s.io/v1"
    kind: str = "MutatingWebhookConfigurationList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__admissionregistration__v1__MutatingWebhookConfiguration]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[
            io__k8s__api__admissionregistration__v1__MutatingWebhookConfiguration
        ],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__admissionregistration__v1__ValidatingWebhook(K8STemplatable):
    """ValidatingWebhook describes an admission webhook and the resources and operations it applies to."""

    props: List[str] = [
        "admissionReviewVersions",
        "clientConfig",
        "failurePolicy",
        "matchPolicy",
        "name",
        "namespaceSelector",
        "objectSelector",
        "rules",
        "sideEffects",
        "timeoutSeconds",
    ]
    required_props: List[str] = [
        "name",
        "clientConfig",
        "sideEffects",
        "admissionReviewVersions",
    ]

    admissionReviewVersions: List[str]
    clientConfig: io__k8s__api__admissionregistration__v1__WebhookClientConfig
    failurePolicy: Optional[str] = None
    matchPolicy: Optional[str] = None
    name: str
    namespaceSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    objectSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    rules: Optional[
        List[io__k8s__api__admissionregistration__v1__RuleWithOperations]
    ] = None
    sideEffects: str
    timeoutSeconds: Optional[int] = None

    def __init__(
        self,
        admissionReviewVersions: List[str],
        clientConfig: io__k8s__api__admissionregistration__v1__WebhookClientConfig,
        name: str,
        sideEffects: str,
        failurePolicy: Optional[str] = None,
        matchPolicy: Optional[str] = None,
        namespaceSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        objectSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        rules: Optional[
            List[io__k8s__api__admissionregistration__v1__RuleWithOperations]
        ] = None,
        timeoutSeconds: Optional[int] = None,
    ):
        super().__init__()
        if admissionReviewVersions is not None:
            self.admissionReviewVersions = admissionReviewVersions
        if clientConfig is not None:
            self.clientConfig = clientConfig
        if name is not None:
            self.name = name
        if sideEffects is not None:
            self.sideEffects = sideEffects
        if failurePolicy is not None:
            self.failurePolicy = failurePolicy
        if matchPolicy is not None:
            self.matchPolicy = matchPolicy
        if namespaceSelector is not None:
            self.namespaceSelector = namespaceSelector
        if objectSelector is not None:
            self.objectSelector = objectSelector
        if rules is not None:
            self.rules = rules
        if timeoutSeconds is not None:
            self.timeoutSeconds = timeoutSeconds


class io__k8s__api__admissionregistration__v1__ValidatingWebhookConfiguration(
    K8STemplatable
):
    """ValidatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and object without changing it."""

    apiVersion: str = "admissionregistration.k8s.io/v1"
    kind: str = "ValidatingWebhookConfiguration"

    props: List[str] = ["apiVersion", "kind", "metadata", "webhooks"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    webhooks: Optional[
        List[io__k8s__api__admissionregistration__v1__ValidatingWebhook]
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        webhooks: Optional[
            List[io__k8s__api__admissionregistration__v1__ValidatingWebhook]
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if webhooks is not None:
            self.webhooks = webhooks


class io__k8s__api__admissionregistration__v1__ValidatingWebhookConfigurationList(
    K8STemplatable
):
    """ValidatingWebhookConfigurationList is a list of ValidatingWebhookConfiguration."""

    apiVersion: str = "admissionregistration.k8s.io/v1"
    kind: str = "ValidatingWebhookConfigurationList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__admissionregistration__v1__ValidatingWebhookConfiguration]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[
            io__k8s__api__admissionregistration__v1__ValidatingWebhookConfiguration
        ],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apiserverinternal__v1alpha1__StorageVersion(K8STemplatable):
    """Storage version of a specific resource."""

    apiVersion: str = "internal.apiserver.k8s.io/v1alpha1"
    kind: str = "StorageVersion"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec", "status"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__apiserverinternal__v1alpha1__StorageVersionSpec
    status: io__k8s__api__apiserverinternal__v1alpha1__StorageVersionStatus

    def __init__(
        self,
        spec: io__k8s__api__apiserverinternal__v1alpha1__StorageVersionSpec,
        status: io__k8s__api__apiserverinternal__v1alpha1__StorageVersionStatus,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apiserverinternal__v1alpha1__StorageVersionList(K8STemplatable):
    """A list of StorageVersions."""

    apiVersion: str = "internal.apiserver.k8s.io/v1alpha1"
    kind: str = "StorageVersionList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apiserverinternal__v1alpha1__StorageVersion]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apiserverinternal__v1alpha1__StorageVersion],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__ControllerRevision(K8STemplatable):
    """ControllerRevision implements an immutable snapshot of state data. Clients are responsible for serializing and deserializing the objects that contain their internal state. Once a ControllerRevision has been successfully created, it can not be updated. The API Server will fail validation of all requests that attempt to mutate the Data field. ControllerRevisions may, however, be deleted. Note that, due to its use by both the DaemonSet and StatefulSet controllers for update and rollback, this object is beta. However, it may be subject to name and representation changes in future releases, and clients should not depend on its stability. It is primarily for internal use by controllers."""

    apiVersion: str = "apps/v1"
    kind: str = "ControllerRevision"

    props: List[str] = ["apiVersion", "data", "kind", "metadata", "revision"]
    required_props: List[str] = ["revision"]

    data: Optional[io__k8s__apimachinery__pkg__runtime__RawExtension] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    revision: int

    def __init__(
        self,
        revision: int,
        data: Optional[io__k8s__apimachinery__pkg__runtime__RawExtension] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if revision is not None:
            self.revision = revision
        if data is not None:
            self.data = data
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__ControllerRevisionList(K8STemplatable):
    """ControllerRevisionList is a resource containing a list of ControllerRevision objects."""

    apiVersion: str = "apps/v1"
    kind: str = "ControllerRevisionList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apps__v1__ControllerRevision]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apps__v1__ControllerRevision],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__DaemonSetUpdateStrategy(K8STemplatable):
    """DaemonSetUpdateStrategy is a struct used to control the update strategy for a DaemonSet."""

    props: List[str] = ["rollingUpdate", "type"]
    required_props: List[str] = []

    rollingUpdate: Optional[io__k8s__api__apps__v1__RollingUpdateDaemonSet] = None
    type: Optional[str] = None

    def __init__(
        self,
        rollingUpdate: Optional[io__k8s__api__apps__v1__RollingUpdateDaemonSet] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if rollingUpdate is not None:
            self.rollingUpdate = rollingUpdate
        if type is not None:
            self.type = type


class io__k8s__api__apps__v1__DeploymentStrategy(K8STemplatable):
    """DeploymentStrategy describes how to replace existing pods with new ones."""

    props: List[str] = ["rollingUpdate", "type"]
    required_props: List[str] = []

    rollingUpdate: Optional[io__k8s__api__apps__v1__RollingUpdateDeployment] = None
    type: Optional[str] = None

    def __init__(
        self,
        rollingUpdate: Optional[io__k8s__api__apps__v1__RollingUpdateDeployment] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if rollingUpdate is not None:
            self.rollingUpdate = rollingUpdate
        if type is not None:
            self.type = type


class io__k8s__api__authentication__v1__TokenRequest(K8STemplatable):
    """TokenRequest requests a token for a given service account."""

    apiVersion: str = "authentication.k8s.io/v1"
    kind: str = "TokenRequest"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authentication__v1__TokenRequestSpec
    status: Optional[io__k8s__api__authentication__v1__TokenRequestStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authentication__v1__TokenRequestSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[io__k8s__api__authentication__v1__TokenRequestStatus] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__authentication__v1__TokenReview(K8STemplatable):
    """TokenReview attempts to authenticate a token to a known user. Note: TokenReview requests may be cached by the webhook token authenticator plugin in the kube-apiserver."""

    apiVersion: str = "authentication.k8s.io/v1"
    kind: str = "TokenReview"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authentication__v1__TokenReviewSpec
    status: Optional[io__k8s__api__authentication__v1__TokenReviewStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authentication__v1__TokenReviewSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[io__k8s__api__authentication__v1__TokenReviewStatus] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__authorization__v1__LocalSubjectAccessReview(K8STemplatable):
    """LocalSubjectAccessReview checks whether or not a user or group can perform an action in a given namespace. Having a namespace scoped resource makes it much easier to grant namespace scoped policy that includes permissions checking."""

    apiVersion: str = "authorization.k8s.io/v1"
    kind: str = "LocalSubjectAccessReview"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authorization__v1__SubjectAccessReviewSpec
    status: Optional[io__k8s__api__authorization__v1__SubjectAccessReviewStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authorization__v1__SubjectAccessReviewSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[
            io__k8s__api__authorization__v1__SubjectAccessReviewStatus
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__authorization__v1__SelfSubjectAccessReview(K8STemplatable):
    """SelfSubjectAccessReview checks whether or the current user can perform an action.  Not filling in a spec.namespace means "in all namespaces".  Self is a special case, because users should always be able to check whether they can perform an action"""

    apiVersion: str = "authorization.k8s.io/v1"
    kind: str = "SelfSubjectAccessReview"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authorization__v1__SelfSubjectAccessReviewSpec
    status: Optional[io__k8s__api__authorization__v1__SubjectAccessReviewStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authorization__v1__SelfSubjectAccessReviewSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[
            io__k8s__api__authorization__v1__SubjectAccessReviewStatus
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__authorization__v1__SelfSubjectRulesReview(K8STemplatable):
    """SelfSubjectRulesReview enumerates the set of actions the current user can perform within a namespace. The returned list of actions may be incomplete depending on the server's authorization mode, and any errors experienced during the evaluation. SelfSubjectRulesReview should be used by UIs to show/hide actions, or to quickly let an end user reason about their permissions. It should NOT Be used by external systems to drive authorization decisions as this raises confused deputy, cache lifetime/revocation, and correctness concerns. SubjectAccessReview, and LocalAccessReview are the correct way to defer authorization decisions to the API server."""

    apiVersion: str = "authorization.k8s.io/v1"
    kind: str = "SelfSubjectRulesReview"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authorization__v1__SelfSubjectRulesReviewSpec
    status: Optional[io__k8s__api__authorization__v1__SubjectRulesReviewStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authorization__v1__SelfSubjectRulesReviewSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[
            io__k8s__api__authorization__v1__SubjectRulesReviewStatus
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__authorization__v1__SubjectAccessReview(K8STemplatable):
    """SubjectAccessReview checks whether or not a user or group can perform an action."""

    apiVersion: str = "authorization.k8s.io/v1"
    kind: str = "SubjectAccessReview"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__authorization__v1__SubjectAccessReviewSpec
    status: Optional[io__k8s__api__authorization__v1__SubjectAccessReviewStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__authorization__v1__SubjectAccessReviewSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[
            io__k8s__api__authorization__v1__SubjectAccessReviewStatus
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v1__HorizontalPodAutoscaler(K8STemplatable):
    """configuration of a horizontal pod autoscaler."""

    apiVersion: str = "autoscaling/v1"
    kind: str = "HorizontalPodAutoscaler"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerSpec] = None
    status: Optional[
        io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerSpec
        ] = None,
        status: Optional[
            io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerList(K8STemplatable):
    """list of horizontal pod autoscaler objects."""

    apiVersion: str = "autoscaling/v1"
    kind: str = "HorizontalPodAutoscalerList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__autoscaling__v1__HorizontalPodAutoscaler]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__autoscaling__v1__HorizontalPodAutoscaler],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v1__Scale(K8STemplatable):
    """Scale represents a scaling request for a resource."""

    apiVersion: str = "autoscaling/v1"
    kind: str = "Scale"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__autoscaling__v1__ScaleSpec] = None
    status: Optional[io__k8s__api__autoscaling__v1__ScaleStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__autoscaling__v1__ScaleSpec] = None,
        status: Optional[io__k8s__api__autoscaling__v1__ScaleStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v2__ContainerResourceMetricSource(K8STemplatable):
    """ContainerResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = ["container", "name", "target"]
    required_props: List[str] = ["name", "target", "container"]

    container: str
    name: str
    target: io__k8s__api__autoscaling__v2__MetricTarget

    def __init__(
        self,
        container: str,
        name: str,
        target: io__k8s__api__autoscaling__v2__MetricTarget,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if name is not None:
            self.name = name
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2__ContainerResourceMetricStatus(K8STemplatable):
    """ContainerResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing a single container in each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = ["container", "current", "name"]
    required_props: List[str] = ["name", "current", "container"]

    container: str
    current: io__k8s__api__autoscaling__v2__MetricValueStatus
    name: str

    def __init__(
        self,
        container: str,
        current: io__k8s__api__autoscaling__v2__MetricValueStatus,
        name: str,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if current is not None:
            self.current = current
        if name is not None:
            self.name = name


class io__k8s__api__autoscaling__v2__MetricIdentifier(K8STemplatable):
    """MetricIdentifier defines the name and optionally selector for a metric"""

    props: List[str] = ["name", "selector"]
    required_props: List[str] = ["name"]

    name: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None

    def __init__(
        self,
        name: str,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2__ObjectMetricSource(K8STemplatable):
    """ObjectMetricSource indicates how to scale on a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = ["describedObject", "metric", "target"]
    required_props: List[str] = ["describedObject", "target", "metric"]

    describedObject: io__k8s__api__autoscaling__v2__CrossVersionObjectReference
    metric: io__k8s__api__autoscaling__v2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2__MetricTarget

    def __init__(
        self,
        describedObject: io__k8s__api__autoscaling__v2__CrossVersionObjectReference,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2__MetricTarget,
    ):
        super().__init__()
        if describedObject is not None:
            self.describedObject = describedObject
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2__ObjectMetricStatus(K8STemplatable):
    """ObjectMetricStatus indicates the current value of a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = ["current", "describedObject", "metric"]
    required_props: List[str] = ["metric", "current", "describedObject"]

    current: io__k8s__api__autoscaling__v2__MetricValueStatus
    describedObject: io__k8s__api__autoscaling__v2__CrossVersionObjectReference
    metric: io__k8s__api__autoscaling__v2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2__MetricValueStatus,
        describedObject: io__k8s__api__autoscaling__v2__CrossVersionObjectReference,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if describedObject is not None:
            self.describedObject = describedObject
        if metric is not None:
            self.metric = metric


class io__k8s__api__autoscaling__v2__PodsMetricSource(K8STemplatable):
    """PodsMetricSource indicates how to scale on a metric describing each pod in the current scale target (for example, transactions-processed-per-second). The values will be averaged together before being compared to the target value."""

    props: List[str] = ["metric", "target"]
    required_props: List[str] = ["metric", "target"]

    metric: io__k8s__api__autoscaling__v2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2__MetricTarget

    def __init__(
        self,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2__MetricTarget,
    ):
        super().__init__()
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2__PodsMetricStatus(K8STemplatable):
    """PodsMetricStatus indicates the current value of a metric describing each pod in the current scale target (for example, transactions-processed-per-second)."""

    props: List[str] = ["current", "metric"]
    required_props: List[str] = ["metric", "current"]

    current: io__k8s__api__autoscaling__v2__MetricValueStatus
    metric: io__k8s__api__autoscaling__v2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2__MetricValueStatus,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if metric is not None:
            self.metric = metric


class io__k8s__api__autoscaling__v2beta1__ExternalMetricSource(K8STemplatable):
    """ExternalMetricSource indicates how to scale on a metric not associated with any Kubernetes object (for example length of queue in cloud messaging service, or QPS from loadbalancer running outside of cluster). Exactly one "target" type should be set."""

    props: List[str] = [
        "metricName",
        "metricSelector",
        "targetAverageValue",
        "targetValue",
    ]
    required_props: List[str] = ["metricName"]

    metricName: str
    metricSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    targetAverageValue: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None
    targetValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None

    def __init__(
        self,
        metricName: str,
        metricSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        targetAverageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        targetValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
    ):
        super().__init__()
        if metricName is not None:
            self.metricName = metricName
        if metricSelector is not None:
            self.metricSelector = metricSelector
        if targetAverageValue is not None:
            self.targetAverageValue = targetAverageValue
        if targetValue is not None:
            self.targetValue = targetValue


class io__k8s__api__autoscaling__v2beta1__ExternalMetricStatus(K8STemplatable):
    """ExternalMetricStatus indicates the current value of a global metric not associated with any Kubernetes object."""

    props: List[str] = [
        "currentAverageValue",
        "currentValue",
        "metricName",
        "metricSelector",
    ]
    required_props: List[str] = ["metricName", "currentValue"]

    currentAverageValue: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None
    currentValue: io__k8s__apimachinery__pkg__api__resource__Quantity
    metricName: str
    metricSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None

    def __init__(
        self,
        currentValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        metricName: str,
        currentAverageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        metricSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if currentValue is not None:
            self.currentValue = currentValue
        if metricName is not None:
            self.metricName = metricName
        if currentAverageValue is not None:
            self.currentAverageValue = currentAverageValue
        if metricSelector is not None:
            self.metricSelector = metricSelector


class io__k8s__api__autoscaling__v2beta1__ObjectMetricSource(K8STemplatable):
    """ObjectMetricSource indicates how to scale on a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = [
        "averageValue",
        "metricName",
        "selector",
        "target",
        "targetValue",
    ]
    required_props: List[str] = ["target", "metricName", "targetValue"]

    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    metricName: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None
    target: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference
    targetValue: io__k8s__apimachinery__pkg__api__resource__Quantity

    def __init__(
        self,
        metricName: str,
        target: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference,
        targetValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if metricName is not None:
            self.metricName = metricName
        if target is not None:
            self.target = target
        if targetValue is not None:
            self.targetValue = targetValue
        if averageValue is not None:
            self.averageValue = averageValue
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2beta1__ObjectMetricStatus(K8STemplatable):
    """ObjectMetricStatus indicates the current value of a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = [
        "averageValue",
        "currentValue",
        "metricName",
        "selector",
        "target",
    ]
    required_props: List[str] = ["target", "metricName", "currentValue"]

    averageValue: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    currentValue: io__k8s__apimachinery__pkg__api__resource__Quantity
    metricName: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None
    target: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference

    def __init__(
        self,
        currentValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        metricName: str,
        target: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference,
        averageValue: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if currentValue is not None:
            self.currentValue = currentValue
        if metricName is not None:
            self.metricName = metricName
        if target is not None:
            self.target = target
        if averageValue is not None:
            self.averageValue = averageValue
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2beta1__PodsMetricSource(K8STemplatable):
    """PodsMetricSource indicates how to scale on a metric describing each pod in the current scale target (for example, transactions-processed-per-second). The values will be averaged together before being compared to the target value."""

    props: List[str] = ["metricName", "selector", "targetAverageValue"]
    required_props: List[str] = ["metricName", "targetAverageValue"]

    metricName: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None
    targetAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity

    def __init__(
        self,
        metricName: str,
        targetAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if metricName is not None:
            self.metricName = metricName
        if targetAverageValue is not None:
            self.targetAverageValue = targetAverageValue
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2beta1__PodsMetricStatus(K8STemplatable):
    """PodsMetricStatus indicates the current value of a metric describing each pod in the current scale target (for example, transactions-processed-per-second)."""

    props: List[str] = ["currentAverageValue", "metricName", "selector"]
    required_props: List[str] = ["metricName", "currentAverageValue"]

    currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity
    metricName: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None

    def __init__(
        self,
        currentAverageValue: io__k8s__apimachinery__pkg__api__resource__Quantity,
        metricName: str,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if currentAverageValue is not None:
            self.currentAverageValue = currentAverageValue
        if metricName is not None:
            self.metricName = metricName
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricSource(K8STemplatable):
    """ContainerResourceMetricSource indicates how to scale on a resource metric known to Kubernetes, as specified in requests and limits, describing each pod in the current scale target (e.g. CPU or memory).  The values will be averaged together before being compared to the target.  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source.  Only one "target" type should be set."""

    props: List[str] = ["container", "name", "target"]
    required_props: List[str] = ["name", "target", "container"]

    container: str
    name: str
    target: io__k8s__api__autoscaling__v2beta2__MetricTarget

    def __init__(
        self,
        container: str,
        name: str,
        target: io__k8s__api__autoscaling__v2beta2__MetricTarget,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if name is not None:
            self.name = name
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricStatus(K8STemplatable):
    """ContainerResourceMetricStatus indicates the current value of a resource metric known to Kubernetes, as specified in requests and limits, describing a single container in each pod in the current scale target (e.g. CPU or memory).  Such metrics are built in to Kubernetes, and have special scaling options on top of those available to normal per-pod metrics using the "pods" source."""

    props: List[str] = ["container", "current", "name"]
    required_props: List[str] = ["name", "current", "container"]

    container: str
    current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus
    name: str

    def __init__(
        self,
        container: str,
        current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus,
        name: str,
    ):
        super().__init__()
        if container is not None:
            self.container = container
        if current is not None:
            self.current = current
        if name is not None:
            self.name = name


class io__k8s__api__autoscaling__v2beta2__MetricIdentifier(K8STemplatable):
    """MetricIdentifier defines the name and optionally selector for a metric"""

    props: List[str] = ["name", "selector"]
    required_props: List[str] = ["name"]

    name: str
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None

    def __init__(
        self,
        name: str,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if selector is not None:
            self.selector = selector


class io__k8s__api__autoscaling__v2beta2__ObjectMetricSource(K8STemplatable):
    """ObjectMetricSource indicates how to scale on a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = ["describedObject", "metric", "target"]
    required_props: List[str] = ["describedObject", "target", "metric"]

    describedObject: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference
    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2beta2__MetricTarget

    def __init__(
        self,
        describedObject: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2beta2__MetricTarget,
    ):
        super().__init__()
        if describedObject is not None:
            self.describedObject = describedObject
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2beta2__ObjectMetricStatus(K8STemplatable):
    """ObjectMetricStatus indicates the current value of a metric describing a kubernetes object (for example, hits-per-second on an Ingress object)."""

    props: List[str] = ["current", "describedObject", "metric"]
    required_props: List[str] = ["metric", "current", "describedObject"]

    current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus
    describedObject: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference
    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus,
        describedObject: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if describedObject is not None:
            self.describedObject = describedObject
        if metric is not None:
            self.metric = metric


class io__k8s__api__autoscaling__v2beta2__PodsMetricSource(K8STemplatable):
    """PodsMetricSource indicates how to scale on a metric describing each pod in the current scale target (for example, transactions-processed-per-second). The values will be averaged together before being compared to the target value."""

    props: List[str] = ["metric", "target"]
    required_props: List[str] = ["metric", "target"]

    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2beta2__MetricTarget

    def __init__(
        self,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2beta2__MetricTarget,
    ):
        super().__init__()
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2beta2__PodsMetricStatus(K8STemplatable):
    """PodsMetricStatus indicates the current value of a metric describing each pod in the current scale target (for example, transactions-processed-per-second)."""

    props: List[str] = ["current", "metric"]
    required_props: List[str] = ["metric", "current"]

    current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus
    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if metric is not None:
            self.metric = metric


class io__k8s__api__certificates__v1__CertificateSigningRequest(K8STemplatable):
    """CertificateSigningRequest objects provide a mechanism to obtain x509 certificates by submitting a certificate signing request, and having it asynchronously approved and issued.

    Kubelets use this API to obtain:
     1. client certificates to authenticate to kube-apiserver (with the "kubernetes.io/kube-apiserver-client-kubelet" signerName).
     2. serving certificates for TLS endpoints kube-apiserver can connect to securely (with the "kubernetes.io/kubelet-serving" signerName).

    This API can be used to request client certificates to authenticate to kube-apiserver (with the "kubernetes.io/kube-apiserver-client" signerName), or to obtain certificates from custom non-Kubernetes signers."""

    apiVersion: str = "certificates.k8s.io/v1"
    kind: str = "CertificateSigningRequest"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__certificates__v1__CertificateSigningRequestSpec
    status: Optional[
        io__k8s__api__certificates__v1__CertificateSigningRequestStatus
    ] = None

    def __init__(
        self,
        spec: io__k8s__api__certificates__v1__CertificateSigningRequestSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[
            io__k8s__api__certificates__v1__CertificateSigningRequestStatus
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__certificates__v1__CertificateSigningRequestList(K8STemplatable):
    """CertificateSigningRequestList is a collection of CertificateSigningRequest objects"""

    apiVersion: str = "certificates.k8s.io/v1"
    kind: str = "CertificateSigningRequestList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__certificates__v1__CertificateSigningRequest]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__certificates__v1__CertificateSigningRequest],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__coordination__v1__Lease(K8STemplatable):
    """Lease defines a lease concept."""

    apiVersion: str = "coordination.k8s.io/v1"
    kind: str = "Lease"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__coordination__v1__LeaseSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__coordination__v1__LeaseSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__coordination__v1__LeaseList(K8STemplatable):
    """LeaseList is a list of Lease objects."""

    apiVersion: str = "coordination.k8s.io/v1"
    kind: str = "LeaseList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__coordination__v1__Lease]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__coordination__v1__Lease],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__Binding(K8STemplatable):
    """Binding ties one object to another; for example, a pod is bound to a node by a scheduler. Deprecated in 1.7, please use the bindings subresource of pods instead."""

    apiVersion: str = "v1"
    kind: str = "Binding"

    props: List[str] = ["apiVersion", "kind", "metadata", "target"]
    required_props: List[str] = ["target"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    target: io__k8s__api__core__v1__ObjectReference

    def __init__(
        self,
        target: io__k8s__api__core__v1__ObjectReference,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if target is not None:
            self.target = target
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ComponentStatus(K8STemplatable):
    """ComponentStatus (and ComponentStatusList) holds the cluster validation info. Deprecated: This API is deprecated in v1.19+"""

    apiVersion: str = "v1"
    kind: str = "ComponentStatus"

    props: List[str] = ["apiVersion", "conditions", "kind", "metadata"]
    required_props: List[str] = []

    conditions: Optional[List[io__k8s__api__core__v1__ComponentCondition]] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None

    def __init__(
        self,
        conditions: Optional[List[io__k8s__api__core__v1__ComponentCondition]] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ComponentStatusList(K8STemplatable):
    """Status of all the conditions for the component as a list of ComponentStatus objects. Deprecated: This API is deprecated in v1.19+"""

    apiVersion: str = "v1"
    kind: str = "ComponentStatusList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__ComponentStatus]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__ComponentStatus],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ConfigMap(K8STemplatable):
    """ConfigMap holds configuration data for pods to consume."""

    apiVersion: str = "v1"
    kind: str = "ConfigMap"

    props: List[str] = [
        "apiVersion",
        "binaryData",
        "data",
        "immutable",
        "kind",
        "metadata",
    ]
    required_props: List[str] = []

    binaryData: Any
    data: Any
    immutable: Optional[bool] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None

    def __init__(
        self,
        binaryData: Any = None,
        data: Any = None,
        immutable: Optional[bool] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if binaryData is not None:
            self.binaryData = binaryData
        if data is not None:
            self.data = data
        if immutable is not None:
            self.immutable = immutable
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ConfigMapList(K8STemplatable):
    """ConfigMapList is a resource containing a list of ConfigMap objects."""

    apiVersion: str = "v1"
    kind: str = "ConfigMapList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__ConfigMap]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__ConfigMap],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ContainerState(K8STemplatable):
    """ContainerState holds a possible state of container. Only one of its members may be specified. If none of them is specified, the default one is ContainerStateWaiting."""

    props: List[str] = ["running", "terminated", "waiting"]
    required_props: List[str] = []

    running: Optional[io__k8s__api__core__v1__ContainerStateRunning] = None
    terminated: Optional[io__k8s__api__core__v1__ContainerStateTerminated] = None
    waiting: Optional[io__k8s__api__core__v1__ContainerStateWaiting] = None

    def __init__(
        self,
        running: Optional[io__k8s__api__core__v1__ContainerStateRunning] = None,
        terminated: Optional[io__k8s__api__core__v1__ContainerStateTerminated] = None,
        waiting: Optional[io__k8s__api__core__v1__ContainerStateWaiting] = None,
    ):
        super().__init__()
        if running is not None:
            self.running = running
        if terminated is not None:
            self.terminated = terminated
        if waiting is not None:
            self.waiting = waiting


class io__k8s__api__core__v1__ContainerStatus(K8STemplatable):
    """ContainerStatus contains details for the current status of this container."""

    props: List[str] = [
        "containerID",
        "image",
        "imageID",
        "lastState",
        "name",
        "ready",
        "restartCount",
        "started",
        "state",
    ]
    required_props: List[str] = ["name", "ready", "restartCount", "image", "imageID"]

    containerID: Optional[str] = None
    image: str
    imageID: str
    lastState: Optional[io__k8s__api__core__v1__ContainerState] = None
    name: str
    ready: bool
    restartCount: int
    started: Optional[bool] = None
    state: Optional[io__k8s__api__core__v1__ContainerState] = None

    def __init__(
        self,
        image: str,
        imageID: str,
        name: str,
        ready: bool,
        restartCount: int,
        containerID: Optional[str] = None,
        lastState: Optional[io__k8s__api__core__v1__ContainerState] = None,
        started: Optional[bool] = None,
        state: Optional[io__k8s__api__core__v1__ContainerState] = None,
    ):
        super().__init__()
        if image is not None:
            self.image = image
        if imageID is not None:
            self.imageID = imageID
        if name is not None:
            self.name = name
        if ready is not None:
            self.ready = ready
        if restartCount is not None:
            self.restartCount = restartCount
        if containerID is not None:
            self.containerID = containerID
        if lastState is not None:
            self.lastState = lastState
        if started is not None:
            self.started = started
        if state is not None:
            self.state = state


class io__k8s__api__core__v1__DownwardAPIVolumeFile(K8STemplatable):
    """DownwardAPIVolumeFile represents information to create the file containing the pod field"""

    props: List[str] = ["fieldRef", "mode", "path", "resourceFieldRef"]
    required_props: List[str] = ["path"]

    fieldRef: Optional[io__k8s__api__core__v1__ObjectFieldSelector] = None
    mode: Optional[int] = None
    path: str
    resourceFieldRef: Optional[io__k8s__api__core__v1__ResourceFieldSelector] = None

    def __init__(
        self,
        path: str,
        fieldRef: Optional[io__k8s__api__core__v1__ObjectFieldSelector] = None,
        mode: Optional[int] = None,
        resourceFieldRef: Optional[
            io__k8s__api__core__v1__ResourceFieldSelector
        ] = None,
    ):
        super().__init__()
        if path is not None:
            self.path = path
        if fieldRef is not None:
            self.fieldRef = fieldRef
        if mode is not None:
            self.mode = mode
        if resourceFieldRef is not None:
            self.resourceFieldRef = resourceFieldRef


class io__k8s__api__core__v1__DownwardAPIVolumeSource(K8STemplatable):
    """DownwardAPIVolumeSource represents a volume containing downward API info. Downward API volumes support ownership management and SELinux relabeling."""

    props: List[str] = ["defaultMode", "items"]
    required_props: List[str] = []

    defaultMode: Optional[int] = None
    items: Optional[List[io__k8s__api__core__v1__DownwardAPIVolumeFile]] = None

    def __init__(
        self,
        defaultMode: Optional[int] = None,
        items: Optional[List[io__k8s__api__core__v1__DownwardAPIVolumeFile]] = None,
    ):
        super().__init__()
        if defaultMode is not None:
            self.defaultMode = defaultMode
        if items is not None:
            self.items = items


class io__k8s__api__core__v1__Endpoints(K8STemplatable):
    """Endpoints is a collection of endpoints that implement the actual service. Example:
     Name: "mysvc",
     Subsets: [
       {
         Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
         Ports: [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
       },
       {
         Addresses: [{"ip": "10.10.3.3"}],
         Ports: [{"name": "a", "port": 93}, {"name": "b", "port": 76}]
       },
    ]"""

    apiVersion: str = "v1"
    kind: str = "Endpoints"

    props: List[str] = ["apiVersion", "kind", "metadata", "subsets"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    subsets: Optional[List[io__k8s__api__core__v1__EndpointSubset]] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        subsets: Optional[List[io__k8s__api__core__v1__EndpointSubset]] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if subsets is not None:
            self.subsets = subsets


class io__k8s__api__core__v1__EndpointsList(K8STemplatable):
    """EndpointsList is a list of endpoints."""

    apiVersion: str = "v1"
    kind: str = "EndpointsList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Endpoints]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Endpoints],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__EnvVarSource(K8STemplatable):
    """EnvVarSource represents a source for the value of an EnvVar."""

    props: List[str] = [
        "configMapKeyRef",
        "fieldRef",
        "resourceFieldRef",
        "secretKeyRef",
    ]
    required_props: List[str] = []

    configMapKeyRef: Optional[io__k8s__api__core__v1__ConfigMapKeySelector] = None
    fieldRef: Optional[io__k8s__api__core__v1__ObjectFieldSelector] = None
    resourceFieldRef: Optional[io__k8s__api__core__v1__ResourceFieldSelector] = None
    secretKeyRef: Optional[io__k8s__api__core__v1__SecretKeySelector] = None

    def __init__(
        self,
        configMapKeyRef: Optional[io__k8s__api__core__v1__ConfigMapKeySelector] = None,
        fieldRef: Optional[io__k8s__api__core__v1__ObjectFieldSelector] = None,
        resourceFieldRef: Optional[
            io__k8s__api__core__v1__ResourceFieldSelector
        ] = None,
        secretKeyRef: Optional[io__k8s__api__core__v1__SecretKeySelector] = None,
    ):
        super().__init__()
        if configMapKeyRef is not None:
            self.configMapKeyRef = configMapKeyRef
        if fieldRef is not None:
            self.fieldRef = fieldRef
        if resourceFieldRef is not None:
            self.resourceFieldRef = resourceFieldRef
        if secretKeyRef is not None:
            self.secretKeyRef = secretKeyRef


class io__k8s__api__core__v1__Event(K8STemplatable):
    """Event is a report of an event somewhere in the cluster.  Events have a limited retention time and triggers and messages may evolve with time.  Event consumers should not rely on the timing of an event with a given Reason reflecting a consistent underlying trigger, or the continued existence of events with that Reason.  Events should be treated as informative, best-effort, supplemental data."""

    apiVersion: str = "v1"
    kind: str = "Event"

    props: List[str] = [
        "action",
        "apiVersion",
        "count",
        "eventTime",
        "firstTimestamp",
        "involvedObject",
        "kind",
        "lastTimestamp",
        "message",
        "metadata",
        "reason",
        "related",
        "reportingComponent",
        "reportingInstance",
        "series",
        "source",
        "type",
    ]
    required_props: List[str] = ["metadata", "involvedObject"]

    action: Optional[str] = None
    count: Optional[int] = None
    eventTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime] = None
    firstTimestamp: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    involvedObject: io__k8s__api__core__v1__ObjectReference
    lastTimestamp: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    message: Optional[str] = None
    metadata: io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
    reason: Optional[str] = None
    related: Optional[io__k8s__api__core__v1__ObjectReference] = None
    reportingComponent: Optional[str] = None
    reportingInstance: Optional[str] = None
    series: Optional[io__k8s__api__core__v1__EventSeries] = None
    source: Optional[io__k8s__api__core__v1__EventSource] = None
    type: Optional[str] = None

    def __init__(
        self,
        involvedObject: io__k8s__api__core__v1__ObjectReference,
        metadata: io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta,
        action: Optional[str] = None,
        count: Optional[int] = None,
        eventTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
        ] = None,
        firstTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        lastTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        message: Optional[str] = None,
        reason: Optional[str] = None,
        related: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        reportingComponent: Optional[str] = None,
        reportingInstance: Optional[str] = None,
        series: Optional[io__k8s__api__core__v1__EventSeries] = None,
        source: Optional[io__k8s__api__core__v1__EventSource] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if involvedObject is not None:
            self.involvedObject = involvedObject
        if metadata is not None:
            self.metadata = metadata
        if action is not None:
            self.action = action
        if count is not None:
            self.count = count
        if eventTime is not None:
            self.eventTime = eventTime
        if firstTimestamp is not None:
            self.firstTimestamp = firstTimestamp
        if lastTimestamp is not None:
            self.lastTimestamp = lastTimestamp
        if message is not None:
            self.message = message
        if reason is not None:
            self.reason = reason
        if related is not None:
            self.related = related
        if reportingComponent is not None:
            self.reportingComponent = reportingComponent
        if reportingInstance is not None:
            self.reportingInstance = reportingInstance
        if series is not None:
            self.series = series
        if source is not None:
            self.source = source
        if type is not None:
            self.type = type


class io__k8s__api__core__v1__EventList(K8STemplatable):
    """EventList is a list of events."""

    apiVersion: str = "v1"
    kind: str = "EventList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Event]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Event],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__LifecycleHandler(K8STemplatable):
    """LifecycleHandler defines a specific action that should be taken in a lifecycle hook. One and only one of the fields, except TCPSocket must be specified."""

    props: List[str] = ["exec", "httpGet", "tcpSocket"]
    required_props: List[str] = []

    exec: Optional[io__k8s__api__core__v1__ExecAction] = None
    httpGet: Optional[io__k8s__api__core__v1__HTTPGetAction] = None
    tcpSocket: Optional[io__k8s__api__core__v1__TCPSocketAction] = None

    def __init__(
        self,
        exec: Optional[io__k8s__api__core__v1__ExecAction] = None,
        httpGet: Optional[io__k8s__api__core__v1__HTTPGetAction] = None,
        tcpSocket: Optional[io__k8s__api__core__v1__TCPSocketAction] = None,
    ):
        super().__init__()
        if exec is not None:
            self.exec = exec
        if httpGet is not None:
            self.httpGet = httpGet
        if tcpSocket is not None:
            self.tcpSocket = tcpSocket


class io__k8s__api__core__v1__LimitRange(K8STemplatable):
    """LimitRange sets resource usage limits for each kind of resource in a Namespace."""

    apiVersion: str = "v1"
    kind: str = "LimitRange"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__LimitRangeSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__LimitRangeSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__core__v1__LimitRangeList(K8STemplatable):
    """LimitRangeList is a list of LimitRange items."""

    apiVersion: str = "v1"
    kind: str = "LimitRangeList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__LimitRange]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__LimitRange],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__Namespace(K8STemplatable):
    """Namespace provides a scope for Names. Use of multiple namespaces is optional."""

    apiVersion: str = "v1"
    kind: str = "Namespace"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__NamespaceSpec] = None
    status: Optional[io__k8s__api__core__v1__NamespaceStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__NamespaceSpec] = None,
        status: Optional[io__k8s__api__core__v1__NamespaceStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__NamespaceList(K8STemplatable):
    """NamespaceList is a list of Namespaces."""

    apiVersion: str = "v1"
    kind: str = "NamespaceList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Namespace]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Namespace],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__NodeAffinity(K8STemplatable):
    """Node affinity is a group of node affinity scheduling rules."""

    props: List[str] = [
        "preferredDuringSchedulingIgnoredDuringExecution",
        "requiredDuringSchedulingIgnoredDuringExecution",
    ]
    required_props: List[str] = []

    preferredDuringSchedulingIgnoredDuringExecution: Optional[
        List[io__k8s__api__core__v1__PreferredSchedulingTerm]
    ] = None
    requiredDuringSchedulingIgnoredDuringExecution: Optional[
        io__k8s__api__core__v1__NodeSelector
    ] = None

    def __init__(
        self,
        preferredDuringSchedulingIgnoredDuringExecution: Optional[
            List[io__k8s__api__core__v1__PreferredSchedulingTerm]
        ] = None,
        requiredDuringSchedulingIgnoredDuringExecution: Optional[
            io__k8s__api__core__v1__NodeSelector
        ] = None,
    ):
        super().__init__()
        if preferredDuringSchedulingIgnoredDuringExecution is not None:
            self.preferredDuringSchedulingIgnoredDuringExecution = (
                preferredDuringSchedulingIgnoredDuringExecution
            )
        if requiredDuringSchedulingIgnoredDuringExecution is not None:
            self.requiredDuringSchedulingIgnoredDuringExecution = (
                requiredDuringSchedulingIgnoredDuringExecution
            )


class io__k8s__api__core__v1__NodeSpec(K8STemplatable):
    """NodeSpec describes the attributes that a node is created with."""

    props: List[str] = [
        "configSource",
        "externalID",
        "podCIDR",
        "podCIDRs",
        "providerID",
        "taints",
        "unschedulable",
    ]
    required_props: List[str] = []

    configSource: Optional[io__k8s__api__core__v1__NodeConfigSource] = None
    externalID: Optional[str] = None
    podCIDR: Optional[str] = None
    podCIDRs: Optional[List[str]] = None
    providerID: Optional[str] = None
    taints: Optional[List[io__k8s__api__core__v1__Taint]] = None
    unschedulable: Optional[bool] = None

    def __init__(
        self,
        configSource: Optional[io__k8s__api__core__v1__NodeConfigSource] = None,
        externalID: Optional[str] = None,
        podCIDR: Optional[str] = None,
        podCIDRs: Optional[List[str]] = None,
        providerID: Optional[str] = None,
        taints: Optional[List[io__k8s__api__core__v1__Taint]] = None,
        unschedulable: Optional[bool] = None,
    ):
        super().__init__()
        if configSource is not None:
            self.configSource = configSource
        if externalID is not None:
            self.externalID = externalID
        if podCIDR is not None:
            self.podCIDR = podCIDR
        if podCIDRs is not None:
            self.podCIDRs = podCIDRs
        if providerID is not None:
            self.providerID = providerID
        if taints is not None:
            self.taints = taints
        if unschedulable is not None:
            self.unschedulable = unschedulable


class io__k8s__api__core__v1__PersistentVolumeClaimSpec(K8STemplatable):
    """PersistentVolumeClaimSpec describes the common attributes of storage devices and allows a Source for provider-specific attributes"""

    props: List[str] = [
        "accessModes",
        "dataSource",
        "dataSourceRef",
        "resources",
        "selector",
        "storageClassName",
        "volumeMode",
        "volumeName",
    ]
    required_props: List[str] = []

    accessModes: Optional[List[str]] = None
    dataSource: Optional[io__k8s__api__core__v1__TypedLocalObjectReference] = None
    dataSourceRef: Optional[io__k8s__api__core__v1__TypedLocalObjectReference] = None
    resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None
    storageClassName: Optional[str] = None
    volumeMode: Optional[str] = None
    volumeName: Optional[str] = None

    def __init__(
        self,
        accessModes: Optional[List[str]] = None,
        dataSource: Optional[io__k8s__api__core__v1__TypedLocalObjectReference] = None,
        dataSourceRef: Optional[
            io__k8s__api__core__v1__TypedLocalObjectReference
        ] = None,
        resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        storageClassName: Optional[str] = None,
        volumeMode: Optional[str] = None,
        volumeName: Optional[str] = None,
    ):
        super().__init__()
        if accessModes is not None:
            self.accessModes = accessModes
        if dataSource is not None:
            self.dataSource = dataSource
        if dataSourceRef is not None:
            self.dataSourceRef = dataSourceRef
        if resources is not None:
            self.resources = resources
        if selector is not None:
            self.selector = selector
        if storageClassName is not None:
            self.storageClassName = storageClassName
        if volumeMode is not None:
            self.volumeMode = volumeMode
        if volumeName is not None:
            self.volumeName = volumeName


class io__k8s__api__core__v1__PersistentVolumeClaimTemplate(K8STemplatable):
    """PersistentVolumeClaimTemplate is used to produce PersistentVolumeClaim objects as part of an EphemeralVolumeSource."""

    props: List[str] = ["metadata", "spec"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__core__v1__PersistentVolumeClaimSpec

    def __init__(
        self,
        spec: io__k8s__api__core__v1__PersistentVolumeClaimSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PersistentVolumeSpec(K8STemplatable):
    """PersistentVolumeSpec is the specification of a persistent volume."""

    props: List[str] = [
        "accessModes",
        "awsElasticBlockStore",
        "azureDisk",
        "azureFile",
        "capacity",
        "cephfs",
        "cinder",
        "claimRef",
        "csi",
        "fc",
        "flexVolume",
        "flocker",
        "gcePersistentDisk",
        "glusterfs",
        "hostPath",
        "iscsi",
        "local",
        "mountOptions",
        "nfs",
        "nodeAffinity",
        "persistentVolumeReclaimPolicy",
        "photonPersistentDisk",
        "portworxVolume",
        "quobyte",
        "rbd",
        "scaleIO",
        "storageClassName",
        "storageos",
        "volumeMode",
        "vsphereVolume",
    ]
    required_props: List[str] = []

    accessModes: Optional[List[str]] = None
    awsElasticBlockStore: Optional[
        io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource
    ] = None
    azureDisk: Optional[io__k8s__api__core__v1__AzureDiskVolumeSource] = None
    azureFile: Optional[io__k8s__api__core__v1__AzureFilePersistentVolumeSource] = None
    capacity: Any
    cephfs: Optional[io__k8s__api__core__v1__CephFSPersistentVolumeSource] = None
    cinder: Optional[io__k8s__api__core__v1__CinderPersistentVolumeSource] = None
    claimRef: Optional[io__k8s__api__core__v1__ObjectReference] = None
    csi: Optional[io__k8s__api__core__v1__CSIPersistentVolumeSource] = None
    fc: Optional[io__k8s__api__core__v1__FCVolumeSource] = None
    flexVolume: Optional[io__k8s__api__core__v1__FlexPersistentVolumeSource] = None
    flocker: Optional[io__k8s__api__core__v1__FlockerVolumeSource] = None
    gcePersistentDisk: Optional[
        io__k8s__api__core__v1__GCEPersistentDiskVolumeSource
    ] = None
    glusterfs: Optional[io__k8s__api__core__v1__GlusterfsPersistentVolumeSource] = None
    hostPath: Optional[io__k8s__api__core__v1__HostPathVolumeSource] = None
    iscsi: Optional[io__k8s__api__core__v1__ISCSIPersistentVolumeSource] = None
    local: Optional[io__k8s__api__core__v1__LocalVolumeSource] = None
    mountOptions: Optional[List[str]] = None
    nfs: Optional[io__k8s__api__core__v1__NFSVolumeSource] = None
    nodeAffinity: Optional[io__k8s__api__core__v1__VolumeNodeAffinity] = None
    persistentVolumeReclaimPolicy: Optional[str] = None
    photonPersistentDisk: Optional[
        io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource
    ] = None
    portworxVolume: Optional[io__k8s__api__core__v1__PortworxVolumeSource] = None
    quobyte: Optional[io__k8s__api__core__v1__QuobyteVolumeSource] = None
    rbd: Optional[io__k8s__api__core__v1__RBDPersistentVolumeSource] = None
    scaleIO: Optional[io__k8s__api__core__v1__ScaleIOPersistentVolumeSource] = None
    storageClassName: Optional[str] = None
    storageos: Optional[io__k8s__api__core__v1__StorageOSPersistentVolumeSource] = None
    volumeMode: Optional[str] = None
    vsphereVolume: Optional[
        io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource
    ] = None

    def __init__(
        self,
        accessModes: Optional[List[str]] = None,
        awsElasticBlockStore: Optional[
            io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource
        ] = None,
        azureDisk: Optional[io__k8s__api__core__v1__AzureDiskVolumeSource] = None,
        azureFile: Optional[
            io__k8s__api__core__v1__AzureFilePersistentVolumeSource
        ] = None,
        capacity: Any = None,
        cephfs: Optional[io__k8s__api__core__v1__CephFSPersistentVolumeSource] = None,
        cinder: Optional[io__k8s__api__core__v1__CinderPersistentVolumeSource] = None,
        claimRef: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        csi: Optional[io__k8s__api__core__v1__CSIPersistentVolumeSource] = None,
        fc: Optional[io__k8s__api__core__v1__FCVolumeSource] = None,
        flexVolume: Optional[io__k8s__api__core__v1__FlexPersistentVolumeSource] = None,
        flocker: Optional[io__k8s__api__core__v1__FlockerVolumeSource] = None,
        gcePersistentDisk: Optional[
            io__k8s__api__core__v1__GCEPersistentDiskVolumeSource
        ] = None,
        glusterfs: Optional[
            io__k8s__api__core__v1__GlusterfsPersistentVolumeSource
        ] = None,
        hostPath: Optional[io__k8s__api__core__v1__HostPathVolumeSource] = None,
        iscsi: Optional[io__k8s__api__core__v1__ISCSIPersistentVolumeSource] = None,
        local: Optional[io__k8s__api__core__v1__LocalVolumeSource] = None,
        mountOptions: Optional[List[str]] = None,
        nfs: Optional[io__k8s__api__core__v1__NFSVolumeSource] = None,
        nodeAffinity: Optional[io__k8s__api__core__v1__VolumeNodeAffinity] = None,
        persistentVolumeReclaimPolicy: Optional[str] = None,
        photonPersistentDisk: Optional[
            io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource
        ] = None,
        portworxVolume: Optional[io__k8s__api__core__v1__PortworxVolumeSource] = None,
        quobyte: Optional[io__k8s__api__core__v1__QuobyteVolumeSource] = None,
        rbd: Optional[io__k8s__api__core__v1__RBDPersistentVolumeSource] = None,
        scaleIO: Optional[io__k8s__api__core__v1__ScaleIOPersistentVolumeSource] = None,
        storageClassName: Optional[str] = None,
        storageos: Optional[
            io__k8s__api__core__v1__StorageOSPersistentVolumeSource
        ] = None,
        volumeMode: Optional[str] = None,
        vsphereVolume: Optional[
            io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource
        ] = None,
    ):
        super().__init__()
        if accessModes is not None:
            self.accessModes = accessModes
        if awsElasticBlockStore is not None:
            self.awsElasticBlockStore = awsElasticBlockStore
        if azureDisk is not None:
            self.azureDisk = azureDisk
        if azureFile is not None:
            self.azureFile = azureFile
        if capacity is not None:
            self.capacity = capacity
        if cephfs is not None:
            self.cephfs = cephfs
        if cinder is not None:
            self.cinder = cinder
        if claimRef is not None:
            self.claimRef = claimRef
        if csi is not None:
            self.csi = csi
        if fc is not None:
            self.fc = fc
        if flexVolume is not None:
            self.flexVolume = flexVolume
        if flocker is not None:
            self.flocker = flocker
        if gcePersistentDisk is not None:
            self.gcePersistentDisk = gcePersistentDisk
        if glusterfs is not None:
            self.glusterfs = glusterfs
        if hostPath is not None:
            self.hostPath = hostPath
        if iscsi is not None:
            self.iscsi = iscsi
        if local is not None:
            self.local = local
        if mountOptions is not None:
            self.mountOptions = mountOptions
        if nfs is not None:
            self.nfs = nfs
        if nodeAffinity is not None:
            self.nodeAffinity = nodeAffinity
        if persistentVolumeReclaimPolicy is not None:
            self.persistentVolumeReclaimPolicy = persistentVolumeReclaimPolicy
        if photonPersistentDisk is not None:
            self.photonPersistentDisk = photonPersistentDisk
        if portworxVolume is not None:
            self.portworxVolume = portworxVolume
        if quobyte is not None:
            self.quobyte = quobyte
        if rbd is not None:
            self.rbd = rbd
        if scaleIO is not None:
            self.scaleIO = scaleIO
        if storageClassName is not None:
            self.storageClassName = storageClassName
        if storageos is not None:
            self.storageos = storageos
        if volumeMode is not None:
            self.volumeMode = volumeMode
        if vsphereVolume is not None:
            self.vsphereVolume = vsphereVolume


class io__k8s__api__core__v1__PodAffinityTerm(K8STemplatable):
    """Defines a set of pods (namely those matching the labelSelector relative to the given namespace(s)) that this pod should be co-located (affinity) or not co-located (anti-affinity) with, where co-located is defined as running on a node whose value of the label with key <topologyKey> matches that of any node on which a pod of the set of pods is running"""

    props: List[str] = [
        "labelSelector",
        "namespaceSelector",
        "namespaces",
        "topologyKey",
    ]
    required_props: List[str] = ["topologyKey"]

    labelSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    namespaceSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    namespaces: Optional[List[str]] = None
    topologyKey: str

    def __init__(
        self,
        topologyKey: str,
        labelSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        namespaceSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        namespaces: Optional[List[str]] = None,
    ):
        super().__init__()
        if topologyKey is not None:
            self.topologyKey = topologyKey
        if labelSelector is not None:
            self.labelSelector = labelSelector
        if namespaceSelector is not None:
            self.namespaceSelector = namespaceSelector
        if namespaces is not None:
            self.namespaces = namespaces


class io__k8s__api__core__v1__PodStatus(K8STemplatable):
    """PodStatus represents information about the status of a pod. Status may trail the actual state of a system, especially if the node that hosts the pod cannot contact the control plane."""

    props: List[str] = [
        "conditions",
        "containerStatuses",
        "ephemeralContainerStatuses",
        "hostIP",
        "initContainerStatuses",
        "message",
        "nominatedNodeName",
        "phase",
        "podIP",
        "podIPs",
        "qosClass",
        "reason",
        "startTime",
    ]
    required_props: List[str] = []

    conditions: Optional[List[io__k8s__api__core__v1__PodCondition]] = None
    containerStatuses: Optional[List[io__k8s__api__core__v1__ContainerStatus]] = None
    ephemeralContainerStatuses: Optional[
        List[io__k8s__api__core__v1__ContainerStatus]
    ] = None
    hostIP: Optional[str] = None
    initContainerStatuses: Optional[
        List[io__k8s__api__core__v1__ContainerStatus]
    ] = None
    message: Optional[str] = None
    nominatedNodeName: Optional[str] = None
    phase: Optional[str] = None
    podIP: Optional[str] = None
    podIPs: Optional[List[io__k8s__api__core__v1__PodIP]] = None
    qosClass: Optional[str] = None
    reason: Optional[str] = None
    startTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None

    def __init__(
        self,
        conditions: Optional[List[io__k8s__api__core__v1__PodCondition]] = None,
        containerStatuses: Optional[
            List[io__k8s__api__core__v1__ContainerStatus]
        ] = None,
        ephemeralContainerStatuses: Optional[
            List[io__k8s__api__core__v1__ContainerStatus]
        ] = None,
        hostIP: Optional[str] = None,
        initContainerStatuses: Optional[
            List[io__k8s__api__core__v1__ContainerStatus]
        ] = None,
        message: Optional[str] = None,
        nominatedNodeName: Optional[str] = None,
        phase: Optional[str] = None,
        podIP: Optional[str] = None,
        podIPs: Optional[List[io__k8s__api__core__v1__PodIP]] = None,
        qosClass: Optional[str] = None,
        reason: Optional[str] = None,
        startTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions
        if containerStatuses is not None:
            self.containerStatuses = containerStatuses
        if ephemeralContainerStatuses is not None:
            self.ephemeralContainerStatuses = ephemeralContainerStatuses
        if hostIP is not None:
            self.hostIP = hostIP
        if initContainerStatuses is not None:
            self.initContainerStatuses = initContainerStatuses
        if message is not None:
            self.message = message
        if nominatedNodeName is not None:
            self.nominatedNodeName = nominatedNodeName
        if phase is not None:
            self.phase = phase
        if podIP is not None:
            self.podIP = podIP
        if podIPs is not None:
            self.podIPs = podIPs
        if qosClass is not None:
            self.qosClass = qosClass
        if reason is not None:
            self.reason = reason
        if startTime is not None:
            self.startTime = startTime


class io__k8s__api__core__v1__Probe(K8STemplatable):
    """Probe describes a health check to be performed against a container to determine whether it is alive or ready to receive traffic."""

    props: List[str] = [
        "exec",
        "failureThreshold",
        "grpc",
        "httpGet",
        "initialDelaySeconds",
        "periodSeconds",
        "successThreshold",
        "tcpSocket",
        "terminationGracePeriodSeconds",
        "timeoutSeconds",
    ]
    required_props: List[str] = []

    exec: Optional[io__k8s__api__core__v1__ExecAction] = None
    failureThreshold: Optional[int] = None
    grpc: Optional[io__k8s__api__core__v1__GRPCAction] = None
    httpGet: Optional[io__k8s__api__core__v1__HTTPGetAction] = None
    initialDelaySeconds: Optional[int] = None
    periodSeconds: Optional[int] = None
    successThreshold: Optional[int] = None
    tcpSocket: Optional[io__k8s__api__core__v1__TCPSocketAction] = None
    terminationGracePeriodSeconds: Optional[int] = None
    timeoutSeconds: Optional[int] = None

    def __init__(
        self,
        exec: Optional[io__k8s__api__core__v1__ExecAction] = None,
        failureThreshold: Optional[int] = None,
        grpc: Optional[io__k8s__api__core__v1__GRPCAction] = None,
        httpGet: Optional[io__k8s__api__core__v1__HTTPGetAction] = None,
        initialDelaySeconds: Optional[int] = None,
        periodSeconds: Optional[int] = None,
        successThreshold: Optional[int] = None,
        tcpSocket: Optional[io__k8s__api__core__v1__TCPSocketAction] = None,
        terminationGracePeriodSeconds: Optional[int] = None,
        timeoutSeconds: Optional[int] = None,
    ):
        super().__init__()
        if exec is not None:
            self.exec = exec
        if failureThreshold is not None:
            self.failureThreshold = failureThreshold
        if grpc is not None:
            self.grpc = grpc
        if httpGet is not None:
            self.httpGet = httpGet
        if initialDelaySeconds is not None:
            self.initialDelaySeconds = initialDelaySeconds
        if periodSeconds is not None:
            self.periodSeconds = periodSeconds
        if successThreshold is not None:
            self.successThreshold = successThreshold
        if tcpSocket is not None:
            self.tcpSocket = tcpSocket
        if terminationGracePeriodSeconds is not None:
            self.terminationGracePeriodSeconds = terminationGracePeriodSeconds
        if timeoutSeconds is not None:
            self.timeoutSeconds = timeoutSeconds


class io__k8s__api__core__v1__ResourceQuotaSpec(K8STemplatable):
    """ResourceQuotaSpec defines the desired hard limits to enforce for Quota."""

    props: List[str] = ["hard", "scopeSelector", "scopes"]
    required_props: List[str] = []

    hard: Any
    scopeSelector: Optional[io__k8s__api__core__v1__ScopeSelector] = None
    scopes: Optional[List[str]] = None

    def __init__(
        self,
        hard: Any = None,
        scopeSelector: Optional[io__k8s__api__core__v1__ScopeSelector] = None,
        scopes: Optional[List[str]] = None,
    ):
        super().__init__()
        if hard is not None:
            self.hard = hard
        if scopeSelector is not None:
            self.scopeSelector = scopeSelector
        if scopes is not None:
            self.scopes = scopes


class io__k8s__api__core__v1__Secret(K8STemplatable):
    """Secret holds secret data of a certain type. The total bytes of the values in the Data field must be less than MaxSecretSize bytes."""

    apiVersion: str = "v1"
    kind: str = "Secret"

    props: List[str] = [
        "apiVersion",
        "data",
        "immutable",
        "kind",
        "metadata",
        "stringData",
        "type",
    ]
    required_props: List[str] = []

    data: Any
    immutable: Optional[bool] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    stringData: Any
    type: Optional[str] = None

    def __init__(
        self,
        data: Any = None,
        immutable: Optional[bool] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        stringData: Any = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if data is not None:
            self.data = data
        if immutable is not None:
            self.immutable = immutable
        if metadata is not None:
            self.metadata = metadata
        if stringData is not None:
            self.stringData = stringData
        if type is not None:
            self.type = type


class io__k8s__api__core__v1__SecretList(K8STemplatable):
    """SecretList is a list of Secret."""

    apiVersion: str = "v1"
    kind: str = "SecretList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Secret]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Secret],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ServiceAccount(K8STemplatable):
    """ServiceAccount binds together: * a name, understood by users, and perhaps by peripheral systems, for an identity * a principal that can be authenticated and authorized * a set of secrets"""

    apiVersion: str = "v1"
    kind: str = "ServiceAccount"

    props: List[str] = [
        "apiVersion",
        "automountServiceAccountToken",
        "imagePullSecrets",
        "kind",
        "metadata",
        "secrets",
    ]
    required_props: List[str] = []

    automountServiceAccountToken: Optional[bool] = None
    imagePullSecrets: Optional[
        List[io__k8s__api__core__v1__LocalObjectReference]
    ] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    secrets: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None

    def __init__(
        self,
        automountServiceAccountToken: Optional[bool] = None,
        imagePullSecrets: Optional[
            List[io__k8s__api__core__v1__LocalObjectReference]
        ] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        secrets: Optional[List[io__k8s__api__core__v1__ObjectReference]] = None,
    ):
        super().__init__()
        if automountServiceAccountToken is not None:
            self.automountServiceAccountToken = automountServiceAccountToken
        if imagePullSecrets is not None:
            self.imagePullSecrets = imagePullSecrets
        if metadata is not None:
            self.metadata = metadata
        if secrets is not None:
            self.secrets = secrets


class io__k8s__api__core__v1__ServiceAccountList(K8STemplatable):
    """ServiceAccountList is a list of ServiceAccount objects"""

    apiVersion: str = "v1"
    kind: str = "ServiceAccountList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__ServiceAccount]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__ServiceAccount],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ServiceStatus(K8STemplatable):
    """ServiceStatus represents the current status of a service."""

    props: List[str] = ["conditions", "loadBalancer"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
    ] = None
    loadBalancer: Optional[io__k8s__api__core__v1__LoadBalancerStatus] = None

    def __init__(
        self,
        conditions: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
        ] = None,
        loadBalancer: Optional[io__k8s__api__core__v1__LoadBalancerStatus] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions
        if loadBalancer is not None:
            self.loadBalancer = loadBalancer


class io__k8s__api__core__v1__TopologySpreadConstraint(K8STemplatable):
    """TopologySpreadConstraint specifies how to spread matching pods among the given topology."""

    props: List[str] = [
        "labelSelector",
        "maxSkew",
        "minDomains",
        "topologyKey",
        "whenUnsatisfiable",
    ]
    required_props: List[str] = ["maxSkew", "topologyKey", "whenUnsatisfiable"]

    labelSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    maxSkew: int
    minDomains: Optional[int] = None
    topologyKey: str
    whenUnsatisfiable: str

    def __init__(
        self,
        maxSkew: int,
        topologyKey: str,
        whenUnsatisfiable: str,
        labelSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        minDomains: Optional[int] = None,
    ):
        super().__init__()
        if maxSkew is not None:
            self.maxSkew = maxSkew
        if topologyKey is not None:
            self.topologyKey = topologyKey
        if whenUnsatisfiable is not None:
            self.whenUnsatisfiable = whenUnsatisfiable
        if labelSelector is not None:
            self.labelSelector = labelSelector
        if minDomains is not None:
            self.minDomains = minDomains


class io__k8s__api__core__v1__WeightedPodAffinityTerm(K8STemplatable):
    """The weights of all of the matched WeightedPodAffinityTerm fields are added per-node to find the most preferred node(s)"""

    props: List[str] = ["podAffinityTerm", "weight"]
    required_props: List[str] = ["weight", "podAffinityTerm"]

    podAffinityTerm: io__k8s__api__core__v1__PodAffinityTerm
    weight: int

    def __init__(
        self, podAffinityTerm: io__k8s__api__core__v1__PodAffinityTerm, weight: int
    ):
        super().__init__()
        if podAffinityTerm is not None:
            self.podAffinityTerm = podAffinityTerm
        if weight is not None:
            self.weight = weight


class io__k8s__api__discovery__v1__Endpoint(K8STemplatable):
    """Endpoint represents a single logical "backend" implementing a service."""

    props: List[str] = [
        "addresses",
        "conditions",
        "deprecatedTopology",
        "hints",
        "hostname",
        "nodeName",
        "targetRef",
        "zone",
    ]
    required_props: List[str] = ["addresses"]

    addresses: List[str]
    conditions: Optional[io__k8s__api__discovery__v1__EndpointConditions] = None
    deprecatedTopology: Any
    hints: Optional[io__k8s__api__discovery__v1__EndpointHints] = None
    hostname: Optional[str] = None
    nodeName: Optional[str] = None
    targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None
    zone: Optional[str] = None

    def __init__(
        self,
        addresses: List[str],
        conditions: Optional[io__k8s__api__discovery__v1__EndpointConditions] = None,
        deprecatedTopology: Any = None,
        hints: Optional[io__k8s__api__discovery__v1__EndpointHints] = None,
        hostname: Optional[str] = None,
        nodeName: Optional[str] = None,
        targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        zone: Optional[str] = None,
    ):
        super().__init__()
        if addresses is not None:
            self.addresses = addresses
        if conditions is not None:
            self.conditions = conditions
        if deprecatedTopology is not None:
            self.deprecatedTopology = deprecatedTopology
        if hints is not None:
            self.hints = hints
        if hostname is not None:
            self.hostname = hostname
        if nodeName is not None:
            self.nodeName = nodeName
        if targetRef is not None:
            self.targetRef = targetRef
        if zone is not None:
            self.zone = zone


class io__k8s__api__discovery__v1__EndpointSlice(K8STemplatable):
    """EndpointSlice represents a subset of the endpoints that implement a service. For a given service there may be multiple EndpointSlice objects, selected by labels, which must be joined to produce the full set of endpoints."""

    apiVersion: str = "discovery.k8s.io/v1"
    kind: str = "EndpointSlice"

    props: List[str] = [
        "addressType",
        "apiVersion",
        "endpoints",
        "kind",
        "metadata",
        "ports",
    ]
    required_props: List[str] = ["addressType", "endpoints"]

    addressType: str
    endpoints: List[io__k8s__api__discovery__v1__Endpoint]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    ports: Optional[List[io__k8s__api__discovery__v1__EndpointPort]] = None

    def __init__(
        self,
        addressType: str,
        endpoints: List[io__k8s__api__discovery__v1__Endpoint],
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        ports: Optional[List[io__k8s__api__discovery__v1__EndpointPort]] = None,
    ):
        super().__init__()
        if addressType is not None:
            self.addressType = addressType
        if endpoints is not None:
            self.endpoints = endpoints
        if metadata is not None:
            self.metadata = metadata
        if ports is not None:
            self.ports = ports


class io__k8s__api__discovery__v1__EndpointSliceList(K8STemplatable):
    """EndpointSliceList represents a list of endpoint slices"""

    apiVersion: str = "discovery.k8s.io/v1"
    kind: str = "EndpointSliceList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__discovery__v1__EndpointSlice]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__discovery__v1__EndpointSlice],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__discovery__v1beta1__Endpoint(K8STemplatable):
    """Endpoint represents a single logical "backend" implementing a service."""

    props: List[str] = [
        "addresses",
        "conditions",
        "hints",
        "hostname",
        "nodeName",
        "targetRef",
        "topology",
    ]
    required_props: List[str] = ["addresses"]

    addresses: List[str]
    conditions: Optional[io__k8s__api__discovery__v1beta1__EndpointConditions] = None
    hints: Optional[io__k8s__api__discovery__v1beta1__EndpointHints] = None
    hostname: Optional[str] = None
    nodeName: Optional[str] = None
    targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None
    topology: Any

    def __init__(
        self,
        addresses: List[str],
        conditions: Optional[
            io__k8s__api__discovery__v1beta1__EndpointConditions
        ] = None,
        hints: Optional[io__k8s__api__discovery__v1beta1__EndpointHints] = None,
        hostname: Optional[str] = None,
        nodeName: Optional[str] = None,
        targetRef: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        topology: Any = None,
    ):
        super().__init__()
        if addresses is not None:
            self.addresses = addresses
        if conditions is not None:
            self.conditions = conditions
        if hints is not None:
            self.hints = hints
        if hostname is not None:
            self.hostname = hostname
        if nodeName is not None:
            self.nodeName = nodeName
        if targetRef is not None:
            self.targetRef = targetRef
        if topology is not None:
            self.topology = topology


class io__k8s__api__discovery__v1beta1__EndpointSlice(K8STemplatable):
    """EndpointSlice represents a subset of the endpoints that implement a service. For a given service there may be multiple EndpointSlice objects, selected by labels, which must be joined to produce the full set of endpoints."""

    apiVersion: str = "discovery.k8s.io/v1beta1"
    kind: str = "EndpointSlice"

    props: List[str] = [
        "addressType",
        "apiVersion",
        "endpoints",
        "kind",
        "metadata",
        "ports",
    ]
    required_props: List[str] = ["addressType", "endpoints"]

    addressType: str
    endpoints: List[io__k8s__api__discovery__v1beta1__Endpoint]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    ports: Optional[List[io__k8s__api__discovery__v1beta1__EndpointPort]] = None

    def __init__(
        self,
        addressType: str,
        endpoints: List[io__k8s__api__discovery__v1beta1__Endpoint],
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        ports: Optional[List[io__k8s__api__discovery__v1beta1__EndpointPort]] = None,
    ):
        super().__init__()
        if addressType is not None:
            self.addressType = addressType
        if endpoints is not None:
            self.endpoints = endpoints
        if metadata is not None:
            self.metadata = metadata
        if ports is not None:
            self.ports = ports


class io__k8s__api__discovery__v1beta1__EndpointSliceList(K8STemplatable):
    """EndpointSliceList represents a list of endpoint slices"""

    apiVersion: str = "discovery.k8s.io/v1beta1"
    kind: str = "EndpointSliceList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__discovery__v1beta1__EndpointSlice]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__discovery__v1beta1__EndpointSlice],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__events__v1__Event(K8STemplatable):
    """Event is a report of an event somewhere in the cluster. It generally denotes some state change in the system. Events have a limited retention time and triggers and messages may evolve with time.  Event consumers should not rely on the timing of an event with a given Reason reflecting a consistent underlying trigger, or the continued existence of events with that Reason.  Events should be treated as informative, best-effort, supplemental data."""

    apiVersion: str = "events.k8s.io/v1"
    kind: str = "Event"

    props: List[str] = [
        "action",
        "apiVersion",
        "deprecatedCount",
        "deprecatedFirstTimestamp",
        "deprecatedLastTimestamp",
        "deprecatedSource",
        "eventTime",
        "kind",
        "metadata",
        "note",
        "reason",
        "regarding",
        "related",
        "reportingController",
        "reportingInstance",
        "series",
        "type",
    ]
    required_props: List[str] = ["eventTime"]

    action: Optional[str] = None
    deprecatedCount: Optional[int] = None
    deprecatedFirstTimestamp: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    deprecatedLastTimestamp: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    deprecatedSource: Optional[io__k8s__api__core__v1__EventSource] = None
    eventTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    note: Optional[str] = None
    reason: Optional[str] = None
    regarding: Optional[io__k8s__api__core__v1__ObjectReference] = None
    related: Optional[io__k8s__api__core__v1__ObjectReference] = None
    reportingController: Optional[str] = None
    reportingInstance: Optional[str] = None
    series: Optional[io__k8s__api__events__v1__EventSeries] = None
    type: Optional[str] = None

    def __init__(
        self,
        eventTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime,
        action: Optional[str] = None,
        deprecatedCount: Optional[int] = None,
        deprecatedFirstTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        deprecatedLastTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        deprecatedSource: Optional[io__k8s__api__core__v1__EventSource] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        note: Optional[str] = None,
        reason: Optional[str] = None,
        regarding: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        related: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        reportingController: Optional[str] = None,
        reportingInstance: Optional[str] = None,
        series: Optional[io__k8s__api__events__v1__EventSeries] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if eventTime is not None:
            self.eventTime = eventTime
        if action is not None:
            self.action = action
        if deprecatedCount is not None:
            self.deprecatedCount = deprecatedCount
        if deprecatedFirstTimestamp is not None:
            self.deprecatedFirstTimestamp = deprecatedFirstTimestamp
        if deprecatedLastTimestamp is not None:
            self.deprecatedLastTimestamp = deprecatedLastTimestamp
        if deprecatedSource is not None:
            self.deprecatedSource = deprecatedSource
        if metadata is not None:
            self.metadata = metadata
        if note is not None:
            self.note = note
        if reason is not None:
            self.reason = reason
        if regarding is not None:
            self.regarding = regarding
        if related is not None:
            self.related = related
        if reportingController is not None:
            self.reportingController = reportingController
        if reportingInstance is not None:
            self.reportingInstance = reportingInstance
        if series is not None:
            self.series = series
        if type is not None:
            self.type = type


class io__k8s__api__events__v1__EventList(K8STemplatable):
    """EventList is a list of Event objects."""

    apiVersion: str = "events.k8s.io/v1"
    kind: str = "EventList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__events__v1__Event]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__events__v1__Event],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__events__v1beta1__Event(K8STemplatable):
    """Event is a report of an event somewhere in the cluster. It generally denotes some state change in the system. Events have a limited retention time and triggers and messages may evolve with time.  Event consumers should not rely on the timing of an event with a given Reason reflecting a consistent underlying trigger, or the continued existence of events with that Reason.  Events should be treated as informative, best-effort, supplemental data."""

    apiVersion: str = "events.k8s.io/v1beta1"
    kind: str = "Event"

    props: List[str] = [
        "action",
        "apiVersion",
        "deprecatedCount",
        "deprecatedFirstTimestamp",
        "deprecatedLastTimestamp",
        "deprecatedSource",
        "eventTime",
        "kind",
        "metadata",
        "note",
        "reason",
        "regarding",
        "related",
        "reportingController",
        "reportingInstance",
        "series",
        "type",
    ]
    required_props: List[str] = ["eventTime"]

    action: Optional[str] = None
    deprecatedCount: Optional[int] = None
    deprecatedFirstTimestamp: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    deprecatedLastTimestamp: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__Time
    ] = None
    deprecatedSource: Optional[io__k8s__api__core__v1__EventSource] = None
    eventTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    note: Optional[str] = None
    reason: Optional[str] = None
    regarding: Optional[io__k8s__api__core__v1__ObjectReference] = None
    related: Optional[io__k8s__api__core__v1__ObjectReference] = None
    reportingController: Optional[str] = None
    reportingInstance: Optional[str] = None
    series: Optional[io__k8s__api__events__v1beta1__EventSeries] = None
    type: Optional[str] = None

    def __init__(
        self,
        eventTime: io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime,
        action: Optional[str] = None,
        deprecatedCount: Optional[int] = None,
        deprecatedFirstTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        deprecatedLastTimestamp: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        deprecatedSource: Optional[io__k8s__api__core__v1__EventSource] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        note: Optional[str] = None,
        reason: Optional[str] = None,
        regarding: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        related: Optional[io__k8s__api__core__v1__ObjectReference] = None,
        reportingController: Optional[str] = None,
        reportingInstance: Optional[str] = None,
        series: Optional[io__k8s__api__events__v1beta1__EventSeries] = None,
        type: Optional[str] = None,
    ):
        super().__init__()
        if eventTime is not None:
            self.eventTime = eventTime
        if action is not None:
            self.action = action
        if deprecatedCount is not None:
            self.deprecatedCount = deprecatedCount
        if deprecatedFirstTimestamp is not None:
            self.deprecatedFirstTimestamp = deprecatedFirstTimestamp
        if deprecatedLastTimestamp is not None:
            self.deprecatedLastTimestamp = deprecatedLastTimestamp
        if deprecatedSource is not None:
            self.deprecatedSource = deprecatedSource
        if metadata is not None:
            self.metadata = metadata
        if note is not None:
            self.note = note
        if reason is not None:
            self.reason = reason
        if regarding is not None:
            self.regarding = regarding
        if related is not None:
            self.related = related
        if reportingController is not None:
            self.reportingController = reportingController
        if reportingInstance is not None:
            self.reportingInstance = reportingInstance
        if series is not None:
            self.series = series
        if type is not None:
            self.type = type


class io__k8s__api__events__v1beta1__EventList(K8STemplatable):
    """EventList is a list of Event objects."""

    apiVersion: str = "events.k8s.io/v1beta1"
    kind: str = "EventList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__events__v1beta1__Event]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__events__v1beta1__Event],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__flowcontrol__v1beta1__PolicyRulesWithSubjects(K8STemplatable):
    """PolicyRulesWithSubjects prescribes a test that applies to a request to an apiserver. The test considers the subject making the request, the verb being requested, and the resource to be acted upon. This PolicyRulesWithSubjects matches a request if and only if both (a) at least one member of subjects matches the request and (b) at least one member of resourceRules or nonResourceRules matches the request."""

    props: List[str] = ["nonResourceRules", "resourceRules", "subjects"]
    required_props: List[str] = ["subjects"]

    nonResourceRules: Optional[
        List[io__k8s__api__flowcontrol__v1beta1__NonResourcePolicyRule]
    ] = None
    resourceRules: Optional[
        List[io__k8s__api__flowcontrol__v1beta1__ResourcePolicyRule]
    ] = None
    subjects: List[io__k8s__api__flowcontrol__v1beta1__Subject]

    def __init__(
        self,
        subjects: List[io__k8s__api__flowcontrol__v1beta1__Subject],
        nonResourceRules: Optional[
            List[io__k8s__api__flowcontrol__v1beta1__NonResourcePolicyRule]
        ] = None,
        resourceRules: Optional[
            List[io__k8s__api__flowcontrol__v1beta1__ResourcePolicyRule]
        ] = None,
    ):
        super().__init__()
        if subjects is not None:
            self.subjects = subjects
        if nonResourceRules is not None:
            self.nonResourceRules = nonResourceRules
        if resourceRules is not None:
            self.resourceRules = resourceRules


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfiguration(K8STemplatable):
    """PriorityLevelConfiguration represents the configuration of a priority level."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta1"
    kind: str = "PriorityLevelConfiguration"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[
        io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationSpec
    ] = None
    status: Optional[
        io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationSpec
        ] = None,
        status: Optional[
            io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationList(
    K8STemplatable
):
    """PriorityLevelConfigurationList is a list of PriorityLevelConfiguration objects."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta1"
    kind: str = "PriorityLevelConfigurationList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfiguration]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfiguration],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__flowcontrol__v1beta2__PolicyRulesWithSubjects(K8STemplatable):
    """PolicyRulesWithSubjects prescribes a test that applies to a request to an apiserver. The test considers the subject making the request, the verb being requested, and the resource to be acted upon. This PolicyRulesWithSubjects matches a request if and only if both (a) at least one member of subjects matches the request and (b) at least one member of resourceRules or nonResourceRules matches the request."""

    props: List[str] = ["nonResourceRules", "resourceRules", "subjects"]
    required_props: List[str] = ["subjects"]

    nonResourceRules: Optional[
        List[io__k8s__api__flowcontrol__v1beta2__NonResourcePolicyRule]
    ] = None
    resourceRules: Optional[
        List[io__k8s__api__flowcontrol__v1beta2__ResourcePolicyRule]
    ] = None
    subjects: List[io__k8s__api__flowcontrol__v1beta2__Subject]

    def __init__(
        self,
        subjects: List[io__k8s__api__flowcontrol__v1beta2__Subject],
        nonResourceRules: Optional[
            List[io__k8s__api__flowcontrol__v1beta2__NonResourcePolicyRule]
        ] = None,
        resourceRules: Optional[
            List[io__k8s__api__flowcontrol__v1beta2__ResourcePolicyRule]
        ] = None,
    ):
        super().__init__()
        if subjects is not None:
            self.subjects = subjects
        if nonResourceRules is not None:
            self.nonResourceRules = nonResourceRules
        if resourceRules is not None:
            self.resourceRules = resourceRules


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfiguration(K8STemplatable):
    """PriorityLevelConfiguration represents the configuration of a priority level."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta2"
    kind: str = "PriorityLevelConfiguration"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[
        io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationSpec
    ] = None
    status: Optional[
        io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationSpec
        ] = None,
        status: Optional[
            io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationList(
    K8STemplatable
):
    """PriorityLevelConfigurationList is a list of PriorityLevelConfiguration objects."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta2"
    kind: str = "PriorityLevelConfigurationList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfiguration]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfiguration],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__networking__v1__IngressBackend(K8STemplatable):
    """IngressBackend describes all endpoints for a given service and port."""

    props: List[str] = ["resource", "service"]
    required_props: List[str] = []

    resource: Optional[io__k8s__api__core__v1__TypedLocalObjectReference] = None
    service: Optional[io__k8s__api__networking__v1__IngressServiceBackend] = None

    def __init__(
        self,
        resource: Optional[io__k8s__api__core__v1__TypedLocalObjectReference] = None,
        service: Optional[io__k8s__api__networking__v1__IngressServiceBackend] = None,
    ):
        super().__init__()
        if resource is not None:
            self.resource = resource
        if service is not None:
            self.service = service


class io__k8s__api__networking__v1__IngressClass(K8STemplatable):
    """IngressClass represents the class of the Ingress, referenced by the Ingress Spec. The `ingressclass.kubernetes.io/is-default-class` annotation can be used to indicate that an IngressClass should be considered default. When a single IngressClass resource has this annotation set to true, new Ingress resources without a class specified will be assigned this default class."""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "IngressClass"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__networking__v1__IngressClassSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__networking__v1__IngressClassSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__networking__v1__IngressClassList(K8STemplatable):
    """IngressClassList is a collection of IngressClasses."""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "IngressClassList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__networking__v1__IngressClass]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__networking__v1__IngressClass],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__networking__v1__NetworkPolicyPeer(K8STemplatable):
    """NetworkPolicyPeer describes a peer to allow traffic to/from. Only certain combinations of fields are allowed"""

    props: List[str] = ["ipBlock", "namespaceSelector", "podSelector"]
    required_props: List[str] = []

    ipBlock: Optional[io__k8s__api__networking__v1__IPBlock] = None
    namespaceSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    podSelector: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None

    def __init__(
        self,
        ipBlock: Optional[io__k8s__api__networking__v1__IPBlock] = None,
        namespaceSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        podSelector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if ipBlock is not None:
            self.ipBlock = ipBlock
        if namespaceSelector is not None:
            self.namespaceSelector = namespaceSelector
        if podSelector is not None:
            self.podSelector = podSelector


class io__k8s__api__networking__v1__NetworkPolicyStatus(K8STemplatable):
    """NetworkPolicyStatus describe the current state of the NetworkPolicy."""

    props: List[str] = ["conditions"]
    required_props: List[str] = []

    conditions: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
    ] = None

    def __init__(
        self,
        conditions: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
        ] = None,
    ):
        super().__init__()
        if conditions is not None:
            self.conditions = conditions


class io__k8s__api__node__v1__RuntimeClass(K8STemplatable):
    """RuntimeClass defines a class of container runtime supported in the cluster. The RuntimeClass is used to determine which container runtime is used to run all containers in a pod. RuntimeClasses are manually defined by a user or cluster provisioner, and referenced in the PodSpec. The Kubelet is responsible for resolving the RuntimeClassName reference before running the pod.  For more details, see https://kubernetes.io/docs/concepts/containers/runtime-class/"""

    apiVersion: str = "node.k8s.io/v1"
    kind: str = "RuntimeClass"

    props: List[str] = [
        "apiVersion",
        "handler",
        "kind",
        "metadata",
        "overhead",
        "scheduling",
    ]
    required_props: List[str] = ["handler"]

    handler: str
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    overhead: Optional[io__k8s__api__node__v1__Overhead] = None
    scheduling: Optional[io__k8s__api__node__v1__Scheduling] = None

    def __init__(
        self,
        handler: str,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        overhead: Optional[io__k8s__api__node__v1__Overhead] = None,
        scheduling: Optional[io__k8s__api__node__v1__Scheduling] = None,
    ):
        super().__init__()
        if handler is not None:
            self.handler = handler
        if metadata is not None:
            self.metadata = metadata
        if overhead is not None:
            self.overhead = overhead
        if scheduling is not None:
            self.scheduling = scheduling


class io__k8s__api__node__v1__RuntimeClassList(K8STemplatable):
    """RuntimeClassList is a list of RuntimeClass objects."""

    apiVersion: str = "node.k8s.io/v1"
    kind: str = "RuntimeClassList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__node__v1__RuntimeClass]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__node__v1__RuntimeClass],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__node__v1beta1__RuntimeClass(K8STemplatable):
    """RuntimeClass defines a class of container runtime supported in the cluster. The RuntimeClass is used to determine which container runtime is used to run all containers in a pod. RuntimeClasses are (currently) manually defined by a user or cluster provisioner, and referenced in the PodSpec. The Kubelet is responsible for resolving the RuntimeClassName reference before running the pod.  For more details, see https://git.k8s.io/enhancements/keps/sig-node/585-runtime-class"""

    apiVersion: str = "node.k8s.io/v1beta1"
    kind: str = "RuntimeClass"

    props: List[str] = [
        "apiVersion",
        "handler",
        "kind",
        "metadata",
        "overhead",
        "scheduling",
    ]
    required_props: List[str] = ["handler"]

    handler: str
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    overhead: Optional[io__k8s__api__node__v1beta1__Overhead] = None
    scheduling: Optional[io__k8s__api__node__v1beta1__Scheduling] = None

    def __init__(
        self,
        handler: str,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        overhead: Optional[io__k8s__api__node__v1beta1__Overhead] = None,
        scheduling: Optional[io__k8s__api__node__v1beta1__Scheduling] = None,
    ):
        super().__init__()
        if handler is not None:
            self.handler = handler
        if metadata is not None:
            self.metadata = metadata
        if overhead is not None:
            self.overhead = overhead
        if scheduling is not None:
            self.scheduling = scheduling


class io__k8s__api__node__v1beta1__RuntimeClassList(K8STemplatable):
    """RuntimeClassList is a list of RuntimeClass objects."""

    apiVersion: str = "node.k8s.io/v1beta1"
    kind: str = "RuntimeClassList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__node__v1beta1__RuntimeClass]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__node__v1beta1__RuntimeClass],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__policy__v1__Eviction(K8STemplatable):
    """Eviction evicts a pod from its node subject to certain policies and safety constraints. This is a subresource of Pod.  A request to cause such an eviction is created by POSTing to .../pods/<pod name>/evictions."""

    apiVersion: str = "policy/v1"
    kind: str = "Eviction"

    props: List[str] = ["apiVersion", "deleteOptions", "kind", "metadata"]
    required_props: List[str] = []

    deleteOptions: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__DeleteOptions
    ] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None

    def __init__(
        self,
        deleteOptions: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__DeleteOptions
        ] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if deleteOptions is not None:
            self.deleteOptions = deleteOptions
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__policy__v1__PodDisruptionBudgetSpec(K8STemplatable):
    """PodDisruptionBudgetSpec is a description of a PodDisruptionBudget."""

    props: List[str] = ["maxUnavailable", "minAvailable", "selector"]
    required_props: List[str] = []

    maxUnavailable: Optional[
        io__k8s__apimachinery__pkg__util__intstr__IntOrString
    ] = None
    minAvailable: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None

    def __init__(
        self,
        maxUnavailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        minAvailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if maxUnavailable is not None:
            self.maxUnavailable = maxUnavailable
        if minAvailable is not None:
            self.minAvailable = minAvailable
        if selector is not None:
            self.selector = selector


class io__k8s__api__policy__v1__PodDisruptionBudgetStatus(K8STemplatable):
    """PodDisruptionBudgetStatus represents information about the status of a PodDisruptionBudget. Status may trail the actual state of a system."""

    props: List[str] = [
        "conditions",
        "currentHealthy",
        "desiredHealthy",
        "disruptedPods",
        "disruptionsAllowed",
        "expectedPods",
        "observedGeneration",
    ]
    required_props: List[str] = [
        "disruptionsAllowed",
        "currentHealthy",
        "desiredHealthy",
        "expectedPods",
    ]

    conditions: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
    ] = None
    currentHealthy: int
    desiredHealthy: int
    disruptedPods: Any
    disruptionsAllowed: int
    expectedPods: int
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        currentHealthy: int,
        desiredHealthy: int,
        disruptionsAllowed: int,
        expectedPods: int,
        conditions: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
        ] = None,
        disruptedPods: Any = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if currentHealthy is not None:
            self.currentHealthy = currentHealthy
        if desiredHealthy is not None:
            self.desiredHealthy = desiredHealthy
        if disruptionsAllowed is not None:
            self.disruptionsAllowed = disruptionsAllowed
        if expectedPods is not None:
            self.expectedPods = expectedPods
        if conditions is not None:
            self.conditions = conditions
        if disruptedPods is not None:
            self.disruptedPods = disruptedPods
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__policy__v1beta1__PodDisruptionBudgetSpec(K8STemplatable):
    """PodDisruptionBudgetSpec is a description of a PodDisruptionBudget."""

    props: List[str] = ["maxUnavailable", "minAvailable", "selector"]
    required_props: List[str] = []

    maxUnavailable: Optional[
        io__k8s__apimachinery__pkg__util__intstr__IntOrString
    ] = None
    minAvailable: Optional[io__k8s__apimachinery__pkg__util__intstr__IntOrString] = None
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None

    def __init__(
        self,
        maxUnavailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        minAvailable: Optional[
            io__k8s__apimachinery__pkg__util__intstr__IntOrString
        ] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if maxUnavailable is not None:
            self.maxUnavailable = maxUnavailable
        if minAvailable is not None:
            self.minAvailable = minAvailable
        if selector is not None:
            self.selector = selector


class io__k8s__api__policy__v1beta1__PodDisruptionBudgetStatus(K8STemplatable):
    """PodDisruptionBudgetStatus represents information about the status of a PodDisruptionBudget. Status may trail the actual state of a system."""

    props: List[str] = [
        "conditions",
        "currentHealthy",
        "desiredHealthy",
        "disruptedPods",
        "disruptionsAllowed",
        "expectedPods",
        "observedGeneration",
    ]
    required_props: List[str] = [
        "disruptionsAllowed",
        "currentHealthy",
        "desiredHealthy",
        "expectedPods",
    ]

    conditions: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
    ] = None
    currentHealthy: int
    desiredHealthy: int
    disruptedPods: Any
    disruptionsAllowed: int
    expectedPods: int
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        currentHealthy: int,
        desiredHealthy: int,
        disruptionsAllowed: int,
        expectedPods: int,
        conditions: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__Condition]
        ] = None,
        disruptedPods: Any = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if currentHealthy is not None:
            self.currentHealthy = currentHealthy
        if desiredHealthy is not None:
            self.desiredHealthy = desiredHealthy
        if disruptionsAllowed is not None:
            self.disruptionsAllowed = disruptionsAllowed
        if expectedPods is not None:
            self.expectedPods = expectedPods
        if conditions is not None:
            self.conditions = conditions
        if disruptedPods is not None:
            self.disruptedPods = disruptedPods
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__policy__v1beta1__PodSecurityPolicy(K8STemplatable):
    """PodSecurityPolicy governs the ability to make requests that affect the Security Context that will be applied to a pod and container. Deprecated in 1.21."""

    apiVersion: str = "policy/v1beta1"
    kind: str = "PodSecurityPolicy"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__policy__v1beta1__PodSecurityPolicySpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__policy__v1beta1__PodSecurityPolicySpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__policy__v1beta1__PodSecurityPolicyList(K8STemplatable):
    """PodSecurityPolicyList is a list of PodSecurityPolicy objects."""

    apiVersion: str = "policy/v1beta1"
    kind: str = "PodSecurityPolicyList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__policy__v1beta1__PodSecurityPolicy]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__policy__v1beta1__PodSecurityPolicy],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__rbac__v1__AggregationRule(K8STemplatable):
    """AggregationRule describes how to locate ClusterRoles to aggregate into the ClusterRole"""

    props: List[str] = ["clusterRoleSelectors"]
    required_props: List[str] = []

    clusterRoleSelectors: Optional[
        List[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector]
    ] = None

    def __init__(
        self,
        clusterRoleSelectors: Optional[
            List[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector]
        ] = None,
    ):
        super().__init__()
        if clusterRoleSelectors is not None:
            self.clusterRoleSelectors = clusterRoleSelectors


class io__k8s__api__rbac__v1__ClusterRole(K8STemplatable):
    """ClusterRole is a cluster level, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding or ClusterRoleBinding."""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "ClusterRole"

    props: List[str] = ["aggregationRule", "apiVersion", "kind", "metadata", "rules"]
    required_props: List[str] = []

    aggregationRule: Optional[io__k8s__api__rbac__v1__AggregationRule] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    rules: Optional[List[io__k8s__api__rbac__v1__PolicyRule]] = None

    def __init__(
        self,
        aggregationRule: Optional[io__k8s__api__rbac__v1__AggregationRule] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        rules: Optional[List[io__k8s__api__rbac__v1__PolicyRule]] = None,
    ):
        super().__init__()
        if aggregationRule is not None:
            self.aggregationRule = aggregationRule
        if metadata is not None:
            self.metadata = metadata
        if rules is not None:
            self.rules = rules


class io__k8s__api__rbac__v1__ClusterRoleBinding(K8STemplatable):
    """ClusterRoleBinding references a ClusterRole, but not contain it.  It can reference a ClusterRole in the global namespace, and adds who information via Subject."""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "ClusterRoleBinding"

    props: List[str] = ["apiVersion", "kind", "metadata", "roleRef", "subjects"]
    required_props: List[str] = ["roleRef"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    roleRef: io__k8s__api__rbac__v1__RoleRef
    subjects: Optional[List[io__k8s__api__rbac__v1__Subject]] = None

    def __init__(
        self,
        roleRef: io__k8s__api__rbac__v1__RoleRef,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        subjects: Optional[List[io__k8s__api__rbac__v1__Subject]] = None,
    ):
        super().__init__()
        if roleRef is not None:
            self.roleRef = roleRef
        if metadata is not None:
            self.metadata = metadata
        if subjects is not None:
            self.subjects = subjects


class io__k8s__api__rbac__v1__ClusterRoleBindingList(K8STemplatable):
    """ClusterRoleBindingList is a collection of ClusterRoleBindings"""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "ClusterRoleBindingList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__rbac__v1__ClusterRoleBinding]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__rbac__v1__ClusterRoleBinding],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__rbac__v1__ClusterRoleList(K8STemplatable):
    """ClusterRoleList is a collection of ClusterRoles"""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "ClusterRoleList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__rbac__v1__ClusterRole]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__rbac__v1__ClusterRole],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__rbac__v1__Role(K8STemplatable):
    """Role is a namespaced, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding."""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "Role"

    props: List[str] = ["apiVersion", "kind", "metadata", "rules"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    rules: Optional[List[io__k8s__api__rbac__v1__PolicyRule]] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        rules: Optional[List[io__k8s__api__rbac__v1__PolicyRule]] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if rules is not None:
            self.rules = rules


class io__k8s__api__rbac__v1__RoleBinding(K8STemplatable):
    """RoleBinding references a role, but does not contain it.  It can reference a Role in the same namespace or a ClusterRole in the global namespace. It adds who information via Subjects and namespace information by which namespace it exists in.  RoleBindings in a given namespace only have effect in that namespace."""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "RoleBinding"

    props: List[str] = ["apiVersion", "kind", "metadata", "roleRef", "subjects"]
    required_props: List[str] = ["roleRef"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    roleRef: io__k8s__api__rbac__v1__RoleRef
    subjects: Optional[List[io__k8s__api__rbac__v1__Subject]] = None

    def __init__(
        self,
        roleRef: io__k8s__api__rbac__v1__RoleRef,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        subjects: Optional[List[io__k8s__api__rbac__v1__Subject]] = None,
    ):
        super().__init__()
        if roleRef is not None:
            self.roleRef = roleRef
        if metadata is not None:
            self.metadata = metadata
        if subjects is not None:
            self.subjects = subjects


class io__k8s__api__rbac__v1__RoleBindingList(K8STemplatable):
    """RoleBindingList is a collection of RoleBindings"""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "RoleBindingList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__rbac__v1__RoleBinding]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__rbac__v1__RoleBinding],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__rbac__v1__RoleList(K8STemplatable):
    """RoleList is a collection of Roles"""

    apiVersion: str = "rbac.authorization.k8s.io/v1"
    kind: str = "RoleList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__rbac__v1__Role]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__rbac__v1__Role],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__scheduling__v1__PriorityClass(K8STemplatable):
    """PriorityClass defines mapping from a priority class name to the priority integer value. The value can be any valid integer."""

    apiVersion: str = "scheduling.k8s.io/v1"
    kind: str = "PriorityClass"

    props: List[str] = [
        "apiVersion",
        "description",
        "globalDefault",
        "kind",
        "metadata",
        "preemptionPolicy",
        "value",
    ]
    required_props: List[str] = ["value"]

    description: Optional[str] = None
    globalDefault: Optional[bool] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    preemptionPolicy: Optional[str] = None
    value: int

    def __init__(
        self,
        value: int,
        description: Optional[str] = None,
        globalDefault: Optional[bool] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        preemptionPolicy: Optional[str] = None,
    ):
        super().__init__()
        if value is not None:
            self.value = value
        if description is not None:
            self.description = description
        if globalDefault is not None:
            self.globalDefault = globalDefault
        if metadata is not None:
            self.metadata = metadata
        if preemptionPolicy is not None:
            self.preemptionPolicy = preemptionPolicy


class io__k8s__api__scheduling__v1__PriorityClassList(K8STemplatable):
    """PriorityClassList is a collection of priority classes."""

    apiVersion: str = "scheduling.k8s.io/v1"
    kind: str = "PriorityClassList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__scheduling__v1__PriorityClass]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__scheduling__v1__PriorityClass],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__CSIDriver(K8STemplatable):
    """CSIDriver captures information about a Container Storage Interface (CSI) volume driver deployed on the cluster. Kubernetes attach detach controller uses this object to determine whether attach is required. Kubelet uses this object to determine whether pod information needs to be passed on mount. CSIDriver objects are non-namespaced."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSIDriver"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__storage__v1__CSIDriverSpec

    def __init__(
        self,
        spec: io__k8s__api__storage__v1__CSIDriverSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__CSIDriverList(K8STemplatable):
    """CSIDriverList is a collection of CSIDriver objects."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSIDriverList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1__CSIDriver]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1__CSIDriver],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__CSINode(K8STemplatable):
    """CSINode holds information about all CSI drivers installed on a node. CSI drivers do not need to create the CSINode object directly. As long as they use the node-driver-registrar sidecar container, the kubelet will automatically populate the CSINode object for the CSI driver as part of kubelet plugin registration. CSINode has the same name as a node. If the object is missing, it means either there are no CSI Drivers available on the node, or the Kubelet version is low enough that it doesn't create this object. CSINode has an OwnerReference that points to the corresponding node object."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSINode"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__storage__v1__CSINodeSpec

    def __init__(
        self,
        spec: io__k8s__api__storage__v1__CSINodeSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__CSINodeList(K8STemplatable):
    """CSINodeList is a collection of CSINode objects."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSINodeList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1__CSINode]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1__CSINode],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__CSIStorageCapacity(K8STemplatable):
    """CSIStorageCapacity stores the result of one CSI GetCapacity call. For a given StorageClass, this describes the available capacity in a particular topology segment.  This can be used when considering where to instantiate new PersistentVolumes.

    For example this can express things like: - StorageClass "standard" has "1234 GiB" available in "topology.kubernetes.io/zone=us-east1" - StorageClass "localssd" has "10 GiB" available in "kubernetes.io/hostname=knode-abc123"

    The following three cases all imply that no capacity is available for a certain combination: - no object exists with suitable topology and storage class name - such an object exists, but the capacity is unset - such an object exists, but the capacity is zero

    The producer of these objects can decide which approach is more suitable.

    They are consumed by the kube-scheduler when a CSI driver opts into capacity-aware scheduling with CSIDriverSpec.StorageCapacity. The scheduler compares the MaximumVolumeSize against the requested size of pending volumes to filter out unsuitable nodes. If MaximumVolumeSize is unset, it falls back to a comparison against the less precise Capacity. If that is also unset, the scheduler assumes that capacity is insufficient and tries some other node."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSIStorageCapacity"

    props: List[str] = [
        "apiVersion",
        "capacity",
        "kind",
        "maximumVolumeSize",
        "metadata",
        "nodeTopology",
        "storageClassName",
    ]
    required_props: List[str] = ["storageClassName"]

    capacity: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    maximumVolumeSize: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    nodeTopology: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    storageClassName: str

    def __init__(
        self,
        storageClassName: str,
        capacity: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
        maximumVolumeSize: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        nodeTopology: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if storageClassName is not None:
            self.storageClassName = storageClassName
        if capacity is not None:
            self.capacity = capacity
        if maximumVolumeSize is not None:
            self.maximumVolumeSize = maximumVolumeSize
        if metadata is not None:
            self.metadata = metadata
        if nodeTopology is not None:
            self.nodeTopology = nodeTopology


class io__k8s__api__storage__v1__CSIStorageCapacityList(K8STemplatable):
    """CSIStorageCapacityList is a collection of CSIStorageCapacity objects."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "CSIStorageCapacityList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1__CSIStorageCapacity]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1__CSIStorageCapacity],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__StorageClass(K8STemplatable):
    """StorageClass describes the parameters for a class of storage for which PersistentVolumes can be dynamically provisioned.

    StorageClasses are non-namespaced; the name of the storage class according to etcd is in ObjectMeta.Name."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "StorageClass"

    props: List[str] = [
        "allowVolumeExpansion",
        "allowedTopologies",
        "apiVersion",
        "kind",
        "metadata",
        "mountOptions",
        "parameters",
        "provisioner",
        "reclaimPolicy",
        "volumeBindingMode",
    ]
    required_props: List[str] = ["provisioner"]

    allowVolumeExpansion: Optional[bool] = None
    allowedTopologies: Optional[
        List[io__k8s__api__core__v1__TopologySelectorTerm]
    ] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    mountOptions: Optional[List[str]] = None
    parameters: Any
    provisioner: str
    reclaimPolicy: Optional[str] = None
    volumeBindingMode: Optional[str] = None

    def __init__(
        self,
        provisioner: str,
        allowVolumeExpansion: Optional[bool] = None,
        allowedTopologies: Optional[
            List[io__k8s__api__core__v1__TopologySelectorTerm]
        ] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        mountOptions: Optional[List[str]] = None,
        parameters: Any = None,
        reclaimPolicy: Optional[str] = None,
        volumeBindingMode: Optional[str] = None,
    ):
        super().__init__()
        if provisioner is not None:
            self.provisioner = provisioner
        if allowVolumeExpansion is not None:
            self.allowVolumeExpansion = allowVolumeExpansion
        if allowedTopologies is not None:
            self.allowedTopologies = allowedTopologies
        if metadata is not None:
            self.metadata = metadata
        if mountOptions is not None:
            self.mountOptions = mountOptions
        if parameters is not None:
            self.parameters = parameters
        if reclaimPolicy is not None:
            self.reclaimPolicy = reclaimPolicy
        if volumeBindingMode is not None:
            self.volumeBindingMode = volumeBindingMode


class io__k8s__api__storage__v1__StorageClassList(K8STemplatable):
    """StorageClassList is a collection of storage classes."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "StorageClassList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1__StorageClass]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1__StorageClass],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__VolumeAttachmentSource(K8STemplatable):
    """VolumeAttachmentSource represents a volume that should be attached. Right now only PersistenVolumes can be attached via external attacher, in future we may allow also inline volumes in pods. Exactly one member can be set."""

    props: List[str] = ["inlineVolumeSpec", "persistentVolumeName"]
    required_props: List[str] = []

    inlineVolumeSpec: Optional[io__k8s__api__core__v1__PersistentVolumeSpec] = None
    persistentVolumeName: Optional[str] = None

    def __init__(
        self,
        inlineVolumeSpec: Optional[io__k8s__api__core__v1__PersistentVolumeSpec] = None,
        persistentVolumeName: Optional[str] = None,
    ):
        super().__init__()
        if inlineVolumeSpec is not None:
            self.inlineVolumeSpec = inlineVolumeSpec
        if persistentVolumeName is not None:
            self.persistentVolumeName = persistentVolumeName


class io__k8s__api__storage__v1__VolumeAttachmentSpec(K8STemplatable):
    """VolumeAttachmentSpec is the specification of a VolumeAttachment request."""

    props: List[str] = ["attacher", "nodeName", "source"]
    required_props: List[str] = ["attacher", "source", "nodeName"]

    attacher: str
    nodeName: str
    source: io__k8s__api__storage__v1__VolumeAttachmentSource

    def __init__(
        self,
        attacher: str,
        nodeName: str,
        source: io__k8s__api__storage__v1__VolumeAttachmentSource,
    ):
        super().__init__()
        if attacher is not None:
            self.attacher = attacher
        if nodeName is not None:
            self.nodeName = nodeName
        if source is not None:
            self.source = source


class io__k8s__api__storage__v1__VolumeAttachmentStatus(K8STemplatable):
    """VolumeAttachmentStatus is the status of a VolumeAttachment request."""

    props: List[str] = ["attachError", "attached", "attachmentMetadata", "detachError"]
    required_props: List[str] = ["attached"]

    attachError: Optional[io__k8s__api__storage__v1__VolumeError] = None
    attached: bool
    attachmentMetadata: Any
    detachError: Optional[io__k8s__api__storage__v1__VolumeError] = None

    def __init__(
        self,
        attached: bool,
        attachError: Optional[io__k8s__api__storage__v1__VolumeError] = None,
        attachmentMetadata: Any = None,
        detachError: Optional[io__k8s__api__storage__v1__VolumeError] = None,
    ):
        super().__init__()
        if attached is not None:
            self.attached = attached
        if attachError is not None:
            self.attachError = attachError
        if attachmentMetadata is not None:
            self.attachmentMetadata = attachmentMetadata
        if detachError is not None:
            self.detachError = detachError


class io__k8s__api__storage__v1beta1__CSIStorageCapacity(K8STemplatable):
    """CSIStorageCapacity stores the result of one CSI GetCapacity call. For a given StorageClass, this describes the available capacity in a particular topology segment.  This can be used when considering where to instantiate new PersistentVolumes.

    For example this can express things like: - StorageClass "standard" has "1234 GiB" available in "topology.kubernetes.io/zone=us-east1" - StorageClass "localssd" has "10 GiB" available in "kubernetes.io/hostname=knode-abc123"

    The following three cases all imply that no capacity is available for a certain combination: - no object exists with suitable topology and storage class name - such an object exists, but the capacity is unset - such an object exists, but the capacity is zero

    The producer of these objects can decide which approach is more suitable.

    They are consumed by the kube-scheduler when a CSI driver opts into capacity-aware scheduling with CSIDriverSpec.StorageCapacity. The scheduler compares the MaximumVolumeSize against the requested size of pending volumes to filter out unsuitable nodes. If MaximumVolumeSize is unset, it falls back to a comparison against the less precise Capacity. If that is also unset, the scheduler assumes that capacity is insufficient and tries some other node."""

    apiVersion: str = "storage.k8s.io/v1beta1"
    kind: str = "CSIStorageCapacity"

    props: List[str] = [
        "apiVersion",
        "capacity",
        "kind",
        "maximumVolumeSize",
        "metadata",
        "nodeTopology",
        "storageClassName",
    ]
    required_props: List[str] = ["storageClassName"]

    capacity: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None
    maximumVolumeSize: Optional[
        io__k8s__apimachinery__pkg__api__resource__Quantity
    ] = None
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    nodeTopology: Optional[
        io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    ] = None
    storageClassName: str

    def __init__(
        self,
        storageClassName: str,
        capacity: Optional[io__k8s__apimachinery__pkg__api__resource__Quantity] = None,
        maximumVolumeSize: Optional[
            io__k8s__apimachinery__pkg__api__resource__Quantity
        ] = None,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        nodeTopology: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
    ):
        super().__init__()
        if storageClassName is not None:
            self.storageClassName = storageClassName
        if capacity is not None:
            self.capacity = capacity
        if maximumVolumeSize is not None:
            self.maximumVolumeSize = maximumVolumeSize
        if metadata is not None:
            self.metadata = metadata
        if nodeTopology is not None:
            self.nodeTopology = nodeTopology


class io__k8s__api__storage__v1beta1__CSIStorageCapacityList(K8STemplatable):
    """CSIStorageCapacityList is a collection of CSIStorageCapacity objects."""

    apiVersion: str = "storage.k8s.io/v1beta1"
    kind: str = "CSIStorageCapacityList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1beta1__CSIStorageCapacity]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1beta1__CSIStorageCapacity],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIService(
    K8STemplatable
):
    """APIService represents a server for a particular GroupVersion. Name must be "version.group"."""

    apiVersion: str = "apiregistration.k8s.io/v1"
    kind: str = "APIService"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[
        io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceSpec
    ] = None
    status: Optional[
        io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceSpec
        ] = None,
        status: Optional[
            io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceList(
    K8STemplatable
):
    """APIServiceList is a list of APIService objects."""

    apiVersion: str = "apiregistration.k8s.io/v1"
    kind: str = "APIServiceList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIService]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[
            io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIService
        ],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v2__ExternalMetricSource(K8STemplatable):
    """ExternalMetricSource indicates how to scale on a metric not associated with any Kubernetes object (for example length of queue in cloud messaging service, or QPS from loadbalancer running outside of cluster)."""

    props: List[str] = ["metric", "target"]
    required_props: List[str] = ["metric", "target"]

    metric: io__k8s__api__autoscaling__v2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2__MetricTarget

    def __init__(
        self,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2__MetricTarget,
    ):
        super().__init__()
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2__ExternalMetricStatus(K8STemplatable):
    """ExternalMetricStatus indicates the current value of a global metric not associated with any Kubernetes object."""

    props: List[str] = ["current", "metric"]
    required_props: List[str] = ["metric", "current"]

    current: io__k8s__api__autoscaling__v2__MetricValueStatus
    metric: io__k8s__api__autoscaling__v2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2__MetricValueStatus,
        metric: io__k8s__api__autoscaling__v2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if metric is not None:
            self.metric = metric


class io__k8s__api__autoscaling__v2__MetricSpec(K8STemplatable):
    """MetricSpec specifies how to scale based on a single metric (only `type` and one other matching field should be set at once)."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2__ContainerResourceMetricSource
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2__ExternalMetricSource] = None
    object: Optional[io__k8s__api__autoscaling__v2__ObjectMetricSource] = None
    pods: Optional[io__k8s__api__autoscaling__v2__PodsMetricSource] = None
    resource: Optional[io__k8s__api__autoscaling__v2__ResourceMetricSource] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2__ContainerResourceMetricSource
        ] = None,
        external: Optional[io__k8s__api__autoscaling__v2__ExternalMetricSource] = None,
        object: Optional[io__k8s__api__autoscaling__v2__ObjectMetricSource] = None,
        pods: Optional[io__k8s__api__autoscaling__v2__PodsMetricSource] = None,
        resource: Optional[io__k8s__api__autoscaling__v2__ResourceMetricSource] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__autoscaling__v2__MetricStatus(K8STemplatable):
    """MetricStatus describes the last-read state of a single metric."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2__ContainerResourceMetricStatus
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2__ExternalMetricStatus] = None
    object: Optional[io__k8s__api__autoscaling__v2__ObjectMetricStatus] = None
    pods: Optional[io__k8s__api__autoscaling__v2__PodsMetricStatus] = None
    resource: Optional[io__k8s__api__autoscaling__v2__ResourceMetricStatus] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2__ContainerResourceMetricStatus
        ] = None,
        external: Optional[io__k8s__api__autoscaling__v2__ExternalMetricStatus] = None,
        object: Optional[io__k8s__api__autoscaling__v2__ObjectMetricStatus] = None,
        pods: Optional[io__k8s__api__autoscaling__v2__PodsMetricStatus] = None,
        resource: Optional[io__k8s__api__autoscaling__v2__ResourceMetricStatus] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__autoscaling__v2beta1__MetricSpec(K8STemplatable):
    """MetricSpec specifies how to scale based on a single metric (only `type` and one other matching field should be set at once)."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricSource
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2beta1__ExternalMetricSource] = None
    object: Optional[io__k8s__api__autoscaling__v2beta1__ObjectMetricSource] = None
    pods: Optional[io__k8s__api__autoscaling__v2beta1__PodsMetricSource] = None
    resource: Optional[io__k8s__api__autoscaling__v2beta1__ResourceMetricSource] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricSource
        ] = None,
        external: Optional[
            io__k8s__api__autoscaling__v2beta1__ExternalMetricSource
        ] = None,
        object: Optional[io__k8s__api__autoscaling__v2beta1__ObjectMetricSource] = None,
        pods: Optional[io__k8s__api__autoscaling__v2beta1__PodsMetricSource] = None,
        resource: Optional[
            io__k8s__api__autoscaling__v2beta1__ResourceMetricSource
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__autoscaling__v2beta1__MetricStatus(K8STemplatable):
    """MetricStatus describes the last-read state of a single metric."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricStatus
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2beta1__ExternalMetricStatus] = None
    object: Optional[io__k8s__api__autoscaling__v2beta1__ObjectMetricStatus] = None
    pods: Optional[io__k8s__api__autoscaling__v2beta1__PodsMetricStatus] = None
    resource: Optional[io__k8s__api__autoscaling__v2beta1__ResourceMetricStatus] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2beta1__ContainerResourceMetricStatus
        ] = None,
        external: Optional[
            io__k8s__api__autoscaling__v2beta1__ExternalMetricStatus
        ] = None,
        object: Optional[io__k8s__api__autoscaling__v2beta1__ObjectMetricStatus] = None,
        pods: Optional[io__k8s__api__autoscaling__v2beta1__PodsMetricStatus] = None,
        resource: Optional[
            io__k8s__api__autoscaling__v2beta1__ResourceMetricStatus
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__autoscaling__v2beta2__ExternalMetricSource(K8STemplatable):
    """ExternalMetricSource indicates how to scale on a metric not associated with any Kubernetes object (for example length of queue in cloud messaging service, or QPS from loadbalancer running outside of cluster)."""

    props: List[str] = ["metric", "target"]
    required_props: List[str] = ["metric", "target"]

    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier
    target: io__k8s__api__autoscaling__v2beta2__MetricTarget

    def __init__(
        self,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
        target: io__k8s__api__autoscaling__v2beta2__MetricTarget,
    ):
        super().__init__()
        if metric is not None:
            self.metric = metric
        if target is not None:
            self.target = target


class io__k8s__api__autoscaling__v2beta2__ExternalMetricStatus(K8STemplatable):
    """ExternalMetricStatus indicates the current value of a global metric not associated with any Kubernetes object."""

    props: List[str] = ["current", "metric"]
    required_props: List[str] = ["metric", "current"]

    current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus
    metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier

    def __init__(
        self,
        current: io__k8s__api__autoscaling__v2beta2__MetricValueStatus,
        metric: io__k8s__api__autoscaling__v2beta2__MetricIdentifier,
    ):
        super().__init__()
        if current is not None:
            self.current = current
        if metric is not None:
            self.metric = metric


class io__k8s__api__autoscaling__v2beta2__MetricSpec(K8STemplatable):
    """MetricSpec specifies how to scale based on a single metric (only `type` and one other matching field should be set at once)."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricSource
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2beta2__ExternalMetricSource] = None
    object: Optional[io__k8s__api__autoscaling__v2beta2__ObjectMetricSource] = None
    pods: Optional[io__k8s__api__autoscaling__v2beta2__PodsMetricSource] = None
    resource: Optional[io__k8s__api__autoscaling__v2beta2__ResourceMetricSource] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricSource
        ] = None,
        external: Optional[
            io__k8s__api__autoscaling__v2beta2__ExternalMetricSource
        ] = None,
        object: Optional[io__k8s__api__autoscaling__v2beta2__ObjectMetricSource] = None,
        pods: Optional[io__k8s__api__autoscaling__v2beta2__PodsMetricSource] = None,
        resource: Optional[
            io__k8s__api__autoscaling__v2beta2__ResourceMetricSource
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__autoscaling__v2beta2__MetricStatus(K8STemplatable):
    """MetricStatus describes the last-read state of a single metric."""

    props: List[str] = [
        "containerResource",
        "external",
        "object",
        "pods",
        "resource",
        "type",
    ]
    required_props: List[str] = ["type"]

    containerResource: Optional[
        io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricStatus
    ] = None
    external: Optional[io__k8s__api__autoscaling__v2beta2__ExternalMetricStatus] = None
    object: Optional[io__k8s__api__autoscaling__v2beta2__ObjectMetricStatus] = None
    pods: Optional[io__k8s__api__autoscaling__v2beta2__PodsMetricStatus] = None
    resource: Optional[io__k8s__api__autoscaling__v2beta2__ResourceMetricStatus] = None
    type: str

    def __init__(
        self,
        type: str,
        containerResource: Optional[
            io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricStatus
        ] = None,
        external: Optional[
            io__k8s__api__autoscaling__v2beta2__ExternalMetricStatus
        ] = None,
        object: Optional[io__k8s__api__autoscaling__v2beta2__ObjectMetricStatus] = None,
        pods: Optional[io__k8s__api__autoscaling__v2beta2__PodsMetricStatus] = None,
        resource: Optional[
            io__k8s__api__autoscaling__v2beta2__ResourceMetricStatus
        ] = None,
    ):
        super().__init__()
        if type is not None:
            self.type = type
        if containerResource is not None:
            self.containerResource = containerResource
        if external is not None:
            self.external = external
        if object is not None:
            self.object = object
        if pods is not None:
            self.pods = pods
        if resource is not None:
            self.resource = resource


class io__k8s__api__core__v1__DownwardAPIProjection(K8STemplatable):
    """Represents downward API info for projecting into a projected volume. Note that this is identical to a downwardAPI volume source without the default mode."""

    props: List[str] = ["items"]
    required_props: List[str] = []

    items: Optional[List[io__k8s__api__core__v1__DownwardAPIVolumeFile]] = None

    def __init__(
        self,
        items: Optional[List[io__k8s__api__core__v1__DownwardAPIVolumeFile]] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items


class io__k8s__api__core__v1__EnvVar(K8STemplatable):
    """EnvVar represents an environment variable present in a Container."""

    props: List[str] = ["name", "value", "valueFrom"]
    required_props: List[str] = ["name"]

    name: str
    value: Optional[str] = None
    valueFrom: Optional[io__k8s__api__core__v1__EnvVarSource] = None

    def __init__(
        self,
        name: str,
        value: Optional[str] = None,
        valueFrom: Optional[io__k8s__api__core__v1__EnvVarSource] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if value is not None:
            self.value = value
        if valueFrom is not None:
            self.valueFrom = valueFrom


class io__k8s__api__core__v1__EphemeralVolumeSource(K8STemplatable):
    """Represents an ephemeral volume that is handled by a normal storage driver."""

    props: List[str] = ["volumeClaimTemplate"]
    required_props: List[str] = []

    volumeClaimTemplate: Optional[
        io__k8s__api__core__v1__PersistentVolumeClaimTemplate
    ] = None

    def __init__(
        self,
        volumeClaimTemplate: Optional[
            io__k8s__api__core__v1__PersistentVolumeClaimTemplate
        ] = None,
    ):
        super().__init__()
        if volumeClaimTemplate is not None:
            self.volumeClaimTemplate = volumeClaimTemplate


class io__k8s__api__core__v1__Lifecycle(K8STemplatable):
    """Lifecycle describes actions that the management system should take in response to container lifecycle events. For the PostStart and PreStop lifecycle handlers, management of the container blocks until the action is complete, unless the container process fails, in which case the handler is aborted."""

    props: List[str] = ["postStart", "preStop"]
    required_props: List[str] = []

    postStart: Optional[io__k8s__api__core__v1__LifecycleHandler] = None
    preStop: Optional[io__k8s__api__core__v1__LifecycleHandler] = None

    def __init__(
        self,
        postStart: Optional[io__k8s__api__core__v1__LifecycleHandler] = None,
        preStop: Optional[io__k8s__api__core__v1__LifecycleHandler] = None,
    ):
        super().__init__()
        if postStart is not None:
            self.postStart = postStart
        if preStop is not None:
            self.preStop = preStop


class io__k8s__api__core__v1__Node(K8STemplatable):
    """Node is a worker node in Kubernetes. Each node will have a unique identifier in the cache (i.e. in etcd)."""

    apiVersion: str = "v1"
    kind: str = "Node"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__NodeSpec] = None
    status: Optional[io__k8s__api__core__v1__NodeStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__NodeSpec] = None,
        status: Optional[io__k8s__api__core__v1__NodeStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__NodeList(K8STemplatable):
    """NodeList is the whole list of all Nodes which have been registered with master."""

    apiVersion: str = "v1"
    kind: str = "NodeList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Node]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Node],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PersistentVolume(K8STemplatable):
    """PersistentVolume (PV) is a storage resource provisioned by an administrator. It is analogous to a node. More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes"""

    apiVersion: str = "v1"
    kind: str = "PersistentVolume"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__PersistentVolumeSpec] = None
    status: Optional[io__k8s__api__core__v1__PersistentVolumeStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__PersistentVolumeSpec] = None,
        status: Optional[io__k8s__api__core__v1__PersistentVolumeStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__PersistentVolumeClaim(K8STemplatable):
    """PersistentVolumeClaim is a user's request for and claim to a persistent volume"""

    apiVersion: str = "v1"
    kind: str = "PersistentVolumeClaim"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__PersistentVolumeClaimSpec] = None
    status: Optional[io__k8s__api__core__v1__PersistentVolumeClaimStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__PersistentVolumeClaimSpec] = None,
        status: Optional[io__k8s__api__core__v1__PersistentVolumeClaimStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__PersistentVolumeClaimList(K8STemplatable):
    """PersistentVolumeClaimList is a list of PersistentVolumeClaim items."""

    apiVersion: str = "v1"
    kind: str = "PersistentVolumeClaimList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__PersistentVolumeClaim]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__PersistentVolumeClaim],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PersistentVolumeList(K8STemplatable):
    """PersistentVolumeList is a list of PersistentVolume items."""

    apiVersion: str = "v1"
    kind: str = "PersistentVolumeList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__PersistentVolume]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__PersistentVolume],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PodAffinity(K8STemplatable):
    """Pod affinity is a group of inter pod affinity scheduling rules."""

    props: List[str] = [
        "preferredDuringSchedulingIgnoredDuringExecution",
        "requiredDuringSchedulingIgnoredDuringExecution",
    ]
    required_props: List[str] = []

    preferredDuringSchedulingIgnoredDuringExecution: Optional[
        List[io__k8s__api__core__v1__WeightedPodAffinityTerm]
    ] = None
    requiredDuringSchedulingIgnoredDuringExecution: Optional[
        List[io__k8s__api__core__v1__PodAffinityTerm]
    ] = None

    def __init__(
        self,
        preferredDuringSchedulingIgnoredDuringExecution: Optional[
            List[io__k8s__api__core__v1__WeightedPodAffinityTerm]
        ] = None,
        requiredDuringSchedulingIgnoredDuringExecution: Optional[
            List[io__k8s__api__core__v1__PodAffinityTerm]
        ] = None,
    ):
        super().__init__()
        if preferredDuringSchedulingIgnoredDuringExecution is not None:
            self.preferredDuringSchedulingIgnoredDuringExecution = (
                preferredDuringSchedulingIgnoredDuringExecution
            )
        if requiredDuringSchedulingIgnoredDuringExecution is not None:
            self.requiredDuringSchedulingIgnoredDuringExecution = (
                requiredDuringSchedulingIgnoredDuringExecution
            )


class io__k8s__api__core__v1__PodAntiAffinity(K8STemplatable):
    """Pod anti affinity is a group of inter pod anti affinity scheduling rules."""

    props: List[str] = [
        "preferredDuringSchedulingIgnoredDuringExecution",
        "requiredDuringSchedulingIgnoredDuringExecution",
    ]
    required_props: List[str] = []

    preferredDuringSchedulingIgnoredDuringExecution: Optional[
        List[io__k8s__api__core__v1__WeightedPodAffinityTerm]
    ] = None
    requiredDuringSchedulingIgnoredDuringExecution: Optional[
        List[io__k8s__api__core__v1__PodAffinityTerm]
    ] = None

    def __init__(
        self,
        preferredDuringSchedulingIgnoredDuringExecution: Optional[
            List[io__k8s__api__core__v1__WeightedPodAffinityTerm]
        ] = None,
        requiredDuringSchedulingIgnoredDuringExecution: Optional[
            List[io__k8s__api__core__v1__PodAffinityTerm]
        ] = None,
    ):
        super().__init__()
        if preferredDuringSchedulingIgnoredDuringExecution is not None:
            self.preferredDuringSchedulingIgnoredDuringExecution = (
                preferredDuringSchedulingIgnoredDuringExecution
            )
        if requiredDuringSchedulingIgnoredDuringExecution is not None:
            self.requiredDuringSchedulingIgnoredDuringExecution = (
                requiredDuringSchedulingIgnoredDuringExecution
            )


class io__k8s__api__core__v1__ResourceQuota(K8STemplatable):
    """ResourceQuota sets aggregate quota restrictions enforced per namespace"""

    apiVersion: str = "v1"
    kind: str = "ResourceQuota"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__ResourceQuotaSpec] = None
    status: Optional[io__k8s__api__core__v1__ResourceQuotaStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__ResourceQuotaSpec] = None,
        status: Optional[io__k8s__api__core__v1__ResourceQuotaStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__ResourceQuotaList(K8STemplatable):
    """ResourceQuotaList is a list of ResourceQuota items."""

    apiVersion: str = "v1"
    kind: str = "ResourceQuotaList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__ResourceQuota]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__ResourceQuota],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__Service(K8STemplatable):
    """Service is a named abstraction of software service (for example, mysql) consisting of local port (for example 3306) that the proxy listens on, and the selector that determines which pods will answer requests sent through the proxy."""

    apiVersion: str = "v1"
    kind: str = "Service"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__ServiceSpec] = None
    status: Optional[io__k8s__api__core__v1__ServiceStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__ServiceSpec] = None,
        status: Optional[io__k8s__api__core__v1__ServiceStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__ServiceList(K8STemplatable):
    """ServiceList holds a list of services."""

    apiVersion: str = "v1"
    kind: str = "ServiceList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Service]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Service],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__VolumeProjection(K8STemplatable):
    """Projection that may be projected along with other supported volume types"""

    props: List[str] = ["configMap", "downwardAPI", "secret", "serviceAccountToken"]
    required_props: List[str] = []

    configMap: Optional[io__k8s__api__core__v1__ConfigMapProjection] = None
    downwardAPI: Optional[io__k8s__api__core__v1__DownwardAPIProjection] = None
    secret: Optional[io__k8s__api__core__v1__SecretProjection] = None
    serviceAccountToken: Optional[
        io__k8s__api__core__v1__ServiceAccountTokenProjection
    ] = None

    def __init__(
        self,
        configMap: Optional[io__k8s__api__core__v1__ConfigMapProjection] = None,
        downwardAPI: Optional[io__k8s__api__core__v1__DownwardAPIProjection] = None,
        secret: Optional[io__k8s__api__core__v1__SecretProjection] = None,
        serviceAccountToken: Optional[
            io__k8s__api__core__v1__ServiceAccountTokenProjection
        ] = None,
    ):
        super().__init__()
        if configMap is not None:
            self.configMap = configMap
        if downwardAPI is not None:
            self.downwardAPI = downwardAPI
        if secret is not None:
            self.secret = secret
        if serviceAccountToken is not None:
            self.serviceAccountToken = serviceAccountToken


class io__k8s__api__flowcontrol__v1beta1__FlowSchemaSpec(K8STemplatable):
    """FlowSchemaSpec describes how the FlowSchema's specification looks like."""

    props: List[str] = [
        "distinguisherMethod",
        "matchingPrecedence",
        "priorityLevelConfiguration",
        "rules",
    ]
    required_props: List[str] = ["priorityLevelConfiguration"]

    distinguisherMethod: Optional[
        io__k8s__api__flowcontrol__v1beta1__FlowDistinguisherMethod
    ] = None
    matchingPrecedence: Optional[int] = None
    priorityLevelConfiguration: io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationReference
    rules: Optional[
        List[io__k8s__api__flowcontrol__v1beta1__PolicyRulesWithSubjects]
    ] = None

    def __init__(
        self,
        priorityLevelConfiguration: io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationReference,
        distinguisherMethod: Optional[
            io__k8s__api__flowcontrol__v1beta1__FlowDistinguisherMethod
        ] = None,
        matchingPrecedence: Optional[int] = None,
        rules: Optional[
            List[io__k8s__api__flowcontrol__v1beta1__PolicyRulesWithSubjects]
        ] = None,
    ):
        super().__init__()
        if priorityLevelConfiguration is not None:
            self.priorityLevelConfiguration = priorityLevelConfiguration
        if distinguisherMethod is not None:
            self.distinguisherMethod = distinguisherMethod
        if matchingPrecedence is not None:
            self.matchingPrecedence = matchingPrecedence
        if rules is not None:
            self.rules = rules


class io__k8s__api__flowcontrol__v1beta2__FlowSchemaSpec(K8STemplatable):
    """FlowSchemaSpec describes how the FlowSchema's specification looks like."""

    props: List[str] = [
        "distinguisherMethod",
        "matchingPrecedence",
        "priorityLevelConfiguration",
        "rules",
    ]
    required_props: List[str] = ["priorityLevelConfiguration"]

    distinguisherMethod: Optional[
        io__k8s__api__flowcontrol__v1beta2__FlowDistinguisherMethod
    ] = None
    matchingPrecedence: Optional[int] = None
    priorityLevelConfiguration: io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationReference
    rules: Optional[
        List[io__k8s__api__flowcontrol__v1beta2__PolicyRulesWithSubjects]
    ] = None

    def __init__(
        self,
        priorityLevelConfiguration: io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationReference,
        distinguisherMethod: Optional[
            io__k8s__api__flowcontrol__v1beta2__FlowDistinguisherMethod
        ] = None,
        matchingPrecedence: Optional[int] = None,
        rules: Optional[
            List[io__k8s__api__flowcontrol__v1beta2__PolicyRulesWithSubjects]
        ] = None,
    ):
        super().__init__()
        if priorityLevelConfiguration is not None:
            self.priorityLevelConfiguration = priorityLevelConfiguration
        if distinguisherMethod is not None:
            self.distinguisherMethod = distinguisherMethod
        if matchingPrecedence is not None:
            self.matchingPrecedence = matchingPrecedence
        if rules is not None:
            self.rules = rules


class io__k8s__api__networking__v1__HTTPIngressPath(K8STemplatable):
    """HTTPIngressPath associates a path with a backend. Incoming urls matching the path are forwarded to the backend."""

    props: List[str] = ["backend", "path", "pathType"]
    required_props: List[str] = ["pathType", "backend"]

    backend: io__k8s__api__networking__v1__IngressBackend
    path: Optional[str] = None
    pathType: str

    def __init__(
        self,
        backend: io__k8s__api__networking__v1__IngressBackend,
        pathType: str,
        path: Optional[str] = None,
    ):
        super().__init__()
        if backend is not None:
            self.backend = backend
        if pathType is not None:
            self.pathType = pathType
        if path is not None:
            self.path = path


class io__k8s__api__networking__v1__HTTPIngressRuleValue(K8STemplatable):
    """HTTPIngressRuleValue is a list of http selectors pointing to backends. In the example: http://<host>/<path>?<searchpart> -> backend where where parts of the url correspond to RFC 3986, this resource will be used to match against everything after the last '/' and before the first '?' or '#'."""

    props: List[str] = ["paths"]
    required_props: List[str] = ["paths"]

    paths: List[io__k8s__api__networking__v1__HTTPIngressPath]

    def __init__(self, paths: List[io__k8s__api__networking__v1__HTTPIngressPath]):
        super().__init__()
        if paths is not None:
            self.paths = paths


class io__k8s__api__networking__v1__IngressRule(K8STemplatable):
    """IngressRule represents the rules mapping the paths under a specified host to the related backend services. Incoming requests are first evaluated for a host match, then routed to the backend associated with the matching IngressRuleValue."""

    props: List[str] = ["host", "http"]
    required_props: List[str] = []

    host: Optional[str] = None
    http: Optional[io__k8s__api__networking__v1__HTTPIngressRuleValue] = None

    def __init__(
        self,
        host: Optional[str] = None,
        http: Optional[io__k8s__api__networking__v1__HTTPIngressRuleValue] = None,
    ):
        super().__init__()
        if host is not None:
            self.host = host
        if http is not None:
            self.http = http


class io__k8s__api__networking__v1__IngressSpec(K8STemplatable):
    """IngressSpec describes the Ingress the user wishes to exist."""

    props: List[str] = ["defaultBackend", "ingressClassName", "rules", "tls"]
    required_props: List[str] = []

    defaultBackend: Optional[io__k8s__api__networking__v1__IngressBackend] = None
    ingressClassName: Optional[str] = None
    rules: Optional[List[io__k8s__api__networking__v1__IngressRule]] = None
    tls: Optional[List[io__k8s__api__networking__v1__IngressTLS]] = None

    def __init__(
        self,
        defaultBackend: Optional[io__k8s__api__networking__v1__IngressBackend] = None,
        ingressClassName: Optional[str] = None,
        rules: Optional[List[io__k8s__api__networking__v1__IngressRule]] = None,
        tls: Optional[List[io__k8s__api__networking__v1__IngressTLS]] = None,
    ):
        super().__init__()
        if defaultBackend is not None:
            self.defaultBackend = defaultBackend
        if ingressClassName is not None:
            self.ingressClassName = ingressClassName
        if rules is not None:
            self.rules = rules
        if tls is not None:
            self.tls = tls


class io__k8s__api__networking__v1__NetworkPolicyEgressRule(K8STemplatable):
    """NetworkPolicyEgressRule describes a particular set of traffic that is allowed out of pods matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and to. This type is beta-level in 1.8"""

    props: List[str] = ["ports", "to"]
    required_props: List[str] = []

    ports: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPort]] = None
    to: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPeer]] = None

    def __init__(
        self,
        ports: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPort]] = None,
        to: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPeer]] = None,
    ):
        super().__init__()
        if ports is not None:
            self.ports = ports
        if to is not None:
            self.to = to


class io__k8s__api__networking__v1__NetworkPolicyIngressRule(K8STemplatable):
    """NetworkPolicyIngressRule describes a particular set of traffic that is allowed to the pods matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and from."""

    props: List[str] = ["k8s_from", "ports"]
    required_props: List[str] = []

    k8s_from: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPeer]] = None
    ports: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPort]] = None

    def __init__(
        self,
        k8s_from: Optional[
            List[io__k8s__api__networking__v1__NetworkPolicyPeer]
        ] = None,
        ports: Optional[List[io__k8s__api__networking__v1__NetworkPolicyPort]] = None,
    ):
        super().__init__()
        if k8s_from is not None:
            self.k8s_from = k8s_from
        if ports is not None:
            self.ports = ports


class io__k8s__api__networking__v1__NetworkPolicySpec(K8STemplatable):
    """NetworkPolicySpec provides the specification of a NetworkPolicy"""

    props: List[str] = ["egress", "ingress", "podSelector", "policyTypes"]
    required_props: List[str] = ["podSelector"]

    egress: Optional[List[io__k8s__api__networking__v1__NetworkPolicyEgressRule]] = None
    ingress: Optional[
        List[io__k8s__api__networking__v1__NetworkPolicyIngressRule]
    ] = None
    podSelector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    policyTypes: Optional[List[str]] = None

    def __init__(
        self,
        podSelector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector,
        egress: Optional[
            List[io__k8s__api__networking__v1__NetworkPolicyEgressRule]
        ] = None,
        ingress: Optional[
            List[io__k8s__api__networking__v1__NetworkPolicyIngressRule]
        ] = None,
        policyTypes: Optional[List[str]] = None,
    ):
        super().__init__()
        if podSelector is not None:
            self.podSelector = podSelector
        if egress is not None:
            self.egress = egress
        if ingress is not None:
            self.ingress = ingress
        if policyTypes is not None:
            self.policyTypes = policyTypes


class io__k8s__api__policy__v1__PodDisruptionBudget(K8STemplatable):
    """PodDisruptionBudget is an object to define the max disruption that can be caused to a collection of pods"""

    apiVersion: str = "policy/v1"
    kind: str = "PodDisruptionBudget"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__policy__v1__PodDisruptionBudgetSpec] = None
    status: Optional[io__k8s__api__policy__v1__PodDisruptionBudgetStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__policy__v1__PodDisruptionBudgetSpec] = None,
        status: Optional[io__k8s__api__policy__v1__PodDisruptionBudgetStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__policy__v1__PodDisruptionBudgetList(K8STemplatable):
    """PodDisruptionBudgetList is a collection of PodDisruptionBudgets."""

    apiVersion: str = "policy/v1"
    kind: str = "PodDisruptionBudgetList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__policy__v1__PodDisruptionBudget]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__policy__v1__PodDisruptionBudget],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__policy__v1beta1__PodDisruptionBudget(K8STemplatable):
    """PodDisruptionBudget is an object to define the max disruption that can be caused to a collection of pods"""

    apiVersion: str = "policy/v1beta1"
    kind: str = "PodDisruptionBudget"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__policy__v1beta1__PodDisruptionBudgetSpec] = None
    status: Optional[io__k8s__api__policy__v1beta1__PodDisruptionBudgetStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__policy__v1beta1__PodDisruptionBudgetSpec] = None,
        status: Optional[
            io__k8s__api__policy__v1beta1__PodDisruptionBudgetStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__policy__v1beta1__PodDisruptionBudgetList(K8STemplatable):
    """PodDisruptionBudgetList is a collection of PodDisruptionBudgets."""

    apiVersion: str = "policy/v1beta1"
    kind: str = "PodDisruptionBudgetList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__policy__v1beta1__PodDisruptionBudget]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__policy__v1beta1__PodDisruptionBudget],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__storage__v1__VolumeAttachment(K8STemplatable):
    """VolumeAttachment captures the intent to attach or detach the specified volume to/from the specified node.

    VolumeAttachment objects are non-namespaced."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "VolumeAttachment"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = ["spec"]

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: io__k8s__api__storage__v1__VolumeAttachmentSpec
    status: Optional[io__k8s__api__storage__v1__VolumeAttachmentStatus] = None

    def __init__(
        self,
        spec: io__k8s__api__storage__v1__VolumeAttachmentSpec,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        status: Optional[io__k8s__api__storage__v1__VolumeAttachmentStatus] = None,
    ):
        super().__init__()
        if spec is not None:
            self.spec = spec
        if metadata is not None:
            self.metadata = metadata
        if status is not None:
            self.status = status


class io__k8s__api__storage__v1__VolumeAttachmentList(K8STemplatable):
    """VolumeAttachmentList is a collection of VolumeAttachment objects."""

    apiVersion: str = "storage.k8s.io/v1"
    kind: str = "VolumeAttachmentList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__storage__v1__VolumeAttachment]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__storage__v1__VolumeAttachment],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerSpec(K8STemplatable):
    """HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler."""

    props: List[str] = [
        "behavior",
        "maxReplicas",
        "metrics",
        "minReplicas",
        "scaleTargetRef",
    ]
    required_props: List[str] = ["scaleTargetRef", "maxReplicas"]

    behavior: Optional[
        io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerBehavior
    ] = None
    maxReplicas: int
    metrics: Optional[List[io__k8s__api__autoscaling__v2__MetricSpec]] = None
    minReplicas: Optional[int] = None
    scaleTargetRef: io__k8s__api__autoscaling__v2__CrossVersionObjectReference

    def __init__(
        self,
        maxReplicas: int,
        scaleTargetRef: io__k8s__api__autoscaling__v2__CrossVersionObjectReference,
        behavior: Optional[
            io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerBehavior
        ] = None,
        metrics: Optional[List[io__k8s__api__autoscaling__v2__MetricSpec]] = None,
        minReplicas: Optional[int] = None,
    ):
        super().__init__()
        if maxReplicas is not None:
            self.maxReplicas = maxReplicas
        if scaleTargetRef is not None:
            self.scaleTargetRef = scaleTargetRef
        if behavior is not None:
            self.behavior = behavior
        if metrics is not None:
            self.metrics = metrics
        if minReplicas is not None:
            self.minReplicas = minReplicas


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerStatus(K8STemplatable):
    """HorizontalPodAutoscalerStatus describes the current status of a horizontal pod autoscaler."""

    props: List[str] = [
        "conditions",
        "currentMetrics",
        "currentReplicas",
        "desiredReplicas",
        "lastScaleTime",
        "observedGeneration",
    ]
    required_props: List[str] = ["desiredReplicas"]

    conditions: Optional[
        List[io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerCondition]
    ] = None
    currentMetrics: Optional[List[io__k8s__api__autoscaling__v2__MetricStatus]] = None
    currentReplicas: Optional[int] = None
    desiredReplicas: int
    lastScaleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        desiredReplicas: int,
        conditions: Optional[
            List[io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerCondition]
        ] = None,
        currentMetrics: Optional[
            List[io__k8s__api__autoscaling__v2__MetricStatus]
        ] = None,
        currentReplicas: Optional[int] = None,
        lastScaleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if desiredReplicas is not None:
            self.desiredReplicas = desiredReplicas
        if conditions is not None:
            self.conditions = conditions
        if currentMetrics is not None:
            self.currentMetrics = currentMetrics
        if currentReplicas is not None:
            self.currentReplicas = currentReplicas
        if lastScaleTime is not None:
            self.lastScaleTime = lastScaleTime
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerSpec(K8STemplatable):
    """HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler."""

    props: List[str] = ["maxReplicas", "metrics", "minReplicas", "scaleTargetRef"]
    required_props: List[str] = ["scaleTargetRef", "maxReplicas"]

    maxReplicas: int
    metrics: Optional[List[io__k8s__api__autoscaling__v2beta1__MetricSpec]] = None
    minReplicas: Optional[int] = None
    scaleTargetRef: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference

    def __init__(
        self,
        maxReplicas: int,
        scaleTargetRef: io__k8s__api__autoscaling__v2beta1__CrossVersionObjectReference,
        metrics: Optional[List[io__k8s__api__autoscaling__v2beta1__MetricSpec]] = None,
        minReplicas: Optional[int] = None,
    ):
        super().__init__()
        if maxReplicas is not None:
            self.maxReplicas = maxReplicas
        if scaleTargetRef is not None:
            self.scaleTargetRef = scaleTargetRef
        if metrics is not None:
            self.metrics = metrics
        if minReplicas is not None:
            self.minReplicas = minReplicas


class io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerStatus(K8STemplatable):
    """HorizontalPodAutoscalerStatus describes the current status of a horizontal pod autoscaler."""

    props: List[str] = [
        "conditions",
        "currentMetrics",
        "currentReplicas",
        "desiredReplicas",
        "lastScaleTime",
        "observedGeneration",
    ]
    required_props: List[str] = ["currentReplicas", "desiredReplicas"]

    conditions: Optional[
        List[io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerCondition]
    ] = None
    currentMetrics: Optional[
        List[io__k8s__api__autoscaling__v2beta1__MetricStatus]
    ] = None
    currentReplicas: int
    desiredReplicas: int
    lastScaleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        currentReplicas: int,
        desiredReplicas: int,
        conditions: Optional[
            List[io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerCondition]
        ] = None,
        currentMetrics: Optional[
            List[io__k8s__api__autoscaling__v2beta1__MetricStatus]
        ] = None,
        lastScaleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if currentReplicas is not None:
            self.currentReplicas = currentReplicas
        if desiredReplicas is not None:
            self.desiredReplicas = desiredReplicas
        if conditions is not None:
            self.conditions = conditions
        if currentMetrics is not None:
            self.currentMetrics = currentMetrics
        if lastScaleTime is not None:
            self.lastScaleTime = lastScaleTime
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerSpec(K8STemplatable):
    """HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler."""

    props: List[str] = [
        "behavior",
        "maxReplicas",
        "metrics",
        "minReplicas",
        "scaleTargetRef",
    ]
    required_props: List[str] = ["scaleTargetRef", "maxReplicas"]

    behavior: Optional[
        io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerBehavior
    ] = None
    maxReplicas: int
    metrics: Optional[List[io__k8s__api__autoscaling__v2beta2__MetricSpec]] = None
    minReplicas: Optional[int] = None
    scaleTargetRef: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference

    def __init__(
        self,
        maxReplicas: int,
        scaleTargetRef: io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference,
        behavior: Optional[
            io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerBehavior
        ] = None,
        metrics: Optional[List[io__k8s__api__autoscaling__v2beta2__MetricSpec]] = None,
        minReplicas: Optional[int] = None,
    ):
        super().__init__()
        if maxReplicas is not None:
            self.maxReplicas = maxReplicas
        if scaleTargetRef is not None:
            self.scaleTargetRef = scaleTargetRef
        if behavior is not None:
            self.behavior = behavior
        if metrics is not None:
            self.metrics = metrics
        if minReplicas is not None:
            self.minReplicas = minReplicas


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerStatus(K8STemplatable):
    """HorizontalPodAutoscalerStatus describes the current status of a horizontal pod autoscaler."""

    props: List[str] = [
        "conditions",
        "currentMetrics",
        "currentReplicas",
        "desiredReplicas",
        "lastScaleTime",
        "observedGeneration",
    ]
    required_props: List[str] = ["currentReplicas", "desiredReplicas"]

    conditions: Optional[
        List[io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerCondition]
    ] = None
    currentMetrics: Optional[
        List[io__k8s__api__autoscaling__v2beta2__MetricStatus]
    ] = None
    currentReplicas: int
    desiredReplicas: int
    lastScaleTime: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__Time] = None
    observedGeneration: Optional[int] = None

    def __init__(
        self,
        currentReplicas: int,
        desiredReplicas: int,
        conditions: Optional[
            List[io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerCondition]
        ] = None,
        currentMetrics: Optional[
            List[io__k8s__api__autoscaling__v2beta2__MetricStatus]
        ] = None,
        lastScaleTime: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__Time
        ] = None,
        observedGeneration: Optional[int] = None,
    ):
        super().__init__()
        if currentReplicas is not None:
            self.currentReplicas = currentReplicas
        if desiredReplicas is not None:
            self.desiredReplicas = desiredReplicas
        if conditions is not None:
            self.conditions = conditions
        if currentMetrics is not None:
            self.currentMetrics = currentMetrics
        if lastScaleTime is not None:
            self.lastScaleTime = lastScaleTime
        if observedGeneration is not None:
            self.observedGeneration = observedGeneration


class io__k8s__api__core__v1__Affinity(K8STemplatable):
    """Affinity is a group of affinity scheduling rules."""

    props: List[str] = ["nodeAffinity", "podAffinity", "podAntiAffinity"]
    required_props: List[str] = []

    nodeAffinity: Optional[io__k8s__api__core__v1__NodeAffinity] = None
    podAffinity: Optional[io__k8s__api__core__v1__PodAffinity] = None
    podAntiAffinity: Optional[io__k8s__api__core__v1__PodAntiAffinity] = None

    def __init__(
        self,
        nodeAffinity: Optional[io__k8s__api__core__v1__NodeAffinity] = None,
        podAffinity: Optional[io__k8s__api__core__v1__PodAffinity] = None,
        podAntiAffinity: Optional[io__k8s__api__core__v1__PodAntiAffinity] = None,
    ):
        super().__init__()
        if nodeAffinity is not None:
            self.nodeAffinity = nodeAffinity
        if podAffinity is not None:
            self.podAffinity = podAffinity
        if podAntiAffinity is not None:
            self.podAntiAffinity = podAntiAffinity


class io__k8s__api__core__v1__Container(K8STemplatable):
    """A single application container that you want to run within a pod."""

    props: List[str] = [
        "args",
        "command",
        "env",
        "envFrom",
        "image",
        "imagePullPolicy",
        "lifecycle",
        "livenessProbe",
        "name",
        "ports",
        "readinessProbe",
        "resources",
        "securityContext",
        "startupProbe",
        "stdin",
        "stdinOnce",
        "terminationMessagePath",
        "terminationMessagePolicy",
        "tty",
        "volumeDevices",
        "volumeMounts",
        "workingDir",
    ]
    required_props: List[str] = ["name"]

    args: Optional[List[str]] = None
    command: Optional[List[str]] = None
    env: Optional[List[io__k8s__api__core__v1__EnvVar]] = None
    envFrom: Optional[List[io__k8s__api__core__v1__EnvFromSource]] = None
    image: Optional[str] = None
    imagePullPolicy: Optional[str] = None
    lifecycle: Optional[io__k8s__api__core__v1__Lifecycle] = None
    livenessProbe: Optional[io__k8s__api__core__v1__Probe] = None
    name: str
    ports: Optional[List[io__k8s__api__core__v1__ContainerPort]] = None
    readinessProbe: Optional[io__k8s__api__core__v1__Probe] = None
    resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None
    securityContext: Optional[io__k8s__api__core__v1__SecurityContext] = None
    startupProbe: Optional[io__k8s__api__core__v1__Probe] = None
    stdin: Optional[bool] = None
    stdinOnce: Optional[bool] = None
    terminationMessagePath: Optional[str] = None
    terminationMessagePolicy: Optional[str] = None
    tty: Optional[bool] = None
    volumeDevices: Optional[List[io__k8s__api__core__v1__VolumeDevice]] = None
    volumeMounts: Optional[List[io__k8s__api__core__v1__VolumeMount]] = None
    workingDir: Optional[str] = None

    def __init__(
        self,
        name: str,
        args: Optional[List[str]] = None,
        command: Optional[List[str]] = None,
        env: Optional[List[io__k8s__api__core__v1__EnvVar]] = None,
        envFrom: Optional[List[io__k8s__api__core__v1__EnvFromSource]] = None,
        image: Optional[str] = None,
        imagePullPolicy: Optional[str] = None,
        lifecycle: Optional[io__k8s__api__core__v1__Lifecycle] = None,
        livenessProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        ports: Optional[List[io__k8s__api__core__v1__ContainerPort]] = None,
        readinessProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None,
        securityContext: Optional[io__k8s__api__core__v1__SecurityContext] = None,
        startupProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        stdin: Optional[bool] = None,
        stdinOnce: Optional[bool] = None,
        terminationMessagePath: Optional[str] = None,
        terminationMessagePolicy: Optional[str] = None,
        tty: Optional[bool] = None,
        volumeDevices: Optional[List[io__k8s__api__core__v1__VolumeDevice]] = None,
        volumeMounts: Optional[List[io__k8s__api__core__v1__VolumeMount]] = None,
        workingDir: Optional[str] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if args is not None:
            self.args = args
        if command is not None:
            self.command = command
        if env is not None:
            self.env = env
        if envFrom is not None:
            self.envFrom = envFrom
        if image is not None:
            self.image = image
        if imagePullPolicy is not None:
            self.imagePullPolicy = imagePullPolicy
        if lifecycle is not None:
            self.lifecycle = lifecycle
        if livenessProbe is not None:
            self.livenessProbe = livenessProbe
        if ports is not None:
            self.ports = ports
        if readinessProbe is not None:
            self.readinessProbe = readinessProbe
        if resources is not None:
            self.resources = resources
        if securityContext is not None:
            self.securityContext = securityContext
        if startupProbe is not None:
            self.startupProbe = startupProbe
        if stdin is not None:
            self.stdin = stdin
        if stdinOnce is not None:
            self.stdinOnce = stdinOnce
        if terminationMessagePath is not None:
            self.terminationMessagePath = terminationMessagePath
        if terminationMessagePolicy is not None:
            self.terminationMessagePolicy = terminationMessagePolicy
        if tty is not None:
            self.tty = tty
        if volumeDevices is not None:
            self.volumeDevices = volumeDevices
        if volumeMounts is not None:
            self.volumeMounts = volumeMounts
        if workingDir is not None:
            self.workingDir = workingDir


class io__k8s__api__core__v1__EphemeralContainer(K8STemplatable):
    """An EphemeralContainer is a temporary container that you may add to an existing Pod for user-initiated activities such as debugging. Ephemeral containers have no resource or scheduling guarantees, and they will not be restarted when they exit or when a Pod is removed or restarted. The kubelet may evict a Pod if an ephemeral container causes the Pod to exceed its resource allocation.

    To add an ephemeral container, use the ephemeralcontainers subresource of an existing Pod. Ephemeral containers may not be removed or restarted.

    This is a beta feature available on clusters that haven't disabled the EphemeralContainers feature gate."""

    props: List[str] = [
        "args",
        "command",
        "env",
        "envFrom",
        "image",
        "imagePullPolicy",
        "lifecycle",
        "livenessProbe",
        "name",
        "ports",
        "readinessProbe",
        "resources",
        "securityContext",
        "startupProbe",
        "stdin",
        "stdinOnce",
        "targetContainerName",
        "terminationMessagePath",
        "terminationMessagePolicy",
        "tty",
        "volumeDevices",
        "volumeMounts",
        "workingDir",
    ]
    required_props: List[str] = ["name"]

    args: Optional[List[str]] = None
    command: Optional[List[str]] = None
    env: Optional[List[io__k8s__api__core__v1__EnvVar]] = None
    envFrom: Optional[List[io__k8s__api__core__v1__EnvFromSource]] = None
    image: Optional[str] = None
    imagePullPolicy: Optional[str] = None
    lifecycle: Optional[io__k8s__api__core__v1__Lifecycle] = None
    livenessProbe: Optional[io__k8s__api__core__v1__Probe] = None
    name: str
    ports: Optional[List[io__k8s__api__core__v1__ContainerPort]] = None
    readinessProbe: Optional[io__k8s__api__core__v1__Probe] = None
    resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None
    securityContext: Optional[io__k8s__api__core__v1__SecurityContext] = None
    startupProbe: Optional[io__k8s__api__core__v1__Probe] = None
    stdin: Optional[bool] = None
    stdinOnce: Optional[bool] = None
    targetContainerName: Optional[str] = None
    terminationMessagePath: Optional[str] = None
    terminationMessagePolicy: Optional[str] = None
    tty: Optional[bool] = None
    volumeDevices: Optional[List[io__k8s__api__core__v1__VolumeDevice]] = None
    volumeMounts: Optional[List[io__k8s__api__core__v1__VolumeMount]] = None
    workingDir: Optional[str] = None

    def __init__(
        self,
        name: str,
        args: Optional[List[str]] = None,
        command: Optional[List[str]] = None,
        env: Optional[List[io__k8s__api__core__v1__EnvVar]] = None,
        envFrom: Optional[List[io__k8s__api__core__v1__EnvFromSource]] = None,
        image: Optional[str] = None,
        imagePullPolicy: Optional[str] = None,
        lifecycle: Optional[io__k8s__api__core__v1__Lifecycle] = None,
        livenessProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        ports: Optional[List[io__k8s__api__core__v1__ContainerPort]] = None,
        readinessProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        resources: Optional[io__k8s__api__core__v1__ResourceRequirements] = None,
        securityContext: Optional[io__k8s__api__core__v1__SecurityContext] = None,
        startupProbe: Optional[io__k8s__api__core__v1__Probe] = None,
        stdin: Optional[bool] = None,
        stdinOnce: Optional[bool] = None,
        targetContainerName: Optional[str] = None,
        terminationMessagePath: Optional[str] = None,
        terminationMessagePolicy: Optional[str] = None,
        tty: Optional[bool] = None,
        volumeDevices: Optional[List[io__k8s__api__core__v1__VolumeDevice]] = None,
        volumeMounts: Optional[List[io__k8s__api__core__v1__VolumeMount]] = None,
        workingDir: Optional[str] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if args is not None:
            self.args = args
        if command is not None:
            self.command = command
        if env is not None:
            self.env = env
        if envFrom is not None:
            self.envFrom = envFrom
        if image is not None:
            self.image = image
        if imagePullPolicy is not None:
            self.imagePullPolicy = imagePullPolicy
        if lifecycle is not None:
            self.lifecycle = lifecycle
        if livenessProbe is not None:
            self.livenessProbe = livenessProbe
        if ports is not None:
            self.ports = ports
        if readinessProbe is not None:
            self.readinessProbe = readinessProbe
        if resources is not None:
            self.resources = resources
        if securityContext is not None:
            self.securityContext = securityContext
        if startupProbe is not None:
            self.startupProbe = startupProbe
        if stdin is not None:
            self.stdin = stdin
        if stdinOnce is not None:
            self.stdinOnce = stdinOnce
        if targetContainerName is not None:
            self.targetContainerName = targetContainerName
        if terminationMessagePath is not None:
            self.terminationMessagePath = terminationMessagePath
        if terminationMessagePolicy is not None:
            self.terminationMessagePolicy = terminationMessagePolicy
        if tty is not None:
            self.tty = tty
        if volumeDevices is not None:
            self.volumeDevices = volumeDevices
        if volumeMounts is not None:
            self.volumeMounts = volumeMounts
        if workingDir is not None:
            self.workingDir = workingDir


class io__k8s__api__core__v1__ProjectedVolumeSource(K8STemplatable):
    """Represents a projected volume source"""

    props: List[str] = ["defaultMode", "sources"]
    required_props: List[str] = []

    defaultMode: Optional[int] = None
    sources: Optional[List[io__k8s__api__core__v1__VolumeProjection]] = None

    def __init__(
        self,
        defaultMode: Optional[int] = None,
        sources: Optional[List[io__k8s__api__core__v1__VolumeProjection]] = None,
    ):
        super().__init__()
        if defaultMode is not None:
            self.defaultMode = defaultMode
        if sources is not None:
            self.sources = sources


class io__k8s__api__core__v1__Volume(K8STemplatable):
    """Volume represents a named volume in a pod that may be accessed by any container in the pod."""

    props: List[str] = [
        "awsElasticBlockStore",
        "azureDisk",
        "azureFile",
        "cephfs",
        "cinder",
        "configMap",
        "csi",
        "downwardAPI",
        "emptyDir",
        "ephemeral",
        "fc",
        "flexVolume",
        "flocker",
        "gcePersistentDisk",
        "gitRepo",
        "glusterfs",
        "hostPath",
        "iscsi",
        "name",
        "nfs",
        "persistentVolumeClaim",
        "photonPersistentDisk",
        "portworxVolume",
        "projected",
        "quobyte",
        "rbd",
        "scaleIO",
        "secret",
        "storageos",
        "vsphereVolume",
    ]
    required_props: List[str] = ["name"]

    awsElasticBlockStore: Optional[
        io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource
    ] = None
    azureDisk: Optional[io__k8s__api__core__v1__AzureDiskVolumeSource] = None
    azureFile: Optional[io__k8s__api__core__v1__AzureFileVolumeSource] = None
    cephfs: Optional[io__k8s__api__core__v1__CephFSVolumeSource] = None
    cinder: Optional[io__k8s__api__core__v1__CinderVolumeSource] = None
    configMap: Optional[io__k8s__api__core__v1__ConfigMapVolumeSource] = None
    csi: Optional[io__k8s__api__core__v1__CSIVolumeSource] = None
    downwardAPI: Optional[io__k8s__api__core__v1__DownwardAPIVolumeSource] = None
    emptyDir: Optional[io__k8s__api__core__v1__EmptyDirVolumeSource] = None
    ephemeral: Optional[io__k8s__api__core__v1__EphemeralVolumeSource] = None
    fc: Optional[io__k8s__api__core__v1__FCVolumeSource] = None
    flexVolume: Optional[io__k8s__api__core__v1__FlexVolumeSource] = None
    flocker: Optional[io__k8s__api__core__v1__FlockerVolumeSource] = None
    gcePersistentDisk: Optional[
        io__k8s__api__core__v1__GCEPersistentDiskVolumeSource
    ] = None
    gitRepo: Optional[io__k8s__api__core__v1__GitRepoVolumeSource] = None
    glusterfs: Optional[io__k8s__api__core__v1__GlusterfsVolumeSource] = None
    hostPath: Optional[io__k8s__api__core__v1__HostPathVolumeSource] = None
    iscsi: Optional[io__k8s__api__core__v1__ISCSIVolumeSource] = None
    name: str
    nfs: Optional[io__k8s__api__core__v1__NFSVolumeSource] = None
    persistentVolumeClaim: Optional[
        io__k8s__api__core__v1__PersistentVolumeClaimVolumeSource
    ] = None
    photonPersistentDisk: Optional[
        io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource
    ] = None
    portworxVolume: Optional[io__k8s__api__core__v1__PortworxVolumeSource] = None
    projected: Optional[io__k8s__api__core__v1__ProjectedVolumeSource] = None
    quobyte: Optional[io__k8s__api__core__v1__QuobyteVolumeSource] = None
    rbd: Optional[io__k8s__api__core__v1__RBDVolumeSource] = None
    scaleIO: Optional[io__k8s__api__core__v1__ScaleIOVolumeSource] = None
    secret: Optional[io__k8s__api__core__v1__SecretVolumeSource] = None
    storageos: Optional[io__k8s__api__core__v1__StorageOSVolumeSource] = None
    vsphereVolume: Optional[
        io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource
    ] = None

    def __init__(
        self,
        name: str,
        awsElasticBlockStore: Optional[
            io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource
        ] = None,
        azureDisk: Optional[io__k8s__api__core__v1__AzureDiskVolumeSource] = None,
        azureFile: Optional[io__k8s__api__core__v1__AzureFileVolumeSource] = None,
        cephfs: Optional[io__k8s__api__core__v1__CephFSVolumeSource] = None,
        cinder: Optional[io__k8s__api__core__v1__CinderVolumeSource] = None,
        configMap: Optional[io__k8s__api__core__v1__ConfigMapVolumeSource] = None,
        csi: Optional[io__k8s__api__core__v1__CSIVolumeSource] = None,
        downwardAPI: Optional[io__k8s__api__core__v1__DownwardAPIVolumeSource] = None,
        emptyDir: Optional[io__k8s__api__core__v1__EmptyDirVolumeSource] = None,
        ephemeral: Optional[io__k8s__api__core__v1__EphemeralVolumeSource] = None,
        fc: Optional[io__k8s__api__core__v1__FCVolumeSource] = None,
        flexVolume: Optional[io__k8s__api__core__v1__FlexVolumeSource] = None,
        flocker: Optional[io__k8s__api__core__v1__FlockerVolumeSource] = None,
        gcePersistentDisk: Optional[
            io__k8s__api__core__v1__GCEPersistentDiskVolumeSource
        ] = None,
        gitRepo: Optional[io__k8s__api__core__v1__GitRepoVolumeSource] = None,
        glusterfs: Optional[io__k8s__api__core__v1__GlusterfsVolumeSource] = None,
        hostPath: Optional[io__k8s__api__core__v1__HostPathVolumeSource] = None,
        iscsi: Optional[io__k8s__api__core__v1__ISCSIVolumeSource] = None,
        nfs: Optional[io__k8s__api__core__v1__NFSVolumeSource] = None,
        persistentVolumeClaim: Optional[
            io__k8s__api__core__v1__PersistentVolumeClaimVolumeSource
        ] = None,
        photonPersistentDisk: Optional[
            io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource
        ] = None,
        portworxVolume: Optional[io__k8s__api__core__v1__PortworxVolumeSource] = None,
        projected: Optional[io__k8s__api__core__v1__ProjectedVolumeSource] = None,
        quobyte: Optional[io__k8s__api__core__v1__QuobyteVolumeSource] = None,
        rbd: Optional[io__k8s__api__core__v1__RBDVolumeSource] = None,
        scaleIO: Optional[io__k8s__api__core__v1__ScaleIOVolumeSource] = None,
        secret: Optional[io__k8s__api__core__v1__SecretVolumeSource] = None,
        storageos: Optional[io__k8s__api__core__v1__StorageOSVolumeSource] = None,
        vsphereVolume: Optional[
            io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource
        ] = None,
    ):
        super().__init__()
        if name is not None:
            self.name = name
        if awsElasticBlockStore is not None:
            self.awsElasticBlockStore = awsElasticBlockStore
        if azureDisk is not None:
            self.azureDisk = azureDisk
        if azureFile is not None:
            self.azureFile = azureFile
        if cephfs is not None:
            self.cephfs = cephfs
        if cinder is not None:
            self.cinder = cinder
        if configMap is not None:
            self.configMap = configMap
        if csi is not None:
            self.csi = csi
        if downwardAPI is not None:
            self.downwardAPI = downwardAPI
        if emptyDir is not None:
            self.emptyDir = emptyDir
        if ephemeral is not None:
            self.ephemeral = ephemeral
        if fc is not None:
            self.fc = fc
        if flexVolume is not None:
            self.flexVolume = flexVolume
        if flocker is not None:
            self.flocker = flocker
        if gcePersistentDisk is not None:
            self.gcePersistentDisk = gcePersistentDisk
        if gitRepo is not None:
            self.gitRepo = gitRepo
        if glusterfs is not None:
            self.glusterfs = glusterfs
        if hostPath is not None:
            self.hostPath = hostPath
        if iscsi is not None:
            self.iscsi = iscsi
        if nfs is not None:
            self.nfs = nfs
        if persistentVolumeClaim is not None:
            self.persistentVolumeClaim = persistentVolumeClaim
        if photonPersistentDisk is not None:
            self.photonPersistentDisk = photonPersistentDisk
        if portworxVolume is not None:
            self.portworxVolume = portworxVolume
        if projected is not None:
            self.projected = projected
        if quobyte is not None:
            self.quobyte = quobyte
        if rbd is not None:
            self.rbd = rbd
        if scaleIO is not None:
            self.scaleIO = scaleIO
        if secret is not None:
            self.secret = secret
        if storageos is not None:
            self.storageos = storageos
        if vsphereVolume is not None:
            self.vsphereVolume = vsphereVolume


class io__k8s__api__flowcontrol__v1beta1__FlowSchema(K8STemplatable):
    """FlowSchema defines the schema of a group of flows. Note that a flow is made up of a set of inbound API requests with similar attributes and is identified by a pair of strings: the name of the FlowSchema and a "flow distinguisher"."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta1"
    kind: str = "FlowSchema"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__flowcontrol__v1beta1__FlowSchemaSpec] = None
    status: Optional[io__k8s__api__flowcontrol__v1beta1__FlowSchemaStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__flowcontrol__v1beta1__FlowSchemaSpec] = None,
        status: Optional[io__k8s__api__flowcontrol__v1beta1__FlowSchemaStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__flowcontrol__v1beta1__FlowSchemaList(K8STemplatable):
    """FlowSchemaList is a list of FlowSchema objects."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta1"
    kind: str = "FlowSchemaList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__flowcontrol__v1beta1__FlowSchema]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__flowcontrol__v1beta1__FlowSchema],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__flowcontrol__v1beta2__FlowSchema(K8STemplatable):
    """FlowSchema defines the schema of a group of flows. Note that a flow is made up of a set of inbound API requests with similar attributes and is identified by a pair of strings: the name of the FlowSchema and a "flow distinguisher"."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta2"
    kind: str = "FlowSchema"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__flowcontrol__v1beta2__FlowSchemaSpec] = None
    status: Optional[io__k8s__api__flowcontrol__v1beta2__FlowSchemaStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__flowcontrol__v1beta2__FlowSchemaSpec] = None,
        status: Optional[io__k8s__api__flowcontrol__v1beta2__FlowSchemaStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__flowcontrol__v1beta2__FlowSchemaList(K8STemplatable):
    """FlowSchemaList is a list of FlowSchema objects."""

    apiVersion: str = "flowcontrol.apiserver.k8s.io/v1beta2"
    kind: str = "FlowSchemaList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__flowcontrol__v1beta2__FlowSchema]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__flowcontrol__v1beta2__FlowSchema],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__networking__v1__Ingress(K8STemplatable):
    """Ingress is a collection of rules that allow inbound connections to reach the endpoints defined by a backend. An Ingress can be configured to give services externally-reachable urls, load balance traffic, terminate SSL, offer name based virtual hosting etc."""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "Ingress"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__networking__v1__IngressSpec] = None
    status: Optional[io__k8s__api__networking__v1__IngressStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__networking__v1__IngressSpec] = None,
        status: Optional[io__k8s__api__networking__v1__IngressStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__networking__v1__IngressList(K8STemplatable):
    """IngressList is a collection of Ingress."""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "IngressList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__networking__v1__Ingress]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__networking__v1__Ingress],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__networking__v1__NetworkPolicy(K8STemplatable):
    """NetworkPolicy describes what network traffic is allowed for a set of Pods"""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "NetworkPolicy"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__networking__v1__NetworkPolicySpec] = None
    status: Optional[io__k8s__api__networking__v1__NetworkPolicyStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__networking__v1__NetworkPolicySpec] = None,
        status: Optional[io__k8s__api__networking__v1__NetworkPolicyStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__networking__v1__NetworkPolicyList(K8STemplatable):
    """NetworkPolicyList is a list of NetworkPolicy objects."""

    apiVersion: str = "networking.k8s.io/v1"
    kind: str = "NetworkPolicyList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__networking__v1__NetworkPolicy]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__networking__v1__NetworkPolicy],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscaler(K8STemplatable):
    """HorizontalPodAutoscaler is the configuration for a horizontal pod autoscaler, which automatically manages the replica count of any resource implementing the scale subresource based on the metrics specified."""

    apiVersion: str = "autoscaling/v2"
    kind: str = "HorizontalPodAutoscaler"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerSpec] = None
    status: Optional[
        io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerSpec
        ] = None,
        status: Optional[
            io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerList(K8STemplatable):
    """HorizontalPodAutoscalerList is a list of horizontal pod autoscaler objects."""

    apiVersion: str = "autoscaling/v2"
    kind: str = "HorizontalPodAutoscalerList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__autoscaling__v2__HorizontalPodAutoscaler]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__autoscaling__v2__HorizontalPodAutoscaler],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscaler(K8STemplatable):
    """HorizontalPodAutoscaler is the configuration for a horizontal pod autoscaler, which automatically manages the replica count of any resource implementing the scale subresource based on the metrics specified."""

    apiVersion: str = "autoscaling/v2beta1"
    kind: str = "HorizontalPodAutoscaler"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[
        io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerSpec
    ] = None
    status: Optional[
        io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerSpec
        ] = None,
        status: Optional[
            io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerList(K8STemplatable):
    """HorizontalPodAutoscaler is a list of horizontal pod autoscaler objects."""

    apiVersion: str = "autoscaling/v2beta1"
    kind: str = "HorizontalPodAutoscalerList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscaler]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscaler],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscaler(K8STemplatable):
    """HorizontalPodAutoscaler is the configuration for a horizontal pod autoscaler, which automatically manages the replica count of any resource implementing the scale subresource based on the metrics specified."""

    apiVersion: str = "autoscaling/v2beta2"
    kind: str = "HorizontalPodAutoscaler"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[
        io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerSpec
    ] = None
    status: Optional[
        io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerStatus
    ] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[
            io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerSpec
        ] = None,
        status: Optional[
            io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerStatus
        ] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerList(K8STemplatable):
    """HorizontalPodAutoscalerList is a list of horizontal pod autoscaler objects."""

    apiVersion: str = "autoscaling/v2beta2"
    kind: str = "HorizontalPodAutoscalerList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscaler]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscaler],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PodSpec(K8STemplatable):
    """PodSpec is a description of a pod."""

    props: List[str] = [
        "activeDeadlineSeconds",
        "affinity",
        "automountServiceAccountToken",
        "containers",
        "dnsConfig",
        "dnsPolicy",
        "enableServiceLinks",
        "ephemeralContainers",
        "hostAliases",
        "hostIPC",
        "hostNetwork",
        "hostPID",
        "hostname",
        "imagePullSecrets",
        "initContainers",
        "nodeName",
        "nodeSelector",
        "os",
        "overhead",
        "preemptionPolicy",
        "priority",
        "priorityClassName",
        "readinessGates",
        "restartPolicy",
        "runtimeClassName",
        "schedulerName",
        "securityContext",
        "serviceAccount",
        "serviceAccountName",
        "setHostnameAsFQDN",
        "shareProcessNamespace",
        "subdomain",
        "terminationGracePeriodSeconds",
        "tolerations",
        "topologySpreadConstraints",
        "volumes",
    ]
    required_props: List[str] = ["containers"]

    activeDeadlineSeconds: Optional[int] = None
    affinity: Optional[io__k8s__api__core__v1__Affinity] = None
    automountServiceAccountToken: Optional[bool] = None
    containers: List[io__k8s__api__core__v1__Container]
    dnsConfig: Optional[io__k8s__api__core__v1__PodDNSConfig] = None
    dnsPolicy: Optional[str] = None
    enableServiceLinks: Optional[bool] = None
    ephemeralContainers: Optional[
        List[io__k8s__api__core__v1__EphemeralContainer]
    ] = None
    hostAliases: Optional[List[io__k8s__api__core__v1__HostAlias]] = None
    hostIPC: Optional[bool] = None
    hostNetwork: Optional[bool] = None
    hostPID: Optional[bool] = None
    hostname: Optional[str] = None
    imagePullSecrets: Optional[
        List[io__k8s__api__core__v1__LocalObjectReference]
    ] = None
    initContainers: Optional[List[io__k8s__api__core__v1__Container]] = None
    nodeName: Optional[str] = None
    nodeSelector: Any
    os: Optional[io__k8s__api__core__v1__PodOS] = None
    overhead: Any
    preemptionPolicy: Optional[str] = None
    priority: Optional[int] = None
    priorityClassName: Optional[str] = None
    readinessGates: Optional[List[io__k8s__api__core__v1__PodReadinessGate]] = None
    restartPolicy: Optional[str] = None
    runtimeClassName: Optional[str] = None
    schedulerName: Optional[str] = None
    securityContext: Optional[io__k8s__api__core__v1__PodSecurityContext] = None
    serviceAccount: Optional[str] = None
    serviceAccountName: Optional[str] = None
    setHostnameAsFQDN: Optional[bool] = None
    shareProcessNamespace: Optional[bool] = None
    subdomain: Optional[str] = None
    terminationGracePeriodSeconds: Optional[int] = None
    tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None
    topologySpreadConstraints: Optional[
        List[io__k8s__api__core__v1__TopologySpreadConstraint]
    ] = None
    volumes: Optional[List[io__k8s__api__core__v1__Volume]] = None

    def __init__(
        self,
        containers: List[io__k8s__api__core__v1__Container],
        activeDeadlineSeconds: Optional[int] = None,
        affinity: Optional[io__k8s__api__core__v1__Affinity] = None,
        automountServiceAccountToken: Optional[bool] = None,
        dnsConfig: Optional[io__k8s__api__core__v1__PodDNSConfig] = None,
        dnsPolicy: Optional[str] = None,
        enableServiceLinks: Optional[bool] = None,
        ephemeralContainers: Optional[
            List[io__k8s__api__core__v1__EphemeralContainer]
        ] = None,
        hostAliases: Optional[List[io__k8s__api__core__v1__HostAlias]] = None,
        hostIPC: Optional[bool] = None,
        hostNetwork: Optional[bool] = None,
        hostPID: Optional[bool] = None,
        hostname: Optional[str] = None,
        imagePullSecrets: Optional[
            List[io__k8s__api__core__v1__LocalObjectReference]
        ] = None,
        initContainers: Optional[List[io__k8s__api__core__v1__Container]] = None,
        nodeName: Optional[str] = None,
        nodeSelector: Any = None,
        os: Optional[io__k8s__api__core__v1__PodOS] = None,
        overhead: Any = None,
        preemptionPolicy: Optional[str] = None,
        priority: Optional[int] = None,
        priorityClassName: Optional[str] = None,
        readinessGates: Optional[List[io__k8s__api__core__v1__PodReadinessGate]] = None,
        restartPolicy: Optional[str] = None,
        runtimeClassName: Optional[str] = None,
        schedulerName: Optional[str] = None,
        securityContext: Optional[io__k8s__api__core__v1__PodSecurityContext] = None,
        serviceAccount: Optional[str] = None,
        serviceAccountName: Optional[str] = None,
        setHostnameAsFQDN: Optional[bool] = None,
        shareProcessNamespace: Optional[bool] = None,
        subdomain: Optional[str] = None,
        terminationGracePeriodSeconds: Optional[int] = None,
        tolerations: Optional[List[io__k8s__api__core__v1__Toleration]] = None,
        topologySpreadConstraints: Optional[
            List[io__k8s__api__core__v1__TopologySpreadConstraint]
        ] = None,
        volumes: Optional[List[io__k8s__api__core__v1__Volume]] = None,
    ):
        super().__init__()
        if containers is not None:
            self.containers = containers
        if activeDeadlineSeconds is not None:
            self.activeDeadlineSeconds = activeDeadlineSeconds
        if affinity is not None:
            self.affinity = affinity
        if automountServiceAccountToken is not None:
            self.automountServiceAccountToken = automountServiceAccountToken
        if dnsConfig is not None:
            self.dnsConfig = dnsConfig
        if dnsPolicy is not None:
            self.dnsPolicy = dnsPolicy
        if enableServiceLinks is not None:
            self.enableServiceLinks = enableServiceLinks
        if ephemeralContainers is not None:
            self.ephemeralContainers = ephemeralContainers
        if hostAliases is not None:
            self.hostAliases = hostAliases
        if hostIPC is not None:
            self.hostIPC = hostIPC
        if hostNetwork is not None:
            self.hostNetwork = hostNetwork
        if hostPID is not None:
            self.hostPID = hostPID
        if hostname is not None:
            self.hostname = hostname
        if imagePullSecrets is not None:
            self.imagePullSecrets = imagePullSecrets
        if initContainers is not None:
            self.initContainers = initContainers
        if nodeName is not None:
            self.nodeName = nodeName
        if nodeSelector is not None:
            self.nodeSelector = nodeSelector
        if os is not None:
            self.os = os
        if overhead is not None:
            self.overhead = overhead
        if preemptionPolicy is not None:
            self.preemptionPolicy = preemptionPolicy
        if priority is not None:
            self.priority = priority
        if priorityClassName is not None:
            self.priorityClassName = priorityClassName
        if readinessGates is not None:
            self.readinessGates = readinessGates
        if restartPolicy is not None:
            self.restartPolicy = restartPolicy
        if runtimeClassName is not None:
            self.runtimeClassName = runtimeClassName
        if schedulerName is not None:
            self.schedulerName = schedulerName
        if securityContext is not None:
            self.securityContext = securityContext
        if serviceAccount is not None:
            self.serviceAccount = serviceAccount
        if serviceAccountName is not None:
            self.serviceAccountName = serviceAccountName
        if setHostnameAsFQDN is not None:
            self.setHostnameAsFQDN = setHostnameAsFQDN
        if shareProcessNamespace is not None:
            self.shareProcessNamespace = shareProcessNamespace
        if subdomain is not None:
            self.subdomain = subdomain
        if terminationGracePeriodSeconds is not None:
            self.terminationGracePeriodSeconds = terminationGracePeriodSeconds
        if tolerations is not None:
            self.tolerations = tolerations
        if topologySpreadConstraints is not None:
            self.topologySpreadConstraints = topologySpreadConstraints
        if volumes is not None:
            self.volumes = volumes


class io__k8s__api__core__v1__PodTemplateSpec(K8STemplatable):
    """PodTemplateSpec describes the data a pod should have when created from a template"""

    props: List[str] = ["metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__PodSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__PodSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__core__v1__ReplicationControllerSpec(K8STemplatable):
    """ReplicationControllerSpec is the specification of a replication controller."""

    props: List[str] = ["minReadySeconds", "replicas", "selector", "template"]
    required_props: List[str] = []

    minReadySeconds: Optional[int] = None
    replicas: Optional[int] = None
    selector: Any
    template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None

    def __init__(
        self,
        minReadySeconds: Optional[int] = None,
        replicas: Optional[int] = None,
        selector: Any = None,
        template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None,
    ):
        super().__init__()
        if minReadySeconds is not None:
            self.minReadySeconds = minReadySeconds
        if replicas is not None:
            self.replicas = replicas
        if selector is not None:
            self.selector = selector
        if template is not None:
            self.template = template


class io__k8s__api__apps__v1__DaemonSetSpec(K8STemplatable):
    """DaemonSetSpec is the specification of a daemon set."""

    props: List[str] = [
        "minReadySeconds",
        "revisionHistoryLimit",
        "selector",
        "template",
        "updateStrategy",
    ]
    required_props: List[str] = ["selector", "template"]

    minReadySeconds: Optional[int] = None
    revisionHistoryLimit: Optional[int] = None
    selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    template: io__k8s__api__core__v1__PodTemplateSpec
    updateStrategy: Optional[io__k8s__api__apps__v1__DaemonSetUpdateStrategy] = None

    def __init__(
        self,
        selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector,
        template: io__k8s__api__core__v1__PodTemplateSpec,
        minReadySeconds: Optional[int] = None,
        revisionHistoryLimit: Optional[int] = None,
        updateStrategy: Optional[
            io__k8s__api__apps__v1__DaemonSetUpdateStrategy
        ] = None,
    ):
        super().__init__()
        if selector is not None:
            self.selector = selector
        if template is not None:
            self.template = template
        if minReadySeconds is not None:
            self.minReadySeconds = minReadySeconds
        if revisionHistoryLimit is not None:
            self.revisionHistoryLimit = revisionHistoryLimit
        if updateStrategy is not None:
            self.updateStrategy = updateStrategy


class io__k8s__api__apps__v1__DeploymentSpec(K8STemplatable):
    """DeploymentSpec is the specification of the desired behavior of the Deployment."""

    props: List[str] = [
        "minReadySeconds",
        "paused",
        "progressDeadlineSeconds",
        "replicas",
        "revisionHistoryLimit",
        "selector",
        "strategy",
        "template",
    ]
    required_props: List[str] = ["selector", "template"]

    minReadySeconds: Optional[int] = None
    paused: Optional[bool] = None
    progressDeadlineSeconds: Optional[int] = None
    replicas: Optional[int] = None
    revisionHistoryLimit: Optional[int] = None
    selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    strategy: Optional[io__k8s__api__apps__v1__DeploymentStrategy] = None
    template: io__k8s__api__core__v1__PodTemplateSpec

    def __init__(
        self,
        selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector,
        template: io__k8s__api__core__v1__PodTemplateSpec,
        minReadySeconds: Optional[int] = None,
        paused: Optional[bool] = None,
        progressDeadlineSeconds: Optional[int] = None,
        replicas: Optional[int] = None,
        revisionHistoryLimit: Optional[int] = None,
        strategy: Optional[io__k8s__api__apps__v1__DeploymentStrategy] = None,
    ):
        super().__init__()
        if selector is not None:
            self.selector = selector
        if template is not None:
            self.template = template
        if minReadySeconds is not None:
            self.minReadySeconds = minReadySeconds
        if paused is not None:
            self.paused = paused
        if progressDeadlineSeconds is not None:
            self.progressDeadlineSeconds = progressDeadlineSeconds
        if replicas is not None:
            self.replicas = replicas
        if revisionHistoryLimit is not None:
            self.revisionHistoryLimit = revisionHistoryLimit
        if strategy is not None:
            self.strategy = strategy


class io__k8s__api__apps__v1__ReplicaSetSpec(K8STemplatable):
    """ReplicaSetSpec is the specification of a ReplicaSet."""

    props: List[str] = ["minReadySeconds", "replicas", "selector", "template"]
    required_props: List[str] = ["selector"]

    minReadySeconds: Optional[int] = None
    replicas: Optional[int] = None
    selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None

    def __init__(
        self,
        selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector,
        minReadySeconds: Optional[int] = None,
        replicas: Optional[int] = None,
        template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None,
    ):
        super().__init__()
        if selector is not None:
            self.selector = selector
        if minReadySeconds is not None:
            self.minReadySeconds = minReadySeconds
        if replicas is not None:
            self.replicas = replicas
        if template is not None:
            self.template = template


class io__k8s__api__apps__v1__StatefulSetSpec(K8STemplatable):
    """A StatefulSetSpec is the specification of a StatefulSet."""

    props: List[str] = [
        "minReadySeconds",
        "persistentVolumeClaimRetentionPolicy",
        "podManagementPolicy",
        "replicas",
        "revisionHistoryLimit",
        "selector",
        "serviceName",
        "template",
        "updateStrategy",
        "volumeClaimTemplates",
    ]
    required_props: List[str] = ["selector", "template", "serviceName"]

    minReadySeconds: Optional[int] = None
    persistentVolumeClaimRetentionPolicy: Optional[
        io__k8s__api__apps__v1__StatefulSetPersistentVolumeClaimRetentionPolicy
    ] = None
    podManagementPolicy: Optional[str] = None
    replicas: Optional[int] = None
    revisionHistoryLimit: Optional[int] = None
    selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
    serviceName: str
    template: io__k8s__api__core__v1__PodTemplateSpec
    updateStrategy: Optional[io__k8s__api__apps__v1__StatefulSetUpdateStrategy] = None
    volumeClaimTemplates: Optional[
        List[io__k8s__api__core__v1__PersistentVolumeClaim]
    ] = None

    def __init__(
        self,
        selector: io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector,
        serviceName: str,
        template: io__k8s__api__core__v1__PodTemplateSpec,
        minReadySeconds: Optional[int] = None,
        persistentVolumeClaimRetentionPolicy: Optional[
            io__k8s__api__apps__v1__StatefulSetPersistentVolumeClaimRetentionPolicy
        ] = None,
        podManagementPolicy: Optional[str] = None,
        replicas: Optional[int] = None,
        revisionHistoryLimit: Optional[int] = None,
        updateStrategy: Optional[
            io__k8s__api__apps__v1__StatefulSetUpdateStrategy
        ] = None,
        volumeClaimTemplates: Optional[
            List[io__k8s__api__core__v1__PersistentVolumeClaim]
        ] = None,
    ):
        super().__init__()
        if selector is not None:
            self.selector = selector
        if serviceName is not None:
            self.serviceName = serviceName
        if template is not None:
            self.template = template
        if minReadySeconds is not None:
            self.minReadySeconds = minReadySeconds
        if persistentVolumeClaimRetentionPolicy is not None:
            self.persistentVolumeClaimRetentionPolicy = (
                persistentVolumeClaimRetentionPolicy
            )
        if podManagementPolicy is not None:
            self.podManagementPolicy = podManagementPolicy
        if replicas is not None:
            self.replicas = replicas
        if revisionHistoryLimit is not None:
            self.revisionHistoryLimit = revisionHistoryLimit
        if updateStrategy is not None:
            self.updateStrategy = updateStrategy
        if volumeClaimTemplates is not None:
            self.volumeClaimTemplates = volumeClaimTemplates


class io__k8s__api__batch__v1__JobSpec(K8STemplatable):
    """JobSpec describes how the job execution will look like."""

    props: List[str] = [
        "activeDeadlineSeconds",
        "backoffLimit",
        "completionMode",
        "completions",
        "manualSelector",
        "parallelism",
        "selector",
        "suspend",
        "template",
        "ttlSecondsAfterFinished",
    ]
    required_props: List[str] = ["template"]

    activeDeadlineSeconds: Optional[int] = None
    backoffLimit: Optional[int] = None
    completionMode: Optional[str] = None
    completions: Optional[int] = None
    manualSelector: Optional[bool] = None
    parallelism: Optional[int] = None
    selector: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector] = None
    suspend: Optional[bool] = None
    template: io__k8s__api__core__v1__PodTemplateSpec
    ttlSecondsAfterFinished: Optional[int] = None

    def __init__(
        self,
        template: io__k8s__api__core__v1__PodTemplateSpec,
        activeDeadlineSeconds: Optional[int] = None,
        backoffLimit: Optional[int] = None,
        completionMode: Optional[str] = None,
        completions: Optional[int] = None,
        manualSelector: Optional[bool] = None,
        parallelism: Optional[int] = None,
        selector: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
        ] = None,
        suspend: Optional[bool] = None,
        ttlSecondsAfterFinished: Optional[int] = None,
    ):
        super().__init__()
        if template is not None:
            self.template = template
        if activeDeadlineSeconds is not None:
            self.activeDeadlineSeconds = activeDeadlineSeconds
        if backoffLimit is not None:
            self.backoffLimit = backoffLimit
        if completionMode is not None:
            self.completionMode = completionMode
        if completions is not None:
            self.completions = completions
        if manualSelector is not None:
            self.manualSelector = manualSelector
        if parallelism is not None:
            self.parallelism = parallelism
        if selector is not None:
            self.selector = selector
        if suspend is not None:
            self.suspend = suspend
        if ttlSecondsAfterFinished is not None:
            self.ttlSecondsAfterFinished = ttlSecondsAfterFinished


class io__k8s__api__batch__v1__JobTemplateSpec(K8STemplatable):
    """JobTemplateSpec describes the data a Job should have when created from a template"""

    props: List[str] = ["metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__batch__v1__JobSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__batch__v1__JobSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__batch__v1beta1__JobTemplateSpec(K8STemplatable):
    """JobTemplateSpec describes the data a Job should have when created from a template"""

    props: List[str] = ["metadata", "spec"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__batch__v1__JobSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__batch__v1__JobSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec


class io__k8s__api__core__v1__Pod(K8STemplatable):
    """Pod is a collection of containers that can run on a host. This resource is created by clients and scheduled onto hosts."""

    apiVersion: str = "v1"
    kind: str = "Pod"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__PodSpec] = None
    status: Optional[io__k8s__api__core__v1__PodStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__PodSpec] = None,
        status: Optional[io__k8s__api__core__v1__PodStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__PodList(K8STemplatable):
    """PodList is a list of Pods."""

    apiVersion: str = "v1"
    kind: str = "PodList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__Pod]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__Pod],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__PodTemplate(K8STemplatable):
    """PodTemplate describes a template for creating copies of a predefined pod."""

    apiVersion: str = "v1"
    kind: str = "PodTemplate"

    props: List[str] = ["apiVersion", "kind", "metadata", "template"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        template: Optional[io__k8s__api__core__v1__PodTemplateSpec] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if template is not None:
            self.template = template


class io__k8s__api__core__v1__PodTemplateList(K8STemplatable):
    """PodTemplateList is a list of PodTemplates."""

    apiVersion: str = "v1"
    kind: str = "PodTemplateList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__PodTemplate]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__PodTemplate],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__core__v1__ReplicationController(K8STemplatable):
    """ReplicationController represents the configuration of a replication controller."""

    apiVersion: str = "v1"
    kind: str = "ReplicationController"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__core__v1__ReplicationControllerSpec] = None
    status: Optional[io__k8s__api__core__v1__ReplicationControllerStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__core__v1__ReplicationControllerSpec] = None,
        status: Optional[io__k8s__api__core__v1__ReplicationControllerStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__core__v1__ReplicationControllerList(K8STemplatable):
    """ReplicationControllerList is a collection of replication controllers."""

    apiVersion: str = "v1"
    kind: str = "ReplicationControllerList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__core__v1__ReplicationController]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__core__v1__ReplicationController],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__DaemonSet(K8STemplatable):
    """DaemonSet represents the configuration of a daemon set."""

    apiVersion: str = "apps/v1"
    kind: str = "DaemonSet"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__apps__v1__DaemonSetSpec] = None
    status: Optional[io__k8s__api__apps__v1__DaemonSetStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__apps__v1__DaemonSetSpec] = None,
        status: Optional[io__k8s__api__apps__v1__DaemonSetStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__apps__v1__DaemonSetList(K8STemplatable):
    """DaemonSetList is a collection of daemon sets."""

    apiVersion: str = "apps/v1"
    kind: str = "DaemonSetList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apps__v1__DaemonSet]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apps__v1__DaemonSet],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__Deployment(K8STemplatable):
    """Deployment enables declarative updates for Pods and ReplicaSets."""

    apiVersion: str = "apps/v1"
    kind: str = "Deployment"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__apps__v1__DeploymentSpec] = None
    status: Optional[io__k8s__api__apps__v1__DeploymentStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__apps__v1__DeploymentSpec] = None,
        status: Optional[io__k8s__api__apps__v1__DeploymentStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__apps__v1__DeploymentList(K8STemplatable):
    """DeploymentList is a list of Deployments."""

    apiVersion: str = "apps/v1"
    kind: str = "DeploymentList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apps__v1__Deployment]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apps__v1__Deployment],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__ReplicaSet(K8STemplatable):
    """ReplicaSet ensures that a specified number of pod replicas are running at any given time."""

    apiVersion: str = "apps/v1"
    kind: str = "ReplicaSet"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__apps__v1__ReplicaSetSpec] = None
    status: Optional[io__k8s__api__apps__v1__ReplicaSetStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__apps__v1__ReplicaSetSpec] = None,
        status: Optional[io__k8s__api__apps__v1__ReplicaSetStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__apps__v1__ReplicaSetList(K8STemplatable):
    """ReplicaSetList is a collection of ReplicaSets."""

    apiVersion: str = "apps/v1"
    kind: str = "ReplicaSetList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apps__v1__ReplicaSet]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apps__v1__ReplicaSet],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__apps__v1__StatefulSet(K8STemplatable):
    """StatefulSet represents a set of pods with consistent identities. Identities are defined as:
     - Network: A single stable DNS and hostname.
     - Storage: As many VolumeClaims as requested.
    The StatefulSet guarantees that a given network identity will always map to the same storage identity."""

    apiVersion: str = "apps/v1"
    kind: str = "StatefulSet"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__apps__v1__StatefulSetSpec] = None
    status: Optional[io__k8s__api__apps__v1__StatefulSetStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__apps__v1__StatefulSetSpec] = None,
        status: Optional[io__k8s__api__apps__v1__StatefulSetStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__apps__v1__StatefulSetList(K8STemplatable):
    """StatefulSetList is a collection of StatefulSets."""

    apiVersion: str = "apps/v1"
    kind: str = "StatefulSetList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__apps__v1__StatefulSet]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__apps__v1__StatefulSet],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__batch__v1__CronJobSpec(K8STemplatable):
    """CronJobSpec describes how the job execution will look like and when it will actually run."""

    props: List[str] = [
        "concurrencyPolicy",
        "failedJobsHistoryLimit",
        "jobTemplate",
        "schedule",
        "startingDeadlineSeconds",
        "successfulJobsHistoryLimit",
        "suspend",
        "timeZone",
    ]
    required_props: List[str] = ["schedule", "jobTemplate"]

    concurrencyPolicy: Optional[str] = None
    failedJobsHistoryLimit: Optional[int] = None
    jobTemplate: io__k8s__api__batch__v1__JobTemplateSpec
    schedule: str
    startingDeadlineSeconds: Optional[int] = None
    successfulJobsHistoryLimit: Optional[int] = None
    suspend: Optional[bool] = None
    timeZone: Optional[str] = None

    def __init__(
        self,
        jobTemplate: io__k8s__api__batch__v1__JobTemplateSpec,
        schedule: str,
        concurrencyPolicy: Optional[str] = None,
        failedJobsHistoryLimit: Optional[int] = None,
        startingDeadlineSeconds: Optional[int] = None,
        successfulJobsHistoryLimit: Optional[int] = None,
        suspend: Optional[bool] = None,
        timeZone: Optional[str] = None,
    ):
        super().__init__()
        if jobTemplate is not None:
            self.jobTemplate = jobTemplate
        if schedule is not None:
            self.schedule = schedule
        if concurrencyPolicy is not None:
            self.concurrencyPolicy = concurrencyPolicy
        if failedJobsHistoryLimit is not None:
            self.failedJobsHistoryLimit = failedJobsHistoryLimit
        if startingDeadlineSeconds is not None:
            self.startingDeadlineSeconds = startingDeadlineSeconds
        if successfulJobsHistoryLimit is not None:
            self.successfulJobsHistoryLimit = successfulJobsHistoryLimit
        if suspend is not None:
            self.suspend = suspend
        if timeZone is not None:
            self.timeZone = timeZone


class io__k8s__api__batch__v1__Job(K8STemplatable):
    """Job represents the configuration of a single job."""

    apiVersion: str = "batch/v1"
    kind: str = "Job"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__batch__v1__JobSpec] = None
    status: Optional[io__k8s__api__batch__v1__JobStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__batch__v1__JobSpec] = None,
        status: Optional[io__k8s__api__batch__v1__JobStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__batch__v1__JobList(K8STemplatable):
    """JobList is a collection of jobs."""

    apiVersion: str = "batch/v1"
    kind: str = "JobList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__batch__v1__Job]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__batch__v1__Job],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__batch__v1beta1__CronJobSpec(K8STemplatable):
    """CronJobSpec describes how the job execution will look like and when it will actually run."""

    props: List[str] = [
        "concurrencyPolicy",
        "failedJobsHistoryLimit",
        "jobTemplate",
        "schedule",
        "startingDeadlineSeconds",
        "successfulJobsHistoryLimit",
        "suspend",
        "timeZone",
    ]
    required_props: List[str] = ["schedule", "jobTemplate"]

    concurrencyPolicy: Optional[str] = None
    failedJobsHistoryLimit: Optional[int] = None
    jobTemplate: io__k8s__api__batch__v1beta1__JobTemplateSpec
    schedule: str
    startingDeadlineSeconds: Optional[int] = None
    successfulJobsHistoryLimit: Optional[int] = None
    suspend: Optional[bool] = None
    timeZone: Optional[str] = None

    def __init__(
        self,
        jobTemplate: io__k8s__api__batch__v1beta1__JobTemplateSpec,
        schedule: str,
        concurrencyPolicy: Optional[str] = None,
        failedJobsHistoryLimit: Optional[int] = None,
        startingDeadlineSeconds: Optional[int] = None,
        successfulJobsHistoryLimit: Optional[int] = None,
        suspend: Optional[bool] = None,
        timeZone: Optional[str] = None,
    ):
        super().__init__()
        if jobTemplate is not None:
            self.jobTemplate = jobTemplate
        if schedule is not None:
            self.schedule = schedule
        if concurrencyPolicy is not None:
            self.concurrencyPolicy = concurrencyPolicy
        if failedJobsHistoryLimit is not None:
            self.failedJobsHistoryLimit = failedJobsHistoryLimit
        if startingDeadlineSeconds is not None:
            self.startingDeadlineSeconds = startingDeadlineSeconds
        if successfulJobsHistoryLimit is not None:
            self.successfulJobsHistoryLimit = successfulJobsHistoryLimit
        if suspend is not None:
            self.suspend = suspend
        if timeZone is not None:
            self.timeZone = timeZone


class io__k8s__api__batch__v1__CronJob(K8STemplatable):
    """CronJob represents the configuration of a single cron job."""

    apiVersion: str = "batch/v1"
    kind: str = "CronJob"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__batch__v1__CronJobSpec] = None
    status: Optional[io__k8s__api__batch__v1__CronJobStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__batch__v1__CronJobSpec] = None,
        status: Optional[io__k8s__api__batch__v1__CronJobStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__batch__v1__CronJobList(K8STemplatable):
    """CronJobList is a collection of cron jobs."""

    apiVersion: str = "batch/v1"
    kind: str = "CronJobList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__batch__v1__CronJob]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__batch__v1__CronJob],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


class io__k8s__api__batch__v1beta1__CronJob(K8STemplatable):
    """CronJob represents the configuration of a single cron job."""

    apiVersion: str = "batch/v1beta1"
    kind: str = "CronJob"

    props: List[str] = ["apiVersion", "kind", "metadata", "spec", "status"]
    required_props: List[str] = []

    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta] = None
    spec: Optional[io__k8s__api__batch__v1beta1__CronJobSpec] = None
    status: Optional[io__k8s__api__batch__v1beta1__CronJobStatus] = None

    def __init__(
        self,
        metadata: Optional[
            io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
        ] = None,
        spec: Optional[io__k8s__api__batch__v1beta1__CronJobSpec] = None,
        status: Optional[io__k8s__api__batch__v1beta1__CronJobStatus] = None,
    ):
        super().__init__()
        if metadata is not None:
            self.metadata = metadata
        if spec is not None:
            self.spec = spec
        if status is not None:
            self.status = status


class io__k8s__api__batch__v1beta1__CronJobList(K8STemplatable):
    """CronJobList is a collection of cron jobs."""

    apiVersion: str = "batch/v1beta1"
    kind: str = "CronJobList"

    props: List[str] = ["apiVersion", "items", "kind", "metadata"]
    required_props: List[str] = ["items"]

    items: List[io__k8s__api__batch__v1beta1__CronJob]
    metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None

    def __init__(
        self,
        items: List[io__k8s__api__batch__v1beta1__CronJob],
        metadata: Optional[io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta] = None,
    ):
        super().__init__()
        if items is not None:
            self.items = items
        if metadata is not None:
            self.metadata = metadata


MutatingWebhook = io__k8s__api__admissionregistration__v1__MutatingWebhook
MutatingWebhookConfiguration = (
    io__k8s__api__admissionregistration__v1__MutatingWebhookConfiguration
)
MutatingWebhookConfigurationList = (
    io__k8s__api__admissionregistration__v1__MutatingWebhookConfigurationList
)
RuleWithOperations = io__k8s__api__admissionregistration__v1__RuleWithOperations
ServiceReference = (
    io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__ServiceReference
)
ValidatingWebhook = io__k8s__api__admissionregistration__v1__ValidatingWebhook
ValidatingWebhookConfiguration = (
    io__k8s__api__admissionregistration__v1__ValidatingWebhookConfiguration
)
ValidatingWebhookConfigurationList = (
    io__k8s__api__admissionregistration__v1__ValidatingWebhookConfigurationList
)
WebhookClientConfig = io__k8s__api__admissionregistration__v1__WebhookClientConfig
ServerStorageVersion = io__k8s__api__apiserverinternal__v1alpha1__ServerStorageVersion
StorageVersion = io__k8s__api__apiserverinternal__v1alpha1__StorageVersion
StorageVersionCondition = (
    io__k8s__api__apiserverinternal__v1alpha1__StorageVersionCondition
)
StorageVersionList = io__k8s__api__apiserverinternal__v1alpha1__StorageVersionList
StorageVersionSpec = io__k8s__api__apiserverinternal__v1alpha1__StorageVersionSpec
StorageVersionStatus = io__k8s__api__apiserverinternal__v1alpha1__StorageVersionStatus
ControllerRevision = io__k8s__api__apps__v1__ControllerRevision
ControllerRevisionList = io__k8s__api__apps__v1__ControllerRevisionList
DaemonSet = io__k8s__api__apps__v1__DaemonSet
DaemonSetCondition = io__k8s__api__apps__v1__DaemonSetCondition
DaemonSetList = io__k8s__api__apps__v1__DaemonSetList
DaemonSetSpec = io__k8s__api__apps__v1__DaemonSetSpec
DaemonSetStatus = io__k8s__api__apps__v1__DaemonSetStatus
DaemonSetUpdateStrategy = io__k8s__api__apps__v1__DaemonSetUpdateStrategy
Deployment = io__k8s__api__apps__v1__Deployment
DeploymentCondition = io__k8s__api__apps__v1__DeploymentCondition
DeploymentList = io__k8s__api__apps__v1__DeploymentList
DeploymentSpec = io__k8s__api__apps__v1__DeploymentSpec
DeploymentStatus = io__k8s__api__apps__v1__DeploymentStatus
DeploymentStrategy = io__k8s__api__apps__v1__DeploymentStrategy
ReplicaSet = io__k8s__api__apps__v1__ReplicaSet
ReplicaSetCondition = io__k8s__api__apps__v1__ReplicaSetCondition
ReplicaSetList = io__k8s__api__apps__v1__ReplicaSetList
ReplicaSetSpec = io__k8s__api__apps__v1__ReplicaSetSpec
ReplicaSetStatus = io__k8s__api__apps__v1__ReplicaSetStatus
RollingUpdateDaemonSet = io__k8s__api__apps__v1__RollingUpdateDaemonSet
RollingUpdateDeployment = io__k8s__api__apps__v1__RollingUpdateDeployment
RollingUpdateStatefulSetStrategy = (
    io__k8s__api__apps__v1__RollingUpdateStatefulSetStrategy
)
StatefulSet = io__k8s__api__apps__v1__StatefulSet
StatefulSetCondition = io__k8s__api__apps__v1__StatefulSetCondition
StatefulSetList = io__k8s__api__apps__v1__StatefulSetList
StatefulSetPersistentVolumeClaimRetentionPolicy = (
    io__k8s__api__apps__v1__StatefulSetPersistentVolumeClaimRetentionPolicy
)
StatefulSetSpec = io__k8s__api__apps__v1__StatefulSetSpec
StatefulSetStatus = io__k8s__api__apps__v1__StatefulSetStatus
StatefulSetUpdateStrategy = io__k8s__api__apps__v1__StatefulSetUpdateStrategy
BoundObjectReference = io__k8s__api__authentication__v1__BoundObjectReference
TokenRequest = io__k8s__api__storage__v1__TokenRequest
TokenRequestSpec = io__k8s__api__authentication__v1__TokenRequestSpec
TokenRequestStatus = io__k8s__api__authentication__v1__TokenRequestStatus
TokenReview = io__k8s__api__authentication__v1__TokenReview
TokenReviewSpec = io__k8s__api__authentication__v1__TokenReviewSpec
TokenReviewStatus = io__k8s__api__authentication__v1__TokenReviewStatus
UserInfo = io__k8s__api__authentication__v1__UserInfo
LocalSubjectAccessReview = io__k8s__api__authorization__v1__LocalSubjectAccessReview
NonResourceAttributes = io__k8s__api__authorization__v1__NonResourceAttributes
NonResourceRule = io__k8s__api__authorization__v1__NonResourceRule
ResourceAttributes = io__k8s__api__authorization__v1__ResourceAttributes
ResourceRule = io__k8s__api__authorization__v1__ResourceRule
SelfSubjectAccessReview = io__k8s__api__authorization__v1__SelfSubjectAccessReview
SelfSubjectAccessReviewSpec = (
    io__k8s__api__authorization__v1__SelfSubjectAccessReviewSpec
)
SelfSubjectRulesReview = io__k8s__api__authorization__v1__SelfSubjectRulesReview
SelfSubjectRulesReviewSpec = io__k8s__api__authorization__v1__SelfSubjectRulesReviewSpec
SubjectAccessReview = io__k8s__api__authorization__v1__SubjectAccessReview
SubjectAccessReviewSpec = io__k8s__api__authorization__v1__SubjectAccessReviewSpec
SubjectAccessReviewStatus = io__k8s__api__authorization__v1__SubjectAccessReviewStatus
SubjectRulesReviewStatus = io__k8s__api__authorization__v1__SubjectRulesReviewStatus
CrossVersionObjectReference = (
    io__k8s__api__autoscaling__v2beta2__CrossVersionObjectReference
)
HorizontalPodAutoscaler = io__k8s__api__autoscaling__v1__HorizontalPodAutoscaler
HorizontalPodAutoscalerList = io__k8s__api__autoscaling__v1__HorizontalPodAutoscalerList
HorizontalPodAutoscalerSpec = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerSpec
)
HorizontalPodAutoscalerStatus = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerStatus
)
Scale = io__k8s__api__autoscaling__v1__Scale
ScaleSpec = io__k8s__api__autoscaling__v1__ScaleSpec
ScaleStatus = io__k8s__api__autoscaling__v1__ScaleStatus
ContainerResourceMetricSource = (
    io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricSource
)
ContainerResourceMetricStatus = (
    io__k8s__api__autoscaling__v2beta2__ContainerResourceMetricStatus
)
ExternalMetricSource = io__k8s__api__autoscaling__v2beta2__ExternalMetricSource
ExternalMetricStatus = io__k8s__api__autoscaling__v2beta2__ExternalMetricStatus
HPAScalingPolicy = io__k8s__api__autoscaling__v2beta2__HPAScalingPolicy
HPAScalingRules = io__k8s__api__autoscaling__v2beta2__HPAScalingRules
autoscaling_v2_HorizontalPodAutoscaler = (
    io__k8s__api__autoscaling__v2__HorizontalPodAutoscaler
)
HorizontalPodAutoscalerBehavior = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerBehavior
)
HorizontalPodAutoscalerCondition = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerCondition
)
autoscaling_v2_HorizontalPodAutoscalerList = (
    io__k8s__api__autoscaling__v2__HorizontalPodAutoscalerList
)
MetricIdentifier = io__k8s__api__autoscaling__v2beta2__MetricIdentifier
MetricSpec = io__k8s__api__autoscaling__v2beta2__MetricSpec
MetricStatus = io__k8s__api__autoscaling__v2beta2__MetricStatus
MetricTarget = io__k8s__api__autoscaling__v2beta2__MetricTarget
MetricValueStatus = io__k8s__api__autoscaling__v2beta2__MetricValueStatus
ObjectMetricSource = io__k8s__api__autoscaling__v2beta2__ObjectMetricSource
ObjectMetricStatus = io__k8s__api__autoscaling__v2beta2__ObjectMetricStatus
PodsMetricSource = io__k8s__api__autoscaling__v2beta2__PodsMetricSource
PodsMetricStatus = io__k8s__api__autoscaling__v2beta2__PodsMetricStatus
ResourceMetricSource = io__k8s__api__autoscaling__v2beta2__ResourceMetricSource
ResourceMetricStatus = io__k8s__api__autoscaling__v2beta2__ResourceMetricStatus
autoscaling_v2beta1_HorizontalPodAutoscaler = (
    io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscaler
)
autoscaling_v2beta1_HorizontalPodAutoscalerList = (
    io__k8s__api__autoscaling__v2beta1__HorizontalPodAutoscalerList
)
autoscaling_v2beta2_HorizontalPodAutoscaler = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscaler
)
autoscaling_v2beta2_HorizontalPodAutoscalerList = (
    io__k8s__api__autoscaling__v2beta2__HorizontalPodAutoscalerList
)
CronJob = io__k8s__api__batch__v1__CronJob
CronJobList = io__k8s__api__batch__v1__CronJobList
CronJobSpec = io__k8s__api__batch__v1beta1__CronJobSpec
CronJobStatus = io__k8s__api__batch__v1beta1__CronJobStatus
Job = io__k8s__api__batch__v1__Job
JobCondition = io__k8s__api__batch__v1__JobCondition
JobList = io__k8s__api__batch__v1__JobList
JobSpec = io__k8s__api__batch__v1__JobSpec
JobStatus = io__k8s__api__batch__v1__JobStatus
JobTemplateSpec = io__k8s__api__batch__v1beta1__JobTemplateSpec
UncountedTerminatedPods = io__k8s__api__batch__v1__UncountedTerminatedPods
batch_v1beta1_CronJob = io__k8s__api__batch__v1beta1__CronJob
batch_v1beta1_CronJobList = io__k8s__api__batch__v1beta1__CronJobList
CertificateSigningRequest = io__k8s__api__certificates__v1__CertificateSigningRequest
CertificateSigningRequestCondition = (
    io__k8s__api__certificates__v1__CertificateSigningRequestCondition
)
CertificateSigningRequestList = (
    io__k8s__api__certificates__v1__CertificateSigningRequestList
)
CertificateSigningRequestSpec = (
    io__k8s__api__certificates__v1__CertificateSigningRequestSpec
)
CertificateSigningRequestStatus = (
    io__k8s__api__certificates__v1__CertificateSigningRequestStatus
)
Lease = io__k8s__api__coordination__v1__Lease
LeaseList = io__k8s__api__coordination__v1__LeaseList
LeaseSpec = io__k8s__api__coordination__v1__LeaseSpec
AWSElasticBlockStoreVolumeSource = (
    io__k8s__api__core__v1__AWSElasticBlockStoreVolumeSource
)
Affinity = io__k8s__api__core__v1__Affinity
AttachedVolume = io__k8s__api__core__v1__AttachedVolume
AzureDiskVolumeSource = io__k8s__api__core__v1__AzureDiskVolumeSource
AzureFilePersistentVolumeSource = (
    io__k8s__api__core__v1__AzureFilePersistentVolumeSource
)
AzureFileVolumeSource = io__k8s__api__core__v1__AzureFileVolumeSource
Binding = io__k8s__api__core__v1__Binding
CSIPersistentVolumeSource = io__k8s__api__core__v1__CSIPersistentVolumeSource
CSIVolumeSource = io__k8s__api__core__v1__CSIVolumeSource
Capabilities = io__k8s__api__core__v1__Capabilities
CephFSPersistentVolumeSource = io__k8s__api__core__v1__CephFSPersistentVolumeSource
CephFSVolumeSource = io__k8s__api__core__v1__CephFSVolumeSource
CinderPersistentVolumeSource = io__k8s__api__core__v1__CinderPersistentVolumeSource
CinderVolumeSource = io__k8s__api__core__v1__CinderVolumeSource
ClientIPConfig = io__k8s__api__core__v1__ClientIPConfig
ComponentCondition = io__k8s__api__core__v1__ComponentCondition
ComponentStatus = io__k8s__api__core__v1__ComponentStatus
ComponentStatusList = io__k8s__api__core__v1__ComponentStatusList
ConfigMap = io__k8s__api__core__v1__ConfigMap
ConfigMapEnvSource = io__k8s__api__core__v1__ConfigMapEnvSource
ConfigMapKeySelector = io__k8s__api__core__v1__ConfigMapKeySelector
ConfigMapList = io__k8s__api__core__v1__ConfigMapList
ConfigMapNodeConfigSource = io__k8s__api__core__v1__ConfigMapNodeConfigSource
ConfigMapProjection = io__k8s__api__core__v1__ConfigMapProjection
ConfigMapVolumeSource = io__k8s__api__core__v1__ConfigMapVolumeSource
Container = io__k8s__api__core__v1__Container
ContainerImage = io__k8s__api__core__v1__ContainerImage
ContainerPort = io__k8s__api__core__v1__ContainerPort
ContainerState = io__k8s__api__core__v1__ContainerState
ContainerStateRunning = io__k8s__api__core__v1__ContainerStateRunning
ContainerStateTerminated = io__k8s__api__core__v1__ContainerStateTerminated
ContainerStateWaiting = io__k8s__api__core__v1__ContainerStateWaiting
ContainerStatus = io__k8s__api__core__v1__ContainerStatus
DaemonEndpoint = io__k8s__api__core__v1__DaemonEndpoint
DownwardAPIProjection = io__k8s__api__core__v1__DownwardAPIProjection
DownwardAPIVolumeFile = io__k8s__api__core__v1__DownwardAPIVolumeFile
DownwardAPIVolumeSource = io__k8s__api__core__v1__DownwardAPIVolumeSource
EmptyDirVolumeSource = io__k8s__api__core__v1__EmptyDirVolumeSource
EndpointAddress = io__k8s__api__core__v1__EndpointAddress
EndpointPort = io__k8s__api__discovery__v1beta1__EndpointPort
EndpointSubset = io__k8s__api__core__v1__EndpointSubset
Endpoints = io__k8s__api__core__v1__Endpoints
EndpointsList = io__k8s__api__core__v1__EndpointsList
EnvFromSource = io__k8s__api__core__v1__EnvFromSource
EnvVar = io__k8s__api__core__v1__EnvVar
EnvVarSource = io__k8s__api__core__v1__EnvVarSource
EphemeralContainer = io__k8s__api__core__v1__EphemeralContainer
EphemeralVolumeSource = io__k8s__api__core__v1__EphemeralVolumeSource
Event = io__k8s__api__core__v1__Event
EventList = io__k8s__api__core__v1__EventList
EventSeries = io__k8s__api__events__v1beta1__EventSeries
EventSource = io__k8s__api__core__v1__EventSource
ExecAction = io__k8s__api__core__v1__ExecAction
FCVolumeSource = io__k8s__api__core__v1__FCVolumeSource
FlexPersistentVolumeSource = io__k8s__api__core__v1__FlexPersistentVolumeSource
FlexVolumeSource = io__k8s__api__core__v1__FlexVolumeSource
FlockerVolumeSource = io__k8s__api__core__v1__FlockerVolumeSource
GCEPersistentDiskVolumeSource = io__k8s__api__core__v1__GCEPersistentDiskVolumeSource
GRPCAction = io__k8s__api__core__v1__GRPCAction
GitRepoVolumeSource = io__k8s__api__core__v1__GitRepoVolumeSource
GlusterfsPersistentVolumeSource = (
    io__k8s__api__core__v1__GlusterfsPersistentVolumeSource
)
GlusterfsVolumeSource = io__k8s__api__core__v1__GlusterfsVolumeSource
HTTPGetAction = io__k8s__api__core__v1__HTTPGetAction
HTTPHeader = io__k8s__api__core__v1__HTTPHeader
HostAlias = io__k8s__api__core__v1__HostAlias
HostPathVolumeSource = io__k8s__api__core__v1__HostPathVolumeSource
ISCSIPersistentVolumeSource = io__k8s__api__core__v1__ISCSIPersistentVolumeSource
ISCSIVolumeSource = io__k8s__api__core__v1__ISCSIVolumeSource
KeyToPath = io__k8s__api__core__v1__KeyToPath
Lifecycle = io__k8s__api__core__v1__Lifecycle
LifecycleHandler = io__k8s__api__core__v1__LifecycleHandler
LimitRange = io__k8s__api__core__v1__LimitRange
LimitRangeItem = io__k8s__api__core__v1__LimitRangeItem
LimitRangeList = io__k8s__api__core__v1__LimitRangeList
LimitRangeSpec = io__k8s__api__core__v1__LimitRangeSpec
LoadBalancerIngress = io__k8s__api__core__v1__LoadBalancerIngress
LoadBalancerStatus = io__k8s__api__core__v1__LoadBalancerStatus
LocalObjectReference = io__k8s__api__core__v1__LocalObjectReference
LocalVolumeSource = io__k8s__api__core__v1__LocalVolumeSource
NFSVolumeSource = io__k8s__api__core__v1__NFSVolumeSource
Namespace = io__k8s__api__core__v1__Namespace
NamespaceCondition = io__k8s__api__core__v1__NamespaceCondition
NamespaceList = io__k8s__api__core__v1__NamespaceList
NamespaceSpec = io__k8s__api__core__v1__NamespaceSpec
NamespaceStatus = io__k8s__api__core__v1__NamespaceStatus
Node = io__k8s__api__core__v1__Node
NodeAddress = io__k8s__api__core__v1__NodeAddress
NodeAffinity = io__k8s__api__core__v1__NodeAffinity
NodeCondition = io__k8s__api__core__v1__NodeCondition
NodeConfigSource = io__k8s__api__core__v1__NodeConfigSource
NodeConfigStatus = io__k8s__api__core__v1__NodeConfigStatus
NodeDaemonEndpoints = io__k8s__api__core__v1__NodeDaemonEndpoints
NodeList = io__k8s__api__core__v1__NodeList
NodeSelector = io__k8s__api__core__v1__NodeSelector
NodeSelectorRequirement = io__k8s__api__core__v1__NodeSelectorRequirement
NodeSelectorTerm = io__k8s__api__core__v1__NodeSelectorTerm
NodeSpec = io__k8s__api__core__v1__NodeSpec
NodeStatus = io__k8s__api__core__v1__NodeStatus
NodeSystemInfo = io__k8s__api__core__v1__NodeSystemInfo
ObjectFieldSelector = io__k8s__api__core__v1__ObjectFieldSelector
ObjectReference = io__k8s__api__core__v1__ObjectReference
PersistentVolume = io__k8s__api__core__v1__PersistentVolume
PersistentVolumeClaim = io__k8s__api__core__v1__PersistentVolumeClaim
PersistentVolumeClaimCondition = io__k8s__api__core__v1__PersistentVolumeClaimCondition
PersistentVolumeClaimList = io__k8s__api__core__v1__PersistentVolumeClaimList
PersistentVolumeClaimSpec = io__k8s__api__core__v1__PersistentVolumeClaimSpec
PersistentVolumeClaimStatus = io__k8s__api__core__v1__PersistentVolumeClaimStatus
PersistentVolumeClaimTemplate = io__k8s__api__core__v1__PersistentVolumeClaimTemplate
PersistentVolumeClaimVolumeSource = (
    io__k8s__api__core__v1__PersistentVolumeClaimVolumeSource
)
PersistentVolumeList = io__k8s__api__core__v1__PersistentVolumeList
PersistentVolumeSpec = io__k8s__api__core__v1__PersistentVolumeSpec
PersistentVolumeStatus = io__k8s__api__core__v1__PersistentVolumeStatus
PhotonPersistentDiskVolumeSource = (
    io__k8s__api__core__v1__PhotonPersistentDiskVolumeSource
)
Pod = io__k8s__api__core__v1__Pod
PodAffinity = io__k8s__api__core__v1__PodAffinity
PodAffinityTerm = io__k8s__api__core__v1__PodAffinityTerm
PodAntiAffinity = io__k8s__api__core__v1__PodAntiAffinity
PodCondition = io__k8s__api__core__v1__PodCondition
PodDNSConfig = io__k8s__api__core__v1__PodDNSConfig
PodDNSConfigOption = io__k8s__api__core__v1__PodDNSConfigOption
PodIP = io__k8s__api__core__v1__PodIP
PodList = io__k8s__api__core__v1__PodList
PodOS = io__k8s__api__core__v1__PodOS
PodReadinessGate = io__k8s__api__core__v1__PodReadinessGate
PodSecurityContext = io__k8s__api__core__v1__PodSecurityContext
PodSpec = io__k8s__api__core__v1__PodSpec
PodStatus = io__k8s__api__core__v1__PodStatus
PodTemplate = io__k8s__api__core__v1__PodTemplate
PodTemplateList = io__k8s__api__core__v1__PodTemplateList
PodTemplateSpec = io__k8s__api__core__v1__PodTemplateSpec
PortStatus = io__k8s__api__core__v1__PortStatus
PortworxVolumeSource = io__k8s__api__core__v1__PortworxVolumeSource
PreferredSchedulingTerm = io__k8s__api__core__v1__PreferredSchedulingTerm
Probe = io__k8s__api__core__v1__Probe
ProjectedVolumeSource = io__k8s__api__core__v1__ProjectedVolumeSource
QuobyteVolumeSource = io__k8s__api__core__v1__QuobyteVolumeSource
RBDPersistentVolumeSource = io__k8s__api__core__v1__RBDPersistentVolumeSource
RBDVolumeSource = io__k8s__api__core__v1__RBDVolumeSource
ReplicationController = io__k8s__api__core__v1__ReplicationController
ReplicationControllerCondition = io__k8s__api__core__v1__ReplicationControllerCondition
ReplicationControllerList = io__k8s__api__core__v1__ReplicationControllerList
ReplicationControllerSpec = io__k8s__api__core__v1__ReplicationControllerSpec
ReplicationControllerStatus = io__k8s__api__core__v1__ReplicationControllerStatus
ResourceFieldSelector = io__k8s__api__core__v1__ResourceFieldSelector
ResourceQuota = io__k8s__api__core__v1__ResourceQuota
ResourceQuotaList = io__k8s__api__core__v1__ResourceQuotaList
ResourceQuotaSpec = io__k8s__api__core__v1__ResourceQuotaSpec
ResourceQuotaStatus = io__k8s__api__core__v1__ResourceQuotaStatus
ResourceRequirements = io__k8s__api__core__v1__ResourceRequirements
SELinuxOptions = io__k8s__api__core__v1__SELinuxOptions
ScaleIOPersistentVolumeSource = io__k8s__api__core__v1__ScaleIOPersistentVolumeSource
ScaleIOVolumeSource = io__k8s__api__core__v1__ScaleIOVolumeSource
ScopeSelector = io__k8s__api__core__v1__ScopeSelector
ScopedResourceSelectorRequirement = (
    io__k8s__api__core__v1__ScopedResourceSelectorRequirement
)
SeccompProfile = io__k8s__api__core__v1__SeccompProfile
Secret = io__k8s__api__core__v1__Secret
SecretEnvSource = io__k8s__api__core__v1__SecretEnvSource
SecretKeySelector = io__k8s__api__core__v1__SecretKeySelector
SecretList = io__k8s__api__core__v1__SecretList
SecretProjection = io__k8s__api__core__v1__SecretProjection
SecretReference = io__k8s__api__core__v1__SecretReference
SecretVolumeSource = io__k8s__api__core__v1__SecretVolumeSource
SecurityContext = io__k8s__api__core__v1__SecurityContext
Service = io__k8s__api__core__v1__Service
ServiceAccount = io__k8s__api__core__v1__ServiceAccount
ServiceAccountList = io__k8s__api__core__v1__ServiceAccountList
ServiceAccountTokenProjection = io__k8s__api__core__v1__ServiceAccountTokenProjection
ServiceList = io__k8s__api__core__v1__ServiceList
ServicePort = io__k8s__api__core__v1__ServicePort
ServiceSpec = io__k8s__api__core__v1__ServiceSpec
ServiceStatus = io__k8s__api__core__v1__ServiceStatus
SessionAffinityConfig = io__k8s__api__core__v1__SessionAffinityConfig
StorageOSPersistentVolumeSource = (
    io__k8s__api__core__v1__StorageOSPersistentVolumeSource
)
StorageOSVolumeSource = io__k8s__api__core__v1__StorageOSVolumeSource
Sysctl = io__k8s__api__core__v1__Sysctl
TCPSocketAction = io__k8s__api__core__v1__TCPSocketAction
Taint = io__k8s__api__core__v1__Taint
Toleration = io__k8s__api__core__v1__Toleration
TopologySelectorLabelRequirement = (
    io__k8s__api__core__v1__TopologySelectorLabelRequirement
)
TopologySelectorTerm = io__k8s__api__core__v1__TopologySelectorTerm
TopologySpreadConstraint = io__k8s__api__core__v1__TopologySpreadConstraint
TypedLocalObjectReference = io__k8s__api__core__v1__TypedLocalObjectReference
Volume = io__k8s__api__core__v1__Volume
VolumeDevice = io__k8s__api__core__v1__VolumeDevice
VolumeMount = io__k8s__api__core__v1__VolumeMount
VolumeNodeAffinity = io__k8s__api__core__v1__VolumeNodeAffinity
VolumeProjection = io__k8s__api__core__v1__VolumeProjection
VsphereVirtualDiskVolumeSource = io__k8s__api__core__v1__VsphereVirtualDiskVolumeSource
WeightedPodAffinityTerm = io__k8s__api__core__v1__WeightedPodAffinityTerm
WindowsSecurityContextOptions = io__k8s__api__core__v1__WindowsSecurityContextOptions
Endpoint = io__k8s__api__discovery__v1beta1__Endpoint
EndpointConditions = io__k8s__api__discovery__v1beta1__EndpointConditions
EndpointHints = io__k8s__api__discovery__v1beta1__EndpointHints
EndpointSlice = io__k8s__api__discovery__v1__EndpointSlice
EndpointSliceList = io__k8s__api__discovery__v1__EndpointSliceList
ForZone = io__k8s__api__discovery__v1beta1__ForZone
discovery__k8s__io_v1beta1_EndpointSlice = (
    io__k8s__api__discovery__v1beta1__EndpointSlice
)
discovery__k8s__io_v1beta1_EndpointSliceList = (
    io__k8s__api__discovery__v1beta1__EndpointSliceList
)
events__k8s__io_v1_Event = io__k8s__api__events__v1__Event
events__k8s__io_v1_EventList = io__k8s__api__events__v1__EventList
events__k8s__io_v1beta1_Event = io__k8s__api__events__v1beta1__Event
events__k8s__io_v1beta1_EventList = io__k8s__api__events__v1beta1__EventList
FlowDistinguisherMethod = io__k8s__api__flowcontrol__v1beta2__FlowDistinguisherMethod
FlowSchema = io__k8s__api__flowcontrol__v1beta1__FlowSchema
FlowSchemaCondition = io__k8s__api__flowcontrol__v1beta2__FlowSchemaCondition
FlowSchemaList = io__k8s__api__flowcontrol__v1beta1__FlowSchemaList
FlowSchemaSpec = io__k8s__api__flowcontrol__v1beta2__FlowSchemaSpec
FlowSchemaStatus = io__k8s__api__flowcontrol__v1beta2__FlowSchemaStatus
GroupSubject = io__k8s__api__flowcontrol__v1beta2__GroupSubject
LimitResponse = io__k8s__api__flowcontrol__v1beta2__LimitResponse
LimitedPriorityLevelConfiguration = (
    io__k8s__api__flowcontrol__v1beta2__LimitedPriorityLevelConfiguration
)
NonResourcePolicyRule = io__k8s__api__flowcontrol__v1beta2__NonResourcePolicyRule
PolicyRulesWithSubjects = io__k8s__api__flowcontrol__v1beta2__PolicyRulesWithSubjects
PriorityLevelConfiguration = (
    io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfiguration
)
PriorityLevelConfigurationCondition = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationCondition
)
PriorityLevelConfigurationList = (
    io__k8s__api__flowcontrol__v1beta1__PriorityLevelConfigurationList
)
PriorityLevelConfigurationReference = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationReference
)
PriorityLevelConfigurationSpec = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationSpec
)
PriorityLevelConfigurationStatus = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationStatus
)
QueuingConfiguration = io__k8s__api__flowcontrol__v1beta2__QueuingConfiguration
ResourcePolicyRule = io__k8s__api__flowcontrol__v1beta2__ResourcePolicyRule
ServiceAccountSubject = io__k8s__api__flowcontrol__v1beta2__ServiceAccountSubject
Subject = io__k8s__api__rbac__v1__Subject
UserSubject = io__k8s__api__flowcontrol__v1beta2__UserSubject
flowcontrol__apiserver__k8s__io_v1beta2_FlowSchema = (
    io__k8s__api__flowcontrol__v1beta2__FlowSchema
)
flowcontrol__apiserver__k8s__io_v1beta2_FlowSchemaList = (
    io__k8s__api__flowcontrol__v1beta2__FlowSchemaList
)
flowcontrol__apiserver__k8s__io_v1beta2_PriorityLevelConfiguration = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfiguration
)
flowcontrol__apiserver__k8s__io_v1beta2_PriorityLevelConfigurationList = (
    io__k8s__api__flowcontrol__v1beta2__PriorityLevelConfigurationList
)
HTTPIngressPath = io__k8s__api__networking__v1__HTTPIngressPath
HTTPIngressRuleValue = io__k8s__api__networking__v1__HTTPIngressRuleValue
IPBlock = io__k8s__api__networking__v1__IPBlock
Ingress = io__k8s__api__networking__v1__Ingress
IngressBackend = io__k8s__api__networking__v1__IngressBackend
IngressClass = io__k8s__api__networking__v1__IngressClass
IngressClassList = io__k8s__api__networking__v1__IngressClassList
IngressClassParametersReference = (
    io__k8s__api__networking__v1__IngressClassParametersReference
)
IngressClassSpec = io__k8s__api__networking__v1__IngressClassSpec
IngressList = io__k8s__api__networking__v1__IngressList
IngressRule = io__k8s__api__networking__v1__IngressRule
IngressServiceBackend = io__k8s__api__networking__v1__IngressServiceBackend
IngressSpec = io__k8s__api__networking__v1__IngressSpec
IngressStatus = io__k8s__api__networking__v1__IngressStatus
IngressTLS = io__k8s__api__networking__v1__IngressTLS
NetworkPolicy = io__k8s__api__networking__v1__NetworkPolicy
NetworkPolicyEgressRule = io__k8s__api__networking__v1__NetworkPolicyEgressRule
NetworkPolicyIngressRule = io__k8s__api__networking__v1__NetworkPolicyIngressRule
NetworkPolicyList = io__k8s__api__networking__v1__NetworkPolicyList
NetworkPolicyPeer = io__k8s__api__networking__v1__NetworkPolicyPeer
NetworkPolicyPort = io__k8s__api__networking__v1__NetworkPolicyPort
NetworkPolicySpec = io__k8s__api__networking__v1__NetworkPolicySpec
NetworkPolicyStatus = io__k8s__api__networking__v1__NetworkPolicyStatus
ServiceBackendPort = io__k8s__api__networking__v1__ServiceBackendPort
Overhead = io__k8s__api__node__v1beta1__Overhead
RuntimeClass = io__k8s__api__node__v1__RuntimeClass
RuntimeClassList = io__k8s__api__node__v1__RuntimeClassList
Scheduling = io__k8s__api__node__v1beta1__Scheduling
node__k8s__io_v1beta1_RuntimeClass = io__k8s__api__node__v1beta1__RuntimeClass
node__k8s__io_v1beta1_RuntimeClassList = io__k8s__api__node__v1beta1__RuntimeClassList
Eviction = io__k8s__api__policy__v1__Eviction
PodDisruptionBudget = io__k8s__api__policy__v1__PodDisruptionBudget
PodDisruptionBudgetList = io__k8s__api__policy__v1__PodDisruptionBudgetList
PodDisruptionBudgetSpec = io__k8s__api__policy__v1beta1__PodDisruptionBudgetSpec
PodDisruptionBudgetStatus = io__k8s__api__policy__v1beta1__PodDisruptionBudgetStatus
AllowedCSIDriver = io__k8s__api__policy__v1beta1__AllowedCSIDriver
AllowedFlexVolume = io__k8s__api__policy__v1beta1__AllowedFlexVolume
AllowedHostPath = io__k8s__api__policy__v1beta1__AllowedHostPath
FSGroupStrategyOptions = io__k8s__api__policy__v1beta1__FSGroupStrategyOptions
HostPortRange = io__k8s__api__policy__v1beta1__HostPortRange
IDRange = io__k8s__api__policy__v1beta1__IDRange
policy_v1beta1_PodDisruptionBudget = io__k8s__api__policy__v1beta1__PodDisruptionBudget
policy_v1beta1_PodDisruptionBudgetList = (
    io__k8s__api__policy__v1beta1__PodDisruptionBudgetList
)
PodSecurityPolicy = io__k8s__api__policy__v1beta1__PodSecurityPolicy
PodSecurityPolicyList = io__k8s__api__policy__v1beta1__PodSecurityPolicyList
PodSecurityPolicySpec = io__k8s__api__policy__v1beta1__PodSecurityPolicySpec
RunAsGroupStrategyOptions = io__k8s__api__policy__v1beta1__RunAsGroupStrategyOptions
RunAsUserStrategyOptions = io__k8s__api__policy__v1beta1__RunAsUserStrategyOptions
RuntimeClassStrategyOptions = io__k8s__api__policy__v1beta1__RuntimeClassStrategyOptions
SELinuxStrategyOptions = io__k8s__api__policy__v1beta1__SELinuxStrategyOptions
SupplementalGroupsStrategyOptions = (
    io__k8s__api__policy__v1beta1__SupplementalGroupsStrategyOptions
)
AggregationRule = io__k8s__api__rbac__v1__AggregationRule
ClusterRole = io__k8s__api__rbac__v1__ClusterRole
ClusterRoleBinding = io__k8s__api__rbac__v1__ClusterRoleBinding
ClusterRoleBindingList = io__k8s__api__rbac__v1__ClusterRoleBindingList
ClusterRoleList = io__k8s__api__rbac__v1__ClusterRoleList
PolicyRule = io__k8s__api__rbac__v1__PolicyRule
Role = io__k8s__api__rbac__v1__Role
RoleBinding = io__k8s__api__rbac__v1__RoleBinding
RoleBindingList = io__k8s__api__rbac__v1__RoleBindingList
RoleList = io__k8s__api__rbac__v1__RoleList
RoleRef = io__k8s__api__rbac__v1__RoleRef
PriorityClass = io__k8s__api__scheduling__v1__PriorityClass
PriorityClassList = io__k8s__api__scheduling__v1__PriorityClassList
CSIDriver = io__k8s__api__storage__v1__CSIDriver
CSIDriverList = io__k8s__api__storage__v1__CSIDriverList
CSIDriverSpec = io__k8s__api__storage__v1__CSIDriverSpec
CSINode = io__k8s__api__storage__v1__CSINode
CSINodeDriver = io__k8s__api__storage__v1__CSINodeDriver
CSINodeList = io__k8s__api__storage__v1__CSINodeList
CSINodeSpec = io__k8s__api__storage__v1__CSINodeSpec
CSIStorageCapacity = io__k8s__api__storage__v1__CSIStorageCapacity
CSIStorageCapacityList = io__k8s__api__storage__v1__CSIStorageCapacityList
StorageClass = io__k8s__api__storage__v1__StorageClass
StorageClassList = io__k8s__api__storage__v1__StorageClassList
VolumeAttachment = io__k8s__api__storage__v1__VolumeAttachment
VolumeAttachmentList = io__k8s__api__storage__v1__VolumeAttachmentList
VolumeAttachmentSource = io__k8s__api__storage__v1__VolumeAttachmentSource
VolumeAttachmentSpec = io__k8s__api__storage__v1__VolumeAttachmentSpec
VolumeAttachmentStatus = io__k8s__api__storage__v1__VolumeAttachmentStatus
VolumeError = io__k8s__api__storage__v1__VolumeError
VolumeNodeResources = io__k8s__api__storage__v1__VolumeNodeResources
storage__k8s__io_v1beta1_CSIStorageCapacity = (
    io__k8s__api__storage__v1beta1__CSIStorageCapacity
)
storage__k8s__io_v1beta1_CSIStorageCapacityList = (
    io__k8s__api__storage__v1beta1__CSIStorageCapacityList
)
Quantity = io__k8s__apimachinery__pkg__api__resource__Quantity
APIGroup = io__k8s__apimachinery__pkg__apis__meta__v1__APIGroup
APIGroupList = io__k8s__apimachinery__pkg__apis__meta__v1__APIGroupList
APIResource = io__k8s__apimachinery__pkg__apis__meta__v1__APIResource
APIResourceList = io__k8s__apimachinery__pkg__apis__meta__v1__APIResourceList
APIVersions = io__k8s__apimachinery__pkg__apis__meta__v1__APIVersions
Condition = io__k8s__apimachinery__pkg__apis__meta__v1__Condition
DeleteOptions = io__k8s__apimachinery__pkg__apis__meta__v1__DeleteOptions
FieldsV1 = io__k8s__apimachinery__pkg__apis__meta__v1__FieldsV1
GroupVersionForDiscovery = (
    io__k8s__apimachinery__pkg__apis__meta__v1__GroupVersionForDiscovery
)
LabelSelector = io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelector
LabelSelectorRequirement = (
    io__k8s__apimachinery__pkg__apis__meta__v1__LabelSelectorRequirement
)
ListMeta = io__k8s__apimachinery__pkg__apis__meta__v1__ListMeta
ManagedFieldsEntry = io__k8s__apimachinery__pkg__apis__meta__v1__ManagedFieldsEntry
MicroTime = io__k8s__apimachinery__pkg__apis__meta__v1__MicroTime
ObjectMeta = io__k8s__apimachinery__pkg__apis__meta__v1__ObjectMeta
OwnerReference = io__k8s__apimachinery__pkg__apis__meta__v1__OwnerReference
Patch = io__k8s__apimachinery__pkg__apis__meta__v1__Patch
Preconditions = io__k8s__apimachinery__pkg__apis__meta__v1__Preconditions
ServerAddressByClientCIDR = (
    io__k8s__apimachinery__pkg__apis__meta__v1__ServerAddressByClientCIDR
)
Status = io__k8s__apimachinery__pkg__apis__meta__v1__Status
StatusCause = io__k8s__apimachinery__pkg__apis__meta__v1__StatusCause
StatusDetails = io__k8s__apimachinery__pkg__apis__meta__v1__StatusDetails
Time = io__k8s__apimachinery__pkg__apis__meta__v1__Time
WatchEvent = io__k8s__apimachinery__pkg__apis__meta__v1__WatchEvent
RawExtension = io__k8s__apimachinery__pkg__runtime__RawExtension
IntOrString = io__k8s__apimachinery__pkg__util__intstr__IntOrString
Info = io__k8s__apimachinery__pkg__version__Info
APIService = io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIService
APIServiceCondition = (
    io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceCondition
)
APIServiceList = (
    io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceList
)
APIServiceSpec = (
    io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceSpec
)
APIServiceStatus = (
    io__k8s__kube_aggregator__pkg__apis__apiregistration__v1__APIServiceStatus
)
