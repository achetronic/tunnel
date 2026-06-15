// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package uplink

import (
	"fmt"
	"maps"

	"github.com/achetronic/tunnel/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func LabelsForNode(node *v1alpha1.EdgeNode) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":                "uplink",
		"app.kubernetes.io/instance":            node.Name,
		"app.kubernetes.io/managed-by":          "tunnel",
		"tunnel.achetronic.com/owner-namespace": node.Namespace,
	}
}

// BuildConfigMap returns the ConfigMap holding the shared uplink desired-state
// document (the tunnelctl template every replica completes with its own
// identity at runtime).
func BuildConfigMap(node *v1alpha1.EdgeNode, uplinkDoc []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-uplink-config", node.Name),
			Namespace: node.Spec.Uplink.Namespace,
			Labels:    LabelsForNode(node),
		},
		Data: map[string]string{
			"uplink.json": string(uplinkDoc),
		},
	}
}

// BuildKeysSecret creates the Secret holding the private keys for each ordinal.
func BuildKeysSecret(node *v1alpha1.EdgeNode, keys map[int32]string) *corev1.Secret {
	stringData := make(map[string]string)
	for ordinal, privKey := range keys {
		stringData[fmt.Sprintf("priv-%d", ordinal)] = privKey
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-uplink-keys", node.Name),
			Namespace: node.Spec.Uplink.Namespace,
			Labels:    LabelsForNode(node),
		},
		StringData: stringData,
	}
}

// BuildHeadlessService renders the headless Service the uplink StatefulSet's
// spec.serviceName points at, satisfying the StatefulSet's per-pod DNS
// identity contract. Same name/namespace/labels as the StatefulSet, ClusterIP
// None, no ports: the uplink exposes nothing in-cluster, the Service exists
// purely for identity.
func BuildHeadlessService(node *v1alpha1.EdgeNode) *corev1.Service {
	labels := LabelsForNode(node)
	selectorLabels := make(map[string]string)
	maps.Copy(selectorLabels, labels)
	delete(selectorLabels, "tunnel.achetronic.com/owner-namespace")

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-uplink", node.Name),
			Namespace: node.Spec.Uplink.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selectorLabels,
		},
	}
}

// BuildStatefulSet returns the StatefulSet that maintains the uplink peers. The
// image and pull policy are passed in by the controller (the image is composed
// from its --image-repo/--image-tag flags). Tunnel parameters (network, MTU,
// keepalive, the relay endpoint and public key) are not container environment:
// they live in the desired-state document mounted from the ConfigMap, which each
// replica completes with its own identity.
func BuildStatefulSet(node *v1alpha1.EdgeNode, image string, pullPolicy corev1.PullPolicy) *appsv1.StatefulSet {
	replicas := node.Spec.Uplink.Replicas
	if replicas <= 0 {
		replicas = 1
	}

	privileged := true

	labels := LabelsForNode(node)

	podLabels := make(map[string]string)
	maps.Copy(podLabels, labels)
	maps.Copy(podLabels, node.Spec.Uplink.Labels)

	selectorLabels := make(map[string]string)
	maps.Copy(selectorLabels, labels)
	delete(selectorLabels, "tunnel.achetronic.com/owner-namespace")

	podAnnotations := make(map[string]string)
	maps.Copy(podAnnotations, node.Spec.Uplink.Annotations)

	affinity := node.Spec.Uplink.Affinity
	if affinity == nil {
		affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{MatchLabels: selectorLabels},
						TopologyKey:   "kubernetes.io/hostname",
					},
				},
			},
		}
	}

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-uplink", node.Name),
			Namespace: node.Spec.Uplink.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			Selector:    &metav1.LabelSelector{MatchLabels: selectorLabels},
			ServiceName: fmt.Sprintf("%s-uplink", node.Name),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      podLabels,
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					Affinity:     affinity,
					NodeSelector: node.Spec.Uplink.NodeSelector,
					Tolerations:  node.Spec.Uplink.Tolerations,
					Containers: []corev1.Container{
						{
							Name:            "uplink",
							Image:           image,
							ImagePullPolicy: pullPolicy,
							// The uplink image is the generic tunnelctl agent. It runs the
							// shared uplink document and applies the per-replica identity
							// transforms (ordinal -> address + private key) on top of it.
							Command: []string{"/usr/local/bin/tunnelctl"},
							Args: []string{
								"run",
								"--config", "/etc/tunnel/uplink.json",
								"--transforms", "/etc/tunnelctl/uplink.transforms.yaml",
								// The readiness server port must match the probe below and
								// the port Envoy health-checks (planner.uplinkReadinessPort).
								"--health-addr", ":40500",
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
							},
							Resources: node.Spec.Uplink.Resources,
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/ready",
										Port: intstr.FromInt(40500),
									},
								},
								PeriodSeconds:    5,
								FailureThreshold: 2,
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "uplink-config", MountPath: "/etc/tunnel"},
								{Name: "wg-keys", MountPath: "/etc/wireguard/keys", ReadOnly: true},
							},
							Env: []corev1.EnvVar{
								// KEYS_DIR is where the per-replica private keys Secret is
								// mounted; the identity transforms read priv-<ordinal> from it.
								{Name: "KEYS_DIR", Value: "/etc/wireguard/keys"},
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "uplink-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: fmt.Sprintf("%s-uplink-config", node.Name),
									},
								},
							},
						},
						{
							Name: "wg-keys",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: fmt.Sprintf("%s-uplink-keys", node.Name),
								},
							},
						},
					},
				},
			},
		},
	}
}
