/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"strings"

	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cloudv1alpha1 "github.com/fevirtus/osdks/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const firewallFinalizer = "cloud.bizflycloud.vn/finalizer"

//+kubebuilder:rbac:groups=cloud.bizflycloud.vn,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cloud.bizflycloud.vn,resources=firewalls/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cloud.bizflycloud.vn,resources=firewalls/finalizers,verbs=update
//+kubebuilder:rbac:groups=batch.tutorial.kubebuilder.io,resources=cronjobs/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;
//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=endpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmap,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac,resources=role,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceAccount,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Firewall object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *FirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	firewall := &cloudv1alpha1.Firewall{}

	// CRD logical
	// ***********************
	// find firewall CR
	err := r.Get(ctx, req.NamespacedName, firewall)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return. Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			logger.Info("Firewall resource not found.")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		logger.Error(err, "Failed to get Firewall")
		return ctrl.Result{}, err
	}

	// Let's add a finalizer. Then, we can define some operations which should
	// occurs before the custom resource to be deleted.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers
	if !controllerutil.ContainsFinalizer(firewall, firewallFinalizer) {
		logger.Info("Adding Finalizer for Firewall")
		if ok := controllerutil.AddFinalizer(firewall, firewallFinalizer); !ok {
			logger.Error(err, "Failed to add finalizer into the custom resource")
			return ctrl.Result{Requeue: true}, nil
		}

		if err = r.Update(ctx, firewall); err != nil {
			logger.Error(err, "Failed to update custom resource to add finalizer")
			return ctrl.Result{}, err
		}
	}

	// Check if the Firewall instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set.
	if !firewall.ObjectMeta.DeletionTimestamp.IsZero() {
		// Execute cleanup logic to delete associated resources
		if err := r.cleanupResources(firewall); err != nil {
			return ctrl.Result{}, err
		}

		// Remove finalizer after cleanup
		controllerutil.RemoveFinalizer(firewall, firewallFinalizer)
		if err := r.Update(ctx, firewall); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	// ***********************

	// Controller logical
	// ***********************

	// Check Domain
	// If we can't find ingress of Domain -> new Domain -> Run full flow
	logger.Info("Finding ingress...")
	ing := &networkv1.Ingress{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: "ingress-nginx",
		Name:      firewall.Spec.Uid + "-ingress",
	}, ing); err != nil {
		if errors.IsNotFound(err) {
			// Can't find ingress. Create new!
			logger.Info("No ingress found. Start create full follow!")
			if err := r.createNew(ctx, firewall); err != nil {
				return ctrl.Result{}, err
			}

			logger.Info("All resource created. Exiting...")
			return ctrl.Result{Requeue: true}, nil
		} else {
			// Error when get ingress
			logger.Error(err, "Error when find ingress!")
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Found Ingress. Checking detail...")

		// Check Host match
		if strings.Compare(ing.Spec.Rules[0].Host, firewall.Spec.Domain) != 0 {
			logger.Info("Domain changed!")

			// Update global ingress
			logger.Info("Updating ingress (global)...")
			ing := r.makeIngress(firewall)
			if err := r.Update(ctx, ing); err != nil {
				logger.Error(err, "Error when update ingress (global)")
				return ctrl.Result{}, err
			} else {
				logger.Info("Ingress update successful!")
			}

			// Update namespaced ingress
			logger.Info("Updating ingress (namespaced)...")
			nsIng := r.makeNsIngress(firewall)
			if err := r.Update(ctx, nsIng); err != nil {
				logger.Error(err, "Error when update ingress (namespaced)")
				return ctrl.Result{}, err
			}
		} else {
			logger.Info("Found Ingress. Nothing change. Next step...")
		}
	}

	// Check endpoints, port
	logger.Info("Finding endpoints...")
	ep := &corev1.Endpoints{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: firewall.Spec.Uid,
		Name:      "service",
	}, ep); err != nil {
		if errors.IsNotFound(err) {
			// Can't find ingress match Domain. Create new endpoints
			logger.Info("Can't find Endpoints matched. Start create new Endpoints")
			ep := r.makeEndpoints(firewall)
			if err := r.Create(ctx, ep); err != nil {
				logger.Error(err, "Error when create Endpoints")
				return ctrl.Result{}, err
			} else {
				logger.Info("New Endpoints had been create!")
			}
		} else {
			// Error when get ingress
			logger.Error(err, "Error when find Endpoints")
			return ctrl.Result{}, err
		}
	} else {
		//Found Endpoints
		if strings.Compare(ep.Subsets[0].Addresses[0].IP, firewall.Spec.Endpoints) != 0 ||
			ep.Subsets[0].Ports[0].Port != firewall.Spec.Port {
			// Update Endpoints
			logger.Info("Found endpoints. Detail changed. Updating...")
			ep := r.makeEndpoints(firewall)
			if err := r.Update(ctx, ep); err != nil {
				logger.Error(err, "Error when update endpoints")
				return ctrl.Result{}, err
			} else {
				logger.Info("Endpoints update successful!")
			}
		} else {
			logger.Info("Found Endpoints. Nothing change. Next step...")
		}
	}

	// Check Secret
	logger.Info("Finding Secret...")
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: firewall.Spec.Uid,
		Name:      firewall.Spec.SecretName,
	}, sec); err != nil {
		if errors.IsNotFound(err) {
			// Can't find Secret. Create new secret
			logger.Info("Can't find Secret matched. Start create new Secret")
			s := r.makeSecret(firewall)
			if err := r.Create(ctx, s); err != nil {
				logger.Error(err, "Error when create Secret")
				return ctrl.Result{}, err
			} else {
				logger.Info("New Secret had been create!")
			}
		} else {
			// Error when get Secret
			logger.Error(err, "Error when find Secret")
			return ctrl.Result{}, err
		}
	} else {
		//Found Secret
		logger.Info("Found Secret. Checking detail...")
		if !bytes.Equal(sec.Data["tls.crt"], firewall.Spec.Crt) ||
			!bytes.Equal(sec.Data["tls.key"], firewall.Spec.Key) {
			// Update Endpoints
			logger.Info("Detail changed. Updating...")
			s := r.makeSecret(firewall)
			if err := r.Update(ctx, s); err != nil {
				logger.Error(err, "Error when update Secret")
				return ctrl.Result{}, err
			} else {
				logger.Info("Secret update successful!")
			}
		} else {
			logger.Info("Found Secret. Nothing change. Next step...")
		}
	}

	// Check ingress (namespaced)
	logger.Info("Finding Ingress (namespaced)...")
	ingNs := &networkv1.Ingress{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: firewall.Spec.Uid,
		Name:      "ingress",
	}, ingNs); err != nil {
		if errors.IsNotFound(err) {
			// Can't find ingress (namespaced). Create new secret
			logger.Info("Can't find ingress (namespaced) matched. Start create new ingress (namespaced)")
			i := r.makeNsIngress(firewall)
			if err := r.Create(ctx, i); err != nil {
				logger.Error(err, "Error when create ingress (namespaced)")
				return ctrl.Result{}, err
			} else {
				logger.Info("New ingress (namespaced) had been create!")
			}
		} else {
			// Error when get Secret
			logger.Error(err, "Error when find ingress (namespaced)")
			return ctrl.Result{}, err
		}
	} else {
		// Found ingress (namespaced)
		logger.Info("Found ingress (namespaced). Checking detail...")
		if !r.nsIngressNotChange(ingNs, firewall) {
			// Update Endpoints
			logger.Info("Detail changed. Updating...")
			i := r.makeNsIngress(firewall)
			if err := r.Update(ctx, i); err != nil {
				logger.Error(err, "Error when update ingress (namespaced)")
				return ctrl.Result{}, err
			} else {
				logger.Info("Ingress (namespaced) update successful!")
			}
		} else {
			logger.Info("Found ingress (namespaced). Nothing change. Next step...")
		}
	}

	// -------

	logger.Info("Operator's actions end!")
	return ctrl.Result{}, nil
}

// nsIngressNotChange return bool
func (r *FirewallReconciler) nsIngressNotChange(found *networkv1.Ingress, f *cloudv1alpha1.Firewall) bool {
	anno := found.ObjectMeta.Annotations
	_, ok := anno[f.Spec.BackendProtocol]

	return (ok && strings.Compare(anno[f.Spec.BackendProtocol], f.Spec.Protocol) == 0) &&
		strings.Compare(anno["nginx.ingress.kubernetes.io/enable-modsecurity"], f.Spec.WafState) == 0 &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.WafMode) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.WafRequestBodyCheck) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.WafMaxRequestBodySizeInKb) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.WafMaxRequestBodySizeNoFile) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.IncludeOwaspConfig) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.SecruleRemoveById) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.ExceptList) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.CustomRule) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.NginxUpstreamVhost) &&
		strings.Contains(anno["nginx.ingress.kubernetes.io/modsecurity-snippet"], f.Spec.ExternalName) &&
		strings.Compare(found.Spec.Rules[0].Host, f.Spec.Domain) == 0 &&
		found.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number == f.Spec.Port &&
		strings.Compare(found.Spec.Rules[1].Host, f.Spec.Uid+".hn.waf.bfcplatform.vn") == 0 &&
		found.Spec.Rules[1].HTTP.Paths[0].Backend.Service.Port.Number == f.Spec.Port &&
		strings.Compare(found.Spec.TLS[0].Hosts[0], f.Spec.Domain) == 0 &&
		strings.Compare(found.Spec.TLS[0].SecretName, f.Spec.SecretName) == 0 &&
		strings.Compare(found.Spec.TLS[1].Hosts[0], f.Spec.Uid+".hn.waf.bfcplatform.vn") == 0 &&
		strings.Compare(found.Spec.TLS[1].SecretName, f.Spec.SecretName) == 0
}

// makeNamespace return Namespace object based on the input from the Firewall object.
func (r *FirewallReconciler) makeNamespace(f *cloudv1alpha1.Firewall) *corev1.Namespace {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.Spec.Uid,
			Labels: map[string]string{
				"name": "development",
			},
		},
	}

	return ns
}

// makeIngress return Ingress (global) object based on the input from the Firewall object.
func (r *FirewallReconciler) makeIngress(f *cloudv1alpha1.Firewall) *networkv1.Ingress {
	pathTypePrefix := networkv1.PathTypePrefix

	ing := &networkv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.Spec.Uid + "-ingress",
			Namespace: "ingress-nginx",
		},
		Spec: networkv1.IngressSpec{
			Rules: []networkv1.IngressRule{{
				Host: f.Spec.Domain,
				IngressRuleValue: networkv1.IngressRuleValue{
					HTTP: &networkv1.HTTPIngressRuleValue{
						Paths: []networkv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathTypePrefix,
							Backend: networkv1.IngressBackend{
								Service: &networkv1.IngressServiceBackend{
									Name: f.Spec.Domain + "-service",
									Port: networkv1.ServiceBackendPort{Number: 80},
								},
							},
						}, {
							Path:     "/",
							PathType: &pathTypePrefix,
							Backend: networkv1.IngressBackend{
								Service: &networkv1.IngressServiceBackend{
									Name: f.Spec.Domain + "-service",
									Port: networkv1.ServiceBackendPort{Number: 443},
								},
							},
						}},
					},
				},
			}},
		},
	}

	return ing
}

// makeService return Service object based on the input from the Firewall object.
func (r *FirewallReconciler) makeService(f *cloudv1alpha1.Firewall) *corev1.Service {
	serv := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.Spec.Domain + "-service",
			Namespace: "ingress-nginx",
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "ingress-nginx-controller." + f.Spec.Domain + ".svc.cluster.local",
			Ports: []corev1.ServicePort{{
				Port:       80,
				Name:       "http",
				TargetPort: intstr.FromInt(80),
			}, {
				Port:       443,
				Name:       "https",
				TargetPort: intstr.FromInt(443),
			}},
		},
	}

	return serv
}

// makeEndpoints returns an Endpoints object based on the input from the Firewall object.
func (r *FirewallReconciler) makeEndpoints(f *cloudv1alpha1.Firewall) *corev1.Endpoints {
	ep := &corev1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Endpoints",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: f.Spec.Uid,
		},
		Subsets: []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{
				IP: f.Spec.Endpoints,
			}},
			Ports: []corev1.EndpointPort{{
				Port: f.Spec.Port,
			}},
		}},
	}

	return ep
}

// makeConfigmap returns a ConfigMap object based on the input from the Firewall object.
func (r *FirewallReconciler) makeConfigmap(f *cloudv1alpha1.Firewall) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-controller",
			Namespace: f.Spec.Uid,
			Labels: map[string]string{
				"app.kubernetes.io/name": "namespace-ingress-nginx",
			},
		},
	}

	return cm
}

// make makeNsIngress returns an Ingress object based on the input from the Firewall object.
func (r *FirewallReconciler) makeNsIngress(f *cloudv1alpha1.Firewall) *networkv1.Ingress {
	pathTypeSpecific := networkv1.PathTypeImplementationSpecific

	nsIng := &networkv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "Ingress",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress",
			Namespace: f.Spec.Uid,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
				//f.Spec.BackendProtocol:                           f.Spec.Protocol,
				"nginx.ingress.kubernetes.io/enable-modsecurity": f.Spec.WafState,
				"nginx.ingress.kubernetes.io/modsecurity-snippet": " Include /etc/nginx/modsecurity/modsecurity.conf" +
					" SecRuleEngine " + f.Spec.WafMode +
					" SecRequestBodyAccess " + f.Spec.WafRequestBodyCheck +
					" SecRequestBodyLimit " + f.Spec.WafMaxRequestBodySizeInKb +
					" SecRequestBodyNoFilesLimit " + f.Spec.WafMaxRequestBodySizeNoFile + " SecRequestBodyLimitAction Reject ",
				//" SecRequestBodyLimitAction Reject " +
				//" " + f.Spec.IncludeOwaspConfig +
				//" " + f.Spec.SecruleRemoveById + " " + f.Spec.ExceptList +
				//" " + f.Spec.CustomRule +
				//" " + f.Spec.NginxUpstreamVhost + " " + f.Spec.ExternalName,
			},
		},
		Spec: networkv1.IngressSpec{
			Rules: []networkv1.IngressRule{{
				Host: f.Spec.Domain,
				IngressRuleValue: networkv1.IngressRuleValue{
					HTTP: &networkv1.HTTPIngressRuleValue{
						Paths: []networkv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathTypeSpecific,
							Backend: networkv1.IngressBackend{
								Service: &networkv1.IngressServiceBackend{
									Name: "service",
									Port: networkv1.ServiceBackendPort{
										Number: f.Spec.Port,
									},
								},
							},
						}},
					},
				},
			}, {
				Host: f.Spec.Uid + ".hn.waf.bfcplatform.vn",
				IngressRuleValue: networkv1.IngressRuleValue{
					HTTP: &networkv1.HTTPIngressRuleValue{
						Paths: []networkv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathTypeSpecific,
							Backend: networkv1.IngressBackend{
								Service: &networkv1.IngressServiceBackend{
									Name: "service",
									Port: networkv1.ServiceBackendPort{
										Number: f.Spec.Port,
									},
								},
							},
						}},
					},
				},
			}},
			TLS: []networkv1.IngressTLS{{
				Hosts:      []string{f.Spec.Domain},
				SecretName: f.Spec.SecretName, // need check
			}, {
				Hosts:      []string{f.Spec.Uid + ".hn.waf.bfcplatform.vn"},
				SecretName: f.Spec.SecretName, //need check
			}},
		},
	}

	return nsIng
}

// makeDeployment returns a Deployment object based on the input from the Firewall object.
func (r *FirewallReconciler) makeDeployment(f *cloudv1alpha1.Firewall) *appsv1.Deployment {
	var revisionHistoryLimit int32
	revisionHistoryLimit = 10
	var runAsUser, tgps int64
	runAsUser = 101
	tgps = 300
	var maxUnavailable intstr.IntOrString
	maxUnavailable = intstr.FromInt(1)
	var t bool
	t = true

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-controller",
			Namespace: f.Spec.Uid,
			Labels: map[string]string{
				"app.kubernetes.io/name": "namespace-ingress-nginx",
			},
		},
		Spec: appsv1.DeploymentSpec{
			MinReadySeconds:      0,
			RevisionHistoryLimit: &revisionHistoryLimit,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: "RollingUpdate",
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Args: []string{
							"/nginx-ingress-controller",
							"--publish-service=$(POD_NAMESPACE)/ingress-nginx-controller",
							"--election-id=ingress-nginx-leader",
							"--controller-class=k8s.io/ingress-nginx",
							"--ingress-class=nginx",
							"--configmap=$(POD_NAMESPACE)/ingress-nginx-controller",
							"--validating-webhook=:8443",
							"--validating-webhook-certificate=/usr/local/certificates/cert",
							"--validating-webhook-key=/usr/local/certificates/key",
							"--watch-namespace=" + f.Spec.Uid,
						},
						Env: []corev1.EnvVar{{
							Name: "POD_NAME",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "metadata.name",
								},
							},
						}, {
							Name: "POD_NAMESPACE",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "metadata.namespace",
								},
							},
						}, {
							Name:  "LD_PRELOAD",
							Value: "/usr/local/lib/libmimalloc.so",
						}},
						Image:           "registry.k8s.io/ingress-nginx/controller:v1.8.2@sha256:74834d3d25b336b62cabeb8bf7f1d788706e2cf1cfd64022de4137ade8881ff2",
						ImagePullPolicy: "IfNotPresent",
						Lifecycle: &corev1.Lifecycle{
							PreStop: &corev1.LifecycleHandler{
								Exec: &corev1.ExecAction{Command: []string{"/wait-shutdown"}},
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   intstr.FromInt(10254),
									Scheme: "HTTP",
								},
							},
							InitialDelaySeconds: 10,
							TimeoutSeconds:      1,
							PeriodSeconds:       10,
							SuccessThreshold:    1,
							FailureThreshold:    5,
						},
						Name: "controller",
						Ports: []corev1.ContainerPort{{
							ContainerPort: 80,
							Name:          "http",
							Protocol:      "TCP",
						}, {
							ContainerPort: 443,
							Name:          "https",
							Protocol:      "TCP",
						}, {
							ContainerPort: 8443,
							Name:          "webhook",
							Protocol:      "TCP",
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   intstr.FromInt(10254),
									Scheme: "HTTP",
								},
							},
							InitialDelaySeconds: 10,
							TimeoutSeconds:      1,
							PeriodSeconds:       10,
							SuccessThreshold:    1,
							FailureThreshold:    3,
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("900Mi"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("90Mi"),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add:  []corev1.Capability{"NET_BIND_SERVICE"},
								Drop: []corev1.Capability{"ALL"},
							},
							RunAsUser:                &runAsUser,
							AllowPrivilegeEscalation: &t,
						},
						VolumeMounts: []corev1.VolumeMount{{
							MountPath: "/usr/local/certificates/",
							Name:      "webhook-cert",
							ReadOnly:  true,
						}},
					}},
					DNSPolicy:                     "ClusterFirst",
					NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
					ServiceAccountName:            "ingress-nginx",
					TerminationGracePeriodSeconds: &tgps,
					Volumes: []corev1.Volume{{
						Name: "webhook-cert",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "ingress-nginx-admission",
							},
						},
					}},
				},
			},
		},
		Status: appsv1.DeploymentStatus{},
	}

	return d
}

// makeRole returns a Role object based on the input from the Firewall object.
func (r *FirewallReconciler) makeRole(f *cloudv1alpha1.Firewall) *v1.Role {
	role := &v1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Rules: []v1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list"},
		}, {
			APIGroups: []string{""},
			Resources: []string{"configmaps", "pods", "secrets", "endpoints"},
			Verbs:     []string{"get", "list", "watch"},
		}, {
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		}, {
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs:     []string{"get", "list"},
		}, {
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses/status"},
			Verbs:     []string{"update"},
		}, {
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingressclasses"},
			Verbs:     []string{"get", "list", "watch"},
		}, {
			APIGroups:     []string{"coordination.k8s.io"},
			ResourceNames: []string{"ingress-nginx-leader"},
			Resources:     []string{"leases"},
			Verbs:         []string{"get", "update"},
		}, {
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"create"},
		}, {
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		}, {
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"list", "watch", "get"},
		}},
	}

	return role
}

// makeRoleAdmin returns a Role object based on the input from the Firewall object.
func (r *FirewallReconciler) makeRoleAdmin(f *cloudv1alpha1.Firewall) *v1.Role {
	role := &v1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-admission",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Rules: []v1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "create"},
		}, {
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list"},
		}},
	}

	return role
}

// makeRoleBinding return a RoleBinding object based on the input from the Firewall object
func (r *FirewallReconciler) makeRoleBinding(f *cloudv1alpha1.Firewall) *v1.RoleBinding {
	rb := &v1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Subjects: []v1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "ingress-nginx",
			Namespace: f.Spec.Uid,
		}},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "ingress-nginx",
		},
	}

	return rb
}

// makeRoleBindingAdmin return a RoleBinding object based on the input from the Firewall object
func (r *FirewallReconciler) makeRoleBindingAdmin(f *cloudv1alpha1.Firewall) *v1.RoleBinding {
	rb := &v1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-admission",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Subjects: []v1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "ingress-nginx-admission",
			Namespace: f.Spec.Uid,
		}},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "ingress-nginx-admission",
		},
	}

	return rb
}

// makeSecret return a Secret object based on the input fromm Firewall object
func (r *FirewallReconciler) makeSecret(f *cloudv1alpha1.Firewall) *corev1.Secret {
	sec := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.Spec.SecretName,
			Namespace: f.Spec.Uid,
		},
		Data: map[string][]byte{"tls.crt": f.Spec.Crt, "tls.key": f.Spec.Key},
		Type: "Opaque",
	}

	return sec
}

// makeServiceEP return Service object based on the input from the Firewall object.
func (r *FirewallReconciler) makeServiceEP(f *cloudv1alpha1.Firewall) *corev1.Service {
	serv := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service",
			Namespace: f.Spec.Uid,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				Port:       80,
				Name:       "http",
				Protocol:   "TCP",
				TargetPort: intstr.FromInt(80),
			}, {
				Port:       443,
				Name:       "https",
				Protocol:   "TCP",
				TargetPort: intstr.FromInt(443),
			}},
		},
	}

	return serv
}

// makeServiceIng return Service object based on the input from the Firewall object.
func (r *FirewallReconciler) makeServiceIng(f *cloudv1alpha1.Firewall) *corev1.Service {
	appProtocolHTTP := "http"
	appProtocolHTTPS := "https"
	ipSingleStack := corev1.IPFamilyPolicySingleStack

	serv := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-controller",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Spec: corev1.ServiceSpec{
			IPFamilies:     []corev1.IPFamily{"IPv4"},
			IPFamilyPolicy: &ipSingleStack,
			Selector:       map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
			Type:           corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				AppProtocol: &appProtocolHTTP,
				Name:        "http",
				Port:        80,
				Protocol:    "TCP",
				TargetPort:  intstr.FromString("http"),
			}, {
				AppProtocol: &appProtocolHTTPS,
				Name:        "https",
				Port:        443,
				Protocol:    "TCP",
				TargetPort:  intstr.FromString("https"),
			}},
		},
	}

	return serv
}

// makeServiceIngAdmin return Service object based on the input from the Firewall object.
func (r *FirewallReconciler) makeServiceIngAdmin(f *cloudv1alpha1.Firewall) *corev1.Service {
	appProtocolHTTPS := "https"

	serv := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-controller-admission",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				AppProtocol: &appProtocolHTTPS,
				Name:        "https-webhook",
				Port:        443,
				TargetPort:  intstr.FromString("webhook"),
			}},
		},
	}

	return serv
}

// makeServiceAccount return a ServiceAccount object based on the input fromm Firewall object
func (r *FirewallReconciler) makeServiceAccount(f *cloudv1alpha1.Firewall) *corev1.ServiceAccount {
	secAcc := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
	}

	return secAcc
}

// makeServiceAccountAdmin return a ServiceAccount object based on the input fromm Firewall object
func (r *FirewallReconciler) makeServiceAccountAdmin(f *cloudv1alpha1.Firewall) *corev1.ServiceAccount {
	secAcc := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-nginx-admission",
			Namespace: f.Spec.Uid,
			Labels:    map[string]string{"app.kubernetes.io/name": "namespace-ingress-nginx"},
		},
	}

	return secAcc
}

// createNew run full follow to create new waf
func (r *FirewallReconciler) createNew(ctx context.Context, f *cloudv1alpha1.Firewall) error {
	logger := log.FromContext(ctx)

	// create namespace
	logger.Info("Create namespace...")
	ns := r.makeNamespace(f)
	if err := r.Create(ctx, ns); err != nil {
		logger.Error(err, "Error when create namespace!")
		return err
	}

	// create global ingress
	logger.Info("Create global ingress...")
	globalIng := r.makeIngress(f)
	if err := r.Create(ctx, globalIng); err != nil {
		logger.Error(err, "Error when create global ingress!")
		return err
	}

	// create service
	logger.Info("Create service...")
	serv := r.makeService(f)
	if err := r.Create(ctx, serv); err != nil {
		logger.Error(err, "Error when create service!")
		return err
	}

	// create configmap
	logger.Info("Create configmap...")
	cm := r.makeConfigmap(f)
	if err := r.Create(ctx, cm); err != nil {
		logger.Error(err, "Error when create configmap")
		return err
	}

	// create ingress (namespace)
	logger.Info("Create ingress in namespace...")
	nsIng := r.makeNsIngress(f)
	if err := r.Create(ctx, nsIng); err != nil {
		logger.Error(err, "Error when create Ingress in namespace")
		return err
	}

	// create deployment
	logger.Info("Create Deployment...")
	d := r.makeDeployment(f)
	if err := r.Create(ctx, d); err != nil {
		logger.Error(err, "Error when create Deployment")
		return err
	}

	// create role
	logger.Info("Create Role....")
	role := r.makeRole(f)
	if err := r.Create(ctx, role); err != nil {
		logger.Error(err, "Error when create Role")
		return err
	}

	// create roleAdmin
	logger.Info("Create RoleAdmin....")
	roleAdmin := r.makeRoleAdmin(f)
	if err := r.Create(ctx, roleAdmin); err != nil {
		logger.Error(err, "Error when create RoleAdmin")
		return err
	}

	// create RoleBinding
	logger.Info("Create RoleBinding...")
	rb := r.makeRoleBinding(f)
	if err := r.Create(ctx, rb); err != nil {
		logger.Error(err, "Error when create RoleBinding")
		return err
	}

	// create RoleBindingAdmin
	logger.Info("Create RoleBindingAdmin...")
	rbadmin := r.makeRoleBindingAdmin(f)
	if err := r.Create(ctx, rbadmin); err != nil {
		logger.Error(err, "Error when create RoleBindingAdmin")
		return err
	}

	// create Secret
	logger.Info("Create Secret...")
	sec := r.makeSecret(f)
	if err := r.Create(ctx, sec); err != nil {
		logger.Error(err, "Error when create Secret")
		return err
	}

	// create Service (namespace)
	logger.Info("Create Service Endpoint...")
	servEP := r.makeServiceEP(f)
	if err := r.Create(ctx, servEP); err != nil {
		logger.Error(err, "Error when create Service Endpoint")
		return err
	}

	// create Service ingress
	logger.Info("Create Service ingress...")
	servIng := r.makeServiceIng(f)
	if err := r.Create(ctx, servIng); err != nil {
		logger.Error(err, "Error when create Service ingress")
		return err
	}

	// create Service ingress admin
	logger.Info("Create Service ingress admin...")
	servIngAdmin := r.makeServiceIngAdmin(f)
	if err := r.Create(ctx, servIngAdmin); err != nil {
		logger.Error(err, "Error when create Service ingress admin")
		return err
	}

	// create ServiceAccount
	logger.Info("Create ServiceAccount...")
	serviceAccount := r.makeServiceAccount(f)
	if err := r.Create(ctx, serviceAccount); err != nil {
		logger.Error(err, "Error when create ServiceAccount")
		return err
	}

	// create ServiceAccountAdmin
	logger.Info("Create ServiceAccount admin...")
	serviceAccountAdmin := r.makeServiceAccountAdmin(f)
	if err := r.Create(ctx, serviceAccountAdmin); err != nil {
		logger.Error(err, "Error when create ServiceAccount admin")
		return err
	}

	return nil
}

// Cleanup function
func (r *FirewallReconciler) cleanupResources(f *cloudv1alpha1.Firewall) error {
	// Add logic to delete associated resources using client.Delete
	//ns := r.makeNamespace(f)

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cloudv1alpha1.Firewall{}).
		Owns(&appsv1.Deployment{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Complete(r)
}
