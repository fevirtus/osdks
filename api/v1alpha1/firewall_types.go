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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// FirewallSpec defines the desired state of Firewall
type FirewallSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of Firewall. Edit firewall_types.go to remove/update

	Uid                         string `json:"uid,omitempty"`         // name/namespace of global ex: test-1
	Domain                      string `json:"domain,omitempty"`      // ex: test-1.abc.xyz
	Endpoints                   string `json:"endpoints,omitempty"`   // endpoints/subsets/address/ip
	Port                        int32  `json:"port,omitempty"`        // endpoints/subsets/ports/port
	SecretName                  string `json:"secret_name,omitempty"` // name of secret
	Crt                         []byte `json:"crt,omitempty"`         // tls crt
	Key                         []byte `json:"key,omitempty"`         // tls key
	BackendProtocol             string `json:"backend_protocol,omitempty"`
	Protocol                    string `json:"protocol,omitempty"`
	WafState                    string `json:"waf_state,omitempty"`
	WafMode                     string `json:"waf_mode,omitempty"`
	WafRequestBodyCheck         string `json:"waf_request_body_check,omitempty"`
	WafMaxRequestBodySizeInKb   string `json:"waf_max_request_body_size_in_kb,omitempty"`
	WafMaxRequestBodySizeNoFile string `json:"waf_max_request_body_size_no_file,omitempty"`
	IncludeOwaspConfig          string `json:"include_owasp_config,omitempty"`
	SecruleRemoveById           string `json:"secrule_remove_by_id,omitempty"`
	ExceptList                  string `json:"except_list,omitempty"`
	CustomRule                  string `json:"custom_rule,omitempty"`
	NginxUpstreamVhost          string `json:"nginx_upstream_vhost,omitempty"`
	ExternalName                string `json:"external_name,omitempty"`
}

// FirewallStatus defines the observed state of Firewall
type FirewallStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Nodes []string `json:"nodes"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// Firewall is the Schema for the firewalls API
type Firewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallSpec   `json:"spec,omitempty"`
	Status FirewallStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// FirewallList contains a list of Firewall
type FirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Firewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Firewall{}, &FirewallList{})
}
