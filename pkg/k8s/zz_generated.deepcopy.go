//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package k8s

import (
	net "net"

	cidr "github.com/cilium/cilium/pkg/cidr"
	types "github.com/cilium/cilium/pkg/clustermesh/types"
	loadbalancer "github.com/cilium/cilium/pkg/loadbalancer"
	store "github.com/cilium/cilium/pkg/service/store"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend) DeepCopyInto(out *Backend) {
	*out = *in
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make(store.PortConfiguration, len(*in))
		for key, val := range *in {
			var outVal *loadbalancer.L4Addr
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(loadbalancer.L4Addr)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.HintsForZones != nil {
		in, out := &in.HintsForZones, &out.HintsForZones
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend.
func (in *Backend) DeepCopy() *Backend {
	if in == nil {
		return nil
	}
	out := new(Backend)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Endpoints) DeepCopyInto(out *Endpoints) {
	*out = *in
	if in.Backends != nil {
		in, out := &in.Backends, &out.Backends
		*out = make(map[types.IPCluster]*Backend, len(*in))
		for key, val := range *in {
			var outVal *Backend
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(Backend)
				(*in).DeepCopyInto(*out)
			}
			(*out)[key] = outVal
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Endpoints.
func (in *Endpoints) DeepCopy() *Endpoints {
	if in == nil {
		return nil
	}
	out := new(Endpoints)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service) DeepCopyInto(out *Service) {
	*out = *in
	if in.FrontendIPs != nil {
		in, out := &in.FrontendIPs, &out.FrontendIPs
		*out = make([]net.IP, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = make(net.IP, len(*in))
				copy(*out, *in)
			}
		}
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make(map[loadbalancer.FEPortName]*loadbalancer.L4Addr, len(*in))
		for key, val := range *in {
			var outVal *loadbalancer.L4Addr
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(loadbalancer.L4Addr)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.NodePorts != nil {
		in, out := &in.NodePorts, &out.NodePorts
		*out = make(map[loadbalancer.FEPortName]NodePortToFrontend, len(*in))
		for key, val := range *in {
			var outVal map[string]*loadbalancer.L3n4AddrID
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = make(NodePortToFrontend, len(*in))
				for key, val := range *in {
					var outVal *loadbalancer.L3n4AddrID
					if val == nil {
						(*out)[key] = nil
					} else {
						in, out := &val, &outVal
						*out = new(loadbalancer.L3n4AddrID)
						(*in).DeepCopyInto(*out)
					}
					(*out)[key] = outVal
				}
			}
			(*out)[key] = outVal
		}
	}
	if in.K8sExternalIPs != nil {
		in, out := &in.K8sExternalIPs, &out.K8sExternalIPs
		*out = make(map[string]net.IP, len(*in))
		for key, val := range *in {
			var outVal []byte
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = make(net.IP, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
	}
	if in.LoadBalancerIPs != nil {
		in, out := &in.LoadBalancerIPs, &out.LoadBalancerIPs
		*out = make(map[string]net.IP, len(*in))
		for key, val := range *in {
			var outVal []byte
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = make(net.IP, len(*in))
				copy(*out, *in)
			}
			(*out)[key] = outVal
		}
	}
	if in.LoadBalancerSourceRanges != nil {
		in, out := &in.LoadBalancerSourceRanges, &out.LoadBalancerSourceRanges
		*out = make(map[string]*cidr.CIDR, len(*in))
		for key, val := range *in {
			var outVal *cidr.CIDR
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = (*in).DeepCopy()
			}
			(*out)[key] = outVal
		}
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Selector != nil {
		in, out := &in.Selector, &out.Selector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service.
func (in *Service) DeepCopy() *Service {
	if in == nil {
		return nil
	}
	out := new(Service)
	in.DeepCopyInto(out)
	return out
}
