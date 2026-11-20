// Package etcd provides the etcd version 3 backend plugin.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/api/v3/mvccpb"
	etcdcv3 "go.etcd.io/etcd/client/v3"
)

const (
	defaultPriority    = 10    // default priority when nothing is set
	defaultTTL         = 300   // default ttl when nothing is set
	defaultLeaseMinTTL = 30    // default minimum TTL for lease-based records
	defaultLeaseMaxTTL = 86400 // default maximum TTL for lease-based records
	etcdTimeout        = 5 * time.Second
)

var errKeyNotFound = errors.New("key not found")

// Etcd is a plugin talks to an etcd cluster.
type Etcd struct {
	Next        plugin.Handler
	Fall        fall.F
	Zones       []string
	PathPrefix  string
	Upstream    *upstream.Upstream
	Client      *etcdcv3.Client
	MinLeaseTTL uint32 // minimum TTL for lease-based records
	MaxLeaseTTL uint32 // maximum TTL for lease-based records
	// NoApexFallback disables the legacy zone-root lookup when apex.dns records are absent.
	NoApexFallback bool

	endpoints    []string      // Stored here as well, to aid in testing.
	syncInterval time.Duration // Stored here as well, to aid in testing.
	dialTimeout  time.Duration // Stored here as well, to aid in testing.
}

// Services implements the ServiceBackend interface.
func (e *Etcd) Services(ctx context.Context, state request.Request, exact bool, _opt plugin.Options) (services []msg.Service, err error) {
	services, err = e.Records(ctx, state, exact)
	if err != nil {
		return
	}

	services = msg.Group(services)
	return
}

// Reverse implements the ServiceBackend interface.
func (e *Etcd) Reverse(ctx context.Context, state request.Request, exact bool, opt plugin.Options) (services []msg.Service, err error) {
	return e.Services(ctx, state, exact, opt)
}

// Lookup implements the ServiceBackend interface.
func (e *Etcd) Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error) {
	return e.Upstream.Lookup(ctx, state, name, typ)
}

// IsNameError implements the ServiceBackend interface.
func (e *Etcd) IsNameError(err error) bool {
	return err == errKeyNotFound
}

// Records looks up records in etcd. If exact is true, it will lookup just this
// name. This is used when find matches when completing SRV lookups for instance.
//
// The range call and every lease TTL call made while processing its result share
// one time budget of etcdTimeout, and none of them outlives ctx. If that budget is
// used up or ctx is done, Records returns the context error.
func (e *Etcd) Records(ctx context.Context, state request.Request, exact bool) ([]msg.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, etcdTimeout)
	defer cancel()

	name := state.Name()

	path, star := msg.PathWithWildcard(name, e.PathPrefix)
	r, err := e.get(ctx, path, !exact)
	if err != nil {
		return nil, err
	}
	segments := strings.Split(msg.Path(name, e.PathPrefix), "/")
	return e.loopNodes(ctx, r.Kvs, segments, star, state.QType())
}

func (e *Etcd) get(ctx context.Context, path string, recursive bool) (*etcdcv3.GetResponse, error) {
	if recursive {
		if !strings.HasSuffix(path, "/") {
			path = path + "/"
		}
		r, err := e.Client.Get(ctx, path, etcdcv3.WithPrefix())
		if err != nil {
			return nil, err
		}
		if r.Count == 0 {
			path = strings.TrimSuffix(path, "/")
			r, err = e.Client.Get(ctx, path)
			if err != nil {
				return nil, err
			}
			if r.Count == 0 {
				return nil, errKeyNotFound
			}
		}
		return r, nil
	}

	r, err := e.Client.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if r.Count == 0 {
		return nil, errKeyNotFound
	}
	return r, nil
}

func (e *Etcd) loopNodes(ctx context.Context, kv []*mvccpb.KeyValue, nameParts []string, star bool, qType uint16) (sx []msg.Service, err error) {
	bx := make(map[msg.Service]struct{})
Nodes:
	for _, n := range kv {
		if star {
			s := string(n.GetKey())
			keyParts := strings.Split(s, "/")
			for i, n := range nameParts {
				if i > len(keyParts)-1 {
					// name is longer than key
					continue Nodes
				}
				if n == "*" || n == "any" {
					continue
				}
				if keyParts[i] != n {
					continue Nodes
				}
			}
		}
		serv := new(msg.Service)
		if err := json.Unmarshal(n.GetValue(), serv); err != nil {
			return nil, fmt.Errorf("%s: %s", n.GetKey(), err.Error())
		}
		serv.Key = string(n.GetKey())
		if _, ok := bx[*serv]; ok {
			continue
		}
		bx[*serv] = struct{}{}

		ttl, terr := e.ttl(ctx, n, serv)
		if terr != nil {
			return nil, terr
		}
		serv.TTL = ttl
		if serv.Priority == 0 {
			serv.Priority = defaultPriority
		}

		if shouldInclude(serv, qType) {
			sx = append(sx, *serv)
		}
	}
	return sx, nil
}

// TTL returns the smaller of the etcd TTL and the service's
// TTL. If neither of these are set (have a zero value), a default is used.
//
// Any lease lookup it makes is bounded by etcdTimeout. Code that has a request
// context should use ttl, so the lookup also stops when that context is done.
func (e *Etcd) TTL(kv *mvccpb.KeyValue, serv *msg.Service) uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), etcdTimeout)
	defer cancel()

	ttl, err := e.ttl(ctx, kv, serv)
	if err != nil {
		// ctx is done. Keep the long-standing behavior of this method and fall
		// back to the service TTL, or the default.
		if serv.TTL != 0 {
			return serv.TTL
		}
		return defaultTTL
	}
	return ttl
}

// ttl is TTL with the lease lookup bound to ctx. It returns an error only when
// ctx is done; a failed or expired lease with a live ctx falls back as before.
func (e *Etcd) ttl(ctx context.Context, kv *mvccpb.KeyValue, serv *msg.Service) (uint32, error) {
	var etcdTTL uint32

	// Get actual lease TTL from etcd if lease exists and client is available
	if kv.GetLease() != 0 && e.Client != nil {
		// Never start a lease RPC once the request is over.
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		resp, err := e.Client.TimeToLive(ctx, etcdcv3.LeaseID(kv.GetLease()))
		if err != nil && ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err == nil && resp.TTL > 0 {
			leaseTTL := resp.TTL

			// Get bounds with defaults
			minTTL := e.MinLeaseTTL
			if minTTL == 0 {
				minTTL = defaultLeaseMinTTL
			}
			maxTTL := e.MaxLeaseTTL
			if maxTTL == 0 {
				maxTTL = defaultLeaseMaxTTL
			}

			// Clamp lease TTL to configured bounds
			minTTL64 := int64(minTTL)
			maxTTL64 := int64(maxTTL)

			if leaseTTL < minTTL64 {
				leaseTTL = minTTL64
			} else if leaseTTL > maxTTL64 {
				leaseTTL = maxTTL64
			}

			etcdTTL = uint32(leaseTTL) // #nosec G115 -- leaseTTL is bounded by minTTL64/maxTTL64
		}
	}

	if etcdTTL == 0 && serv.TTL == 0 {
		return defaultTTL, nil
	}
	if etcdTTL == 0 {
		return serv.TTL, nil
	}
	if serv.TTL == 0 {
		return etcdTTL, nil
	}
	if etcdTTL < serv.TTL {
		return etcdTTL, nil
	}
	return serv.TTL, nil
}

// shouldInclude returns true if the service should be included in a list of records, given the qType. For all the
// currently supported lookup types, the only one to allow for an empty Host field in the service are TXT records
// which resolve directly.  If a TXT record is being resolved by CNAME, then we expect the Host field to have a
// value while the TXT field will be empty.
func shouldInclude(serv *msg.Service, qType uint16) bool {
	return (qType == dns.TypeTXT && serv.Text != "") || serv.Host != ""
}

// OnShutdown shuts down etcd client when caddy instance restart
func (e *Etcd) OnShutdown() error {
	if e.Client != nil {
		e.Client.Close()
	}
	return nil
}
