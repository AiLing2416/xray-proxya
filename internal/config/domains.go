package config

import (
	"crypto/rand"
	"math/big"
)

var realityDomains = []string{
	"cloudflare.com",
	"amazon.com",
	"digitalocean.com",
	"linode.com",
	"docker.com",
	"ubuntu.com",
	"debian.org",
	"python.org",
	"go.dev",
	"github.com",
	"amd.com",
	"intel.com",
	"nvidia.com",
	"kernel.org",
	"postgresql.org",
	"mongodb.com",
	"redis.io",
}

func GetRandomRealityDomain() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(realityDomains))))
	if err != nil {
		return realityDomains[0]
	}
	return realityDomains[n.Int64()]
}
