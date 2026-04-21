package config

import (
	"crypto/rand"
	"math/big"
)

var realityDomains = []string{
	"www.google.com",
	"www.amazon.com",
	"www.microsoft.com",
	"www.cloudflare.com",
	"www.intel.com",
	"www.nvidia.com",
	"www.amd.com",
	"www.digitalocean.com",
	"www.docker.com",
	"www.ubuntu.com",
	"www.debian.org",
	"www.python.org",
	"go.dev",
	"github.com",
	"www.kernel.org",
	"www.postgresql.org",
	"www.mongodb.com",
	"redis.io",
}

func GetRandomRealityDomain() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(realityDomains))))
	if err != nil {
		return realityDomains[0]
	}
	return realityDomains[n.Int64()]
}

func GetAllRealityDomains() []string {
	return realityDomains
}
