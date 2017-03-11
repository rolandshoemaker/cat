package cat

import (
	"crypto/x509"
	"fmt"
	"sync"
)

type CertParser func(*x509.Certificate) map[string]interface{}
type ChainParser func([]*x509.Certificate) map[string]interface{}

func ProcessCertificate(cert *x509.Certificate, parsers []CertParser) map[string]interface{} {
	wg := new(sync.WaitGroup)
	results := make(chan map[string]interface{}, len(parsers))
	for _, parser := range parsers {
		wg.Add(1)
		go func(p CertParser) {
			defer wg.Done()
			r := p(cert)
			if r == nil {
				return
			}
			results <- r
		}(parser)
	}
	fmt.Println("wait")
	wg.Wait()
	fmt.Println("waited")
	close(results)
	flat := map[string]interface{}{}
	for r := range results {
		for k, v := range r {
			// fail on overwrite?
			flat[k] = v
		}
	}
	fmt.Println("doned")
	return flat
}

func ProcessChain(chain []*x509.Certificate, parsers []ChainParser) map[string]interface{} {
	wg := new(sync.WaitGroup)
	results := make(chan map[string]interface{}, len(parsers))
	for _, parser := range parsers {
		wg.Add(1)
		go func(p ChainParser) {
			defer wg.Done()
			r := p(chain)
			if r == nil {
				return
			}
			results <- r
		}(parser)
	}
	wg.Wait()
	close(results)
	flat := map[string]interface{}{}
	for r := range results {
		for k, v := range r {
			// fail on overwrite?
			flat[k] = v
		}
	}
	return flat
}
