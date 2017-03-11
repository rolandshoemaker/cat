package cat

import (
	"crypto/x509"
	"fmt"
	"plugin"
)

func LoadCertParsers(plugins []string) ([]CertParser, error) {
	parsers := []CertParser{}
	for _, pluginPath := range plugins {
		p, err := plugin.Open(pluginPath)
		if err != nil {
			return nil, err
		}
		symbol, err := p.Lookup("ProcessCertificate")
		if err != nil {
			return nil, err
		}
		parser, ok := symbol.(func(*x509.Certificate) map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Unable to load 'ParseCertificate' function from plugin %q", p)
		}
		parsers = append(parsers, parser)
	}
	return parsers, nil
}

func LoadChainParsers(plugins []string) ([]ChainParser, error) {
	parsers := []ChainParser{}
	for _, pluginPath := range plugins {
		p, err := plugin.Open(pluginPath)
		if err != nil {
			return nil, err
		}
		symbol, err := p.Lookup("ProcessChain")
		if err != nil {
			return nil, err
		}
		parser, ok := symbol.(func([]*x509.Certificate) map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Unable to load 'ParseChain' function from plugin %q", p)
		}
		parsers = append(parsers, parser)
	}
	return parsers, nil
}
