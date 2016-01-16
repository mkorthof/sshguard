package main

import (
	"regexp"
)

// Parser is a group of compiled regular expressions for matching attacks.
type Parser struct {
	res []*regexp.Regexp
}

func extract(re *regexp.Regexp, s string) map[string]string {
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return nil
	}

	names := re.SubexpNames()
	results := make(map[string]string)
	for i, name := range names {
		if i != 0 && name != "" {
			results[name] = matches[i]
		}
	}
	return results
}

// NewParser compiles a slice of strings into a Parser.
func NewParser(patterns []string) *Parser {
	var p Parser
	p.res = make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		p.res[i] = regexp.MustCompile(pattern)
	}
	return &p
}

// Parse extracts details of an attack or returns nil if no match.
func (p *Parser) Parse(s string) map[string]string {
	for _, re := range p.res {
		if result := extract(re, s); result != nil {
			return result
		}
	}
	return nil
}

// Addr returns the value of the address fields of a string-string map.
func Addr(values map[string]string) string {
	if ip6, ok := values["ip6"]; ok {
		return ip6
	}
	return values["ip4"]
}
