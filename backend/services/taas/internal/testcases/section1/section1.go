// Package section1 implements TP-469 Section 1 – Messages and Path Names.
package section1

import "github.com/leandrofars/oktopus/taas/internal/testcases"

// All returns the complete set of Section 1 test cases.
func All() []testcases.TestCase {
	var cases []testcases.TestCase
	cases = append(cases, addCases()...)
	cases = append(cases, setCases()...)
	cases = append(cases, deleteCases()...)
	cases = append(cases, getCases()...)
	cases = append(cases, operateCases()...)
	cases = append(cases, getInstancesCases()...)
	cases = append(cases, getSupportedDMCases()...)
	cases = append(cases, notifyCases()...)
	return cases
}
