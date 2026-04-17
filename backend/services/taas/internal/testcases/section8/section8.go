// Package section8 implements TP-469 Section 8 – Discovery Test Cases.
//
// All tests in this section require network-level infrastructure that cannot
// be automated via the controller REST API:
//   - 8.1–8.3: Require control of a DHCP server (send specific options, reboot
//     device, capture DHCP request packets).
//   - 8.4–8.7: Require mDNS/DNS-SD packet capture on the local network and/or
//     the ability to reboot the device and observe multicast DNS traffic.
//
// All tests are registered with Disabled:true and return testcases.Skip so
// they are visible in the test catalogue but not counted as failures.
package section8

import (
	"context"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the complete set of Section 8 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		testCase8_1(),
		testCase8_2(),
		testCase8_3(),
		testCase8_4(),
		testCase8_5(),
		testCase8_6(),
		testCase8_7(),
	}
}

// ---------------------------------------------------------------------------
// 8.1 – DHCP Discovery - Agent Request Requirements
// ---------------------------------------------------------------------------

func testCase8_1() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.1",
		Section:  8,
		Name:     "DHCP Discovery – Agent Request Requirements",
		Purpose:  "Verify the EUT includes a Vendor Class option with Enterprise Number 3561 and vendor-class-data \"usp\" in its DHCP request.",
		Tags:     []string{"discovery", "dhcp"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.1 requires rebooting the EUT and capturing DHCP request packets to verify " +
					"the Vendor Class option (Enterprise Number 3561, data \"usp\"). " +
					"DHCP packet inspection cannot be performed via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.2 – DHCP Discovery - Agent handling of received options
// ---------------------------------------------------------------------------

func testCase8_2() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.2",
		Section:  8,
		Name:     "DHCP Discovery – Agent handling of received options",
		Purpose:  "Verify the EUT correctly processes a ProvisioningCode delivered via DHCP option and reflects it in the data model.",
		Tags:     []string{"discovery", "dhcp", "provisioning-code"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.2 requires configuring a DHCP server to deliver a specific provisioning code, " +
					"rebooting the EUT, and then verifying the ProvisioningCode via a USP Get. " +
					"DHCP server control cannot be provided via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.3 – DHCP Discovery - FQDN Leads to DNS Query
// ---------------------------------------------------------------------------

func testCase8_3() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.3",
		Section:  8,
		Name:     "DHCP Discovery – FQDN Leads to DNS Query",
		Purpose:  "Verify the EUT performs a DNS lookup when it receives a controller URL containing an FQDN via DHCP.",
		Tags:     []string{"discovery", "dhcp", "dns", "fqdn"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.3 requires configuring a DHCP server to provide a controller FQDN URL, " +
					"rebooting the EUT, and capturing DNS query packets to confirm the EUT resolves the FQDN. " +
					"DHCP server control and DNS packet capture cannot be performed via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.4 – mDNS
// ---------------------------------------------------------------------------

func testCase8_4() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.4",
		Section:  8,
		Name:     "mDNS",
		Purpose:  "Verify the EUT uses mDNS to resolve a controller URL containing \".local.\" received via DHCP.",
		Tags:     []string{"discovery", "mdns"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.4 requires the EUT to have mDNS enabled and a pre-configured controller URL " +
					"containing \".local.\", a Boot! subscription, a reboot of the EUT, and capture of mDNS " +
					"request packets on the local network. " +
					"mDNS packet inspection cannot be performed via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.5 – mDNS and Message Transfer Protocols
// ---------------------------------------------------------------------------

func testCase8_5() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.5",
		Section:  8,
		Name:     "mDNS and Message Transfer Protocols",
		Purpose:  "Verify the EUT advertises each supported MTP via unsolicited mDNS responses containing correct SRV and TXT records.",
		Tags:     []string{"discovery", "mdns", "mtp"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.5 requires rebooting the EUT and capturing unsolicited multicast DNS responses " +
					"on the local network to inspect SRV and TXT records per supported MTP. " +
					"mDNS packet capture cannot be performed via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.6 – DNS - DNS Record Requirements
// ---------------------------------------------------------------------------

func testCase8_6() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.6",
		Section:  8,
		Name:     "DNS – DNS Record Requirements",
		Purpose:  "Verify the EUT sends mDNS advertisements containing a TXT record (with \"path\" and \"name\" attributes) for every supported MTP.",
		Tags:     []string{"discovery", "mdns", "dns", "txt-record"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.6 requires rebooting the EUT and capturing multicast mDNS advertisement packets " +
					"to inspect TXT records for each supported MTP. " +
					"mDNS packet capture cannot be performed via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 8.7 – mDNS request response
// ---------------------------------------------------------------------------

func testCase8_7() testcases.TestCase {
	return testcases.TestCase{
		ID:       "8.7",
		Section:  8,
		Name:     "mDNS request response",
		Purpose:  "Verify the EUT responds to an mDNS query with the correct service information.",
		Tags:     []string{"discovery", "mdns", "query"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 8.7 requires rebooting the EUT, sending an mDNS query to the multicast domain, " +
					"and capturing the EUT's mDNS response to verify correctness. " +
					"mDNS query/response cannot be performed via the controller REST API.")
		},
	}
}
