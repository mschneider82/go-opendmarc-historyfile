package goopendmarchistoryfile

import "github.com/emersion/go-msgauth/authres"

type ARCPolicyValue int

const (
	DMARC_ARC_POLICY_RESULT_PASS   ARCPolicyValue = 0
	DMARC_ARC_POLICY_RESULT_UNUSED ARCPolicyValue = 1
	DMARC_ARC_POLICY_RESULT_FAIL   ARCPolicyValue = 2 // should be the default
)

type DMARCResult int

const (
	DMARC_RESULT_REJECT     DMARCResult = 0
	DMARC_RESULT_DISCARD    DMARCResult = 1
	DMARC_RESULT_ACCEPT     DMARCResult = 2
	DMARC_RESULT_TEMPFAIL   DMARCResult = 3
	DMARC_RESULT_QUARANTINE DMARCResult = 4
)

// aresresult type for specifying an authentication result
type aresresult int

const (
	ares_result_undefined aresresult = -1
	ares_result_pass      aresresult = 0
	ares_result_unused    aresresult = 1
	ares_result_softfail  aresresult = 2
	ares_result_neutral   aresresult = 3
	ares_result_temperror aresresult = 4
	ares_result_permerror aresresult = 5
	ares_result_none      aresresult = 6
	ares_result_fail      aresresult = 7
	ares_result_policy    aresresult = 8
	ares_result_nxdomain  aresresult = 9
	ares_result_signed    aresresult = 10
	ares_result_unknown   aresresult = 11
	ares_result_discard   aresresult = 12
)

/*
DMARCPolicy	to enforce, as follows:
			14 = unknown (no record found)
			15 = pass
			16 = reject
			17 = quarantine
			18 = none
*/
type DMARCPolicy int

const (
	DMARC_POLICY_ABSENT     DMARCPolicy = 14 /* Policy up to you. No DMARC record found */
	DMARC_POLICY_PASS       DMARCPolicy = 15 /* Policy OK so accept message */
	DMARC_POLICY_REJECT     DMARCPolicy = 16 /* Policy says to reject message */
	DMARC_POLICY_QUARANTINE DMARCPolicy = 17 /* Policy says to quarantine message */
	DMARC_POLICY_NONE       DMARCPolicy = 18 /* Policy says to monitor and report */

)

type spf = aresresult

const (
	spf_result_undefinied spf = ares_result_undefined
	spf_result_pass       spf = ares_result_pass
	spf_result_none       spf = ares_result_none
	spf_result_tempfail   spf = ares_result_temperror
	spf_result_fail       spf = ares_result_fail
	spf_result_permerror  spf = ares_result_permerror
)

const SPF_RESULT_UNDEFINIED authres.ResultValue = "undefined"

type dmarc_dns_record_Policy int

const (
	dmarc_record_p_unspecified dmarc_dns_record_Policy = '\x00' // p and sp
	dmarc_record_p_none        dmarc_dns_record_Policy = 'n'    // p and sp
	dmarc_record_p_quarantine  dmarc_dns_record_Policy = 'q'    // p and sp
	dmarc_record_p_reject      dmarc_dns_record_Policy = 'r'    // p and sp
)
