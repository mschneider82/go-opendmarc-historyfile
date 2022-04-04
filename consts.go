package goopendmarchistoryfile

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

// ARESResult type for specifying an authentication result
type ARESResult int

const (
	ARES_RESULT_UNDEFINED ARESResult = -1
	ARES_RESULT_PASS      ARESResult = 0
	ARES_RESULT_UNUSED    ARESResult = 1
	ARES_RESULT_SOFTFAIL  ARESResult = 2
	ARES_RESULT_NEUTRAL   ARESResult = 3
	ARES_RESULT_TEMPERROR ARESResult = 4
	ARES_RESULT_PERMERROR ARESResult = 5
	ARES_RESULT_NONE      ARESResult = 6
	ARES_RESULT_FAIL      ARESResult = 7
	ARES_RESULT_POLICY    ARESResult = 8
	ARES_RESULT_NXDOMAIN  ARESResult = 9
	ARES_RESULT_SIGNED    ARESResult = 10
	ARES_RESULT_UNKNOWN   ARESResult = 11
	ARES_RESULT_DISCARD   ARESResult = 12
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

type SPF = ARESResult

const (
	SPF_RESULT_UNDEFINIED SPF = ARES_RESULT_UNDEFINED
	SPF_RESULT_PASS       SPF = ARES_RESULT_PASS
	SPF_RESULT_NONE       SPF = ARES_RESULT_NONE
	SPF_RESULT_TEMPFAIL   SPF = ARES_RESULT_TEMPERROR
	SPF_RESULT_FAIL       SPF = ARES_RESULT_FAIL
	SPF_RESULT_PERMERROR  SPF = ARES_RESULT_PERMERROR
)

type DMARC_DNS_RECORD_Policy int

const (
	DMARC_RECORD_P_UNSPECIFIED DMARC_DNS_RECORD_Policy = '\x00' // p and sp
	DMARC_RECORD_P_NONE        DMARC_DNS_RECORD_Policy = 'n'    // p and sp
	DMARC_RECORD_P_QUARANTINE  DMARC_DNS_RECORD_Policy = 'q'    // p and sp
	DMARC_RECORD_P_REJECT      DMARC_DNS_RECORD_Policy = 'r'    // p and sp
)
