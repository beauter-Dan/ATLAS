ROLES = ["viewer", "analyst", "approver", "admin"]
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}
ASSESSMENT_STATUS = ["draft", "active", "paused", "completed", "archived"]
STATUS_TRANSITIONS = {
    "draft": {"active", "archived"},
    "active": {"paused", "completed"},
    "paused": {"active", "completed", "archived"},
    "completed": {"archived"},
    "archived": set(),
}
ENVIRONMENTS = ["test", "staging", "production"]
ASSET_TYPES = ["domain", "subdomain", "ip", "url", "api", "service", "database",
               "storage", "third_party", "auth_system", "application_server"]
SCOPE_STATES = ["authorized", "excluded", "discovered"]
RULE_TYPES = ["include", "exclude"]
MATCH_TYPES = ["domain", "wildcard", "ip", "cidr", "url_prefix"]
CONFIDENCE = ["low", "medium", "high"]
VERIFICATION = ["unverified", "verified", "disputed"]
OBS_KINDS = ["direct_observation", "inference", "hypothesis", "confirmed", "unknown"]
HYP_STATUS = ["open", "experiment_planned", "validated", "refuted", "closed"]
EXP_STATUS = ["draft", "pending_approval", "approved", "rejected", "running",
              "completed", "failed", "rolled_back"]
EXP_TYPES = ["http_status_check", "header_review"]
CLASSIFICATIONS = ["confirmed_vulnerability", "potential_vulnerability",
                   "informational_observation", "false_positive", "insufficient_evidence"]
SEVERITIES = ["info", "low", "medium", "high", "critical"]

MEMBER_PERMISSIONS = ["viewer", "analyst", "approver"]
MEMBER_LEVEL = {p: i for i, p in enumerate(MEMBER_PERMISSIONS)}
