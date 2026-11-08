/**
 * PROVISIONAL shapes. The shared contract (ATLAS-SHARED/contracts/*) was not available
 * when this scaffold was written. Replace these with the documented models, then update
 * src/services/contract.js and src/services/mock/ to match exactly.
 *
 * @typedef {Object} DashboardSummary
 * @property {number} targets
 * @property {number} activeAssessments
 * @property {number} assets
 * @property {number} technologies
 * @property {number} pendingHypotheses
 * @property {number} confirmedFindings
 * @property {ActivityEntry[]} recentActivity
 * @property {AssessmentProgress[]} assessmentProgress
 *
 * @typedef {Object} ActivityEntry
 * @property {string} id
 * @property {string} timestamp ISO 8601
 * @property {string} message
 *
 * @typedef {Object} AssessmentProgress
 * @property {string} id
 * @property {string} name
 * @property {number} percent 0-100
 * @property {string} status
 *
 * @typedef {Object} Target
 * @property {string} id
 * @property {string} name
 * @property {string} organization
 * @property {string} description
 * @property {Authorization} authorization
 * @property {string[]} permittedAssets  hostnames or patterns inside scope
 * @property {string[]} excludedAssets   always out of scope; wins over permitted
 * @property {AssessmentRef[]} assessments
 * @property {string} createdAt
 * @property {string} updatedAt
 *
 * @typedef {Object} Authorization
 * @property {'pending'|'authorized'|'expired'|'revoked'} status  set by the backend, never by this UI
 * @property {string} reference   engagement or authorization reference
 * @property {string} authorizedBy
 * @property {string} validFrom   YYYY-MM-DD
 * @property {string} validUntil  YYYY-MM-DD
 *
 * @typedef {Object} AssessmentRef
 * @property {string} id
 * @property {string} name
 * @property {string} status
 * @property {string} startedAt
 */
export {};
