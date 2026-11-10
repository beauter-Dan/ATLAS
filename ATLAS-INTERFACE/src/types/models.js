/**
 * UI models. They are produced from the REAL backend contract (ATLAS-SHARED/contracts/openapi.json v1.1.0)
 * by src/services/mappers.js, the only place the backend's snake_case shapes are touched.
 *
 * @typedef {Object} Target
 * @property {string} id
 * @property {string} name
 * @property {string} organization
 * @property {string} baseDomain
 * @property {string} description
 * @property {Authorization} authorization  derived from the backend's authorization_* fields; the server is the authority
 * @property {Assessment[]} assessments
 * @property {Object<string,{permitted:string[],excluded:string[]}>} scope  scope rules keyed by assessment id (scope is per assessment)
 * @property {string} createdAt  ISO 8601
 *
 * @typedef {Object} Authorization
 * @property {'pending'|'authorized'|'expired'} status  the backend has no "revoked" state
 * @property {string} reference
 * @property {string} authorizedBy
 * @property {string} validFrom   YYYY-MM-DD
 * @property {string} validUntil  YYYY-MM-DD
 *
 * @typedef {Object} Assessment
 * @property {string} id @property {string} name @property {string} status @property {string} environment @property {string} startedAt
 *
 * @typedef {Object} DashboardSummary
 * @property {number} targets @property {number} activeAssessments @property {number} assets @property {number} technologies
 * @property {number} pendingHypotheses @property {number} confirmedFindings
 * @property {{id:string,timestamp:string,message:string}[]} recentActivity
 * @property {{id:string,name:string,percent:number,status:string}[]} assessmentProgress  percent = workflow stages completed out of 7
 */
export {};
