# Bug Discovery Protocol - LinkShield Backend API

## Mission Statement

You are conducting a comprehensive bug discovery audit of the LinkShield Backend API project:

```
Repository: https://github.com/freelancing-solutions/linkshield_backend
Stack: FastAPI + Celery + Python + PostgreSQL + Redis
```

Your objective is to **systematically identify bugs, potential issues, and code smells** throughout the codebase, then generate Kiro specification files for each bug category to guide the debugging process.

**CRITICAL: This is a discovery mission, NOT a debugging mission. You identify and document issues, you do NOT fix them.**

---

## Phase 1: Systematic Code Audit

### 1.1 Repository Setup

```bash
# Clone repository
git clone https://github.com/freelancing-solutions/linkshield_backend
cd linkshield_backend

# Setup environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 1.2 Bug Discovery Categories

Systematically analyze code for these bug categories:

#### Category 1: Logic Errors
- Incorrect conditional logic
- Off-by-one errors
- Null/None handling issues
- Edge case failures
- Incorrect operator usage (e.g., `=` vs `==`, `and` vs `or`)
- Type mismatches
- Unreachable code
- Infinite loops or recursion

#### Category 2: Async/Concurrency Issues
- **Race conditions**
- Missing `await` on async functions
- Blocking operations in async context
- Deadlocks in background tasks
- Celery task configuration errors
- Task retry logic issues
- Incorrect use of async/sync Redis operations
- Background task error handling

#### Category 3: Database Issues
- **SQL injection vulnerabilities** (even with ORM)
- N+1 query problems
- Missing database indexes
- Transaction management errors
- Connection pool exhaustion
- Lazy loading issues
- Missing foreign key constraints
- Incorrect relationship configurations
- Database migration issues

#### Category 4: Authentication & Security
- JWT token validation flaws
- Session management bugs
- Password hashing issues
- **Authentication bypass vulnerabilities**
- Missing authorization checks
- Token expiry not enforced
- Refresh token vulnerabilities
- Rate limiting bypass
- CORS misconfiguration
- Security header issues

#### Category 5: API Integration Bugs
- **VirusTotal API** error handling
- **Google Safe Browsing API** response parsing
- **URLVoid API** timeout handling
- **OpenAI API** rate limiting
- API key validation failures
- External service circuit breaker missing
- Retry logic issues
- Response caching bugs

#### Category 6: Input Validation
- Missing input sanitization
- **XSS vulnerabilities**
- Injection attacks (SQL, command, etc.)
- URL validation bypasses
- Email validation flaws
- File upload vulnerabilities
- Request size limit bypasses
- JSON parsing errors

#### Category 7: Error Handling
- Unhandled exceptions
- Information leakage in error messages
- Missing error logging
- Incorrect HTTP status codes
- Exception swallowing (empty except blocks)
- Resource leaks in error paths
- Missing rollback on errors
- Uncaught async exceptions

#### Category 8: Rate Limiting & Quotas
- Rate limit bypass vulnerabilities
- Incorrect limit calculations
- Redis connection failures
- Memory backend inconsistencies
- Subscription tier enforcement bugs
- Quota reset logic errors
- Distributed rate limiting issues

#### Category 9: Data Integrity
- Data validation failures
- Serialization/deserialization bugs
- Data type inconsistencies
- Missing required fields
- Constraint violation handling
- Duplicate data prevention
- Data migration errors

#### Category 10: Performance & Resource Issues
- Memory leaks
- Database connection leaks
- Redis connection leaks
- Inefficient queries
- Excessive API calls
- Missing pagination
- Large object loading
- Background task queue buildup

#### Category 11: Configuration & Environment
- Missing environment variables
- Incorrect default values
- Configuration validation missing
- Secret key exposure
- Hardcoded credentials
- Environment-specific bugs
- Dependency version conflicts

#### Category 12: Testing & Documentation
- Missing test coverage for critical paths
- Incorrect test assertions
- Flaky tests
- Outdated documentation
- Missing API endpoint documentation
- Incorrect example code

---

### 1.3 Audit Methodology

For **EACH file** in the codebase, follow this systematic approach:

#### Step 1: File-Level Analysis

```markdown
## Auditing: [filepath]

**Purpose:** [What this file does]
**Dependencies:** [Key imports and external dependencies]
**Complexity:** [High/Medium/Low]

### Static Analysis Checklist:
- [ ] Syntax correctness verified
- [ ] Type hints present and correct
- [ ] Docstrings present
- [ ] Error handling present
- [ ] Logging implemented
- [ ] Security considerations addressed
```

#### Step 2: Function-Level Analysis

For each function/method:

```python
# Example analysis template
"""
Function: authenticate_user()
Location: src/authentication/auth_service.py:45

BUG DISCOVERY ANALYSIS:
========================

1. LOGIC ERRORS:
   - Line 52: Missing check for disabled users
   - Line 60: Password comparison before rate limit check (timing attack)

2. SECURITY ISSUES:
   - Line 48: Username enumeration possible via timing difference
   - Line 67: Token expiry not validated

3. ERROR HANDLING:
   - Line 55: Database exception not caught
   - Line 70: Returns generic error, information leakage

4. PERFORMANCE:
   - Line 58: Multiple database queries, should use JOIN

5. CODE QUALITY:
   - Missing type hints on return value
   - No docstring
   - Magic number '3600' (should be config constant)

SEVERITY: HIGH
CATEGORY: Authentication & Security
PRIORITY: P0
"""
```

#### Step 3: Integration Point Analysis

Analyze how components interact:

```markdown
## Integration Point: Authentication → Rate Limiting

**Files Involved:**
- src/authentication/auth_service.py
- src/security/rate_limiter.py

**Potential Issues:**
1. Race condition: User can bypass rate limit by making concurrent requests
2. Redis connection not released on error
3. Rate limit check happens AFTER expensive database query
4. Missing distributed lock for quota updates

**Evidence:**
- File: src/security/rate_limiter.py:120
- Code: `redis_client.incr(key)` without atomic check-and-increment

**Impact:** High - Rate limiting can be bypassed
**Likelihood:** High - Easy to exploit
**Severity:** CRITICAL
```

---

### 1.4 Discovery Process

#### Directory-by-Directory Audit Order:

1. **src/config/** - Configuration issues
2. **src/models/** - Database model issues
3. **src/authentication/** - Auth bugs (CRITICAL)
4. **src/security/** - Security vulnerabilities (CRITICAL)
5. **src/services/** - External service integration bugs
6. **src/controllers/** - Business logic errors
7. **src/routes/** - API endpoint bugs
8. **src/bots/** - Bot handler issues
9. **app.py** - Application initialization bugs

#### For Each Directory:

```markdown
## Directory: src/authentication/

**Files Audited:**
1. auth_service.py - [X bugs found]
2. jwt_handler.py - [Y bugs found]
3. session_manager.py - [Z bugs found]

**Critical Bugs:** [Count]
**High Priority:** [Count]
**Medium Priority:** [Count]
**Low Priority:** [Count]

**Most Severe Issues:**
1. [Bug description]
2. [Bug description]
3. [Bug description]
```

---

## Phase 2: Bug Classification & Specification

### 2.1 Bug Documentation Format

For **EACH discovered bug**, create a detailed report:

```markdown
# BUG-[ID]: [Short Description]

## Discovery Information
- **Discovered By:** Automated Audit
- **Discovery Date:** [Date]
- **File:** [filepath:line_number]
- **Category:** [Bug Category]
- **Severity:** CRITICAL | HIGH | MEDIUM | LOW
- **Priority:** P0 | P1 | P2 | P3

## Bug Description

### What's Wrong:
[Clear description of the bug]

### Expected Behavior:
[What should happen]

### Actual Behavior:
[What actually happens]

### Root Cause:
[Technical explanation of why the bug exists]

## Evidence

### Code Location:
```python
# File: src/authentication/auth_service.py
# Lines: 45-52

def authenticate_user(username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password_hash):  # BUG: No account lockout check
        return create_token(user)
    return None  # BUG: Doesn't distinguish between invalid user and wrong password
```

### Stack Trace (if applicable):
```
[Error output if bug causes crashes]
```

### Reproduction Steps:
1. [Step 1]
2. [Step 2]
3. [Bug manifests]

## Impact Analysis

### Security Impact:
- [ ] Information disclosure
- [ ] Authentication bypass
- [ ] Authorization bypass
- [ ] Data corruption
- [ ] Denial of service
- [ ] Remote code execution

### Functional Impact:
- [ ] Feature completely broken
- [ ] Feature partially broken
- [ ] Performance degradation
- [ ] User experience degraded
- [ ] Edge case only

### Business Impact:
- [ ] Data loss possible
- [ ] Service downtime
- [ ] Compliance violation
- [ ] Revenue impact
- [ ] Reputation damage

### Affected Components:
- [Component 1]
- [Component 2]

### Affected Users:
- [ ] All users
- [ ] Authenticated users only
- [ ] Specific subscription tier
- [ ] Admin users only

## Technical Details

### Environment:
- Python Version: [Version]
- FastAPI Version: [Version]
- Dependencies: [Relevant packages]

### Related Code:
- [Other files/functions affected]

### Dependencies:
- [Other bugs this depends on]
- [Other bugs that depend on this]

## Testing

### Detection Method:
- [ ] Manual code review
- [ ] Static analysis tool
- [ ] Runtime error
- [ ] Unit test failure
- [ ] Integration test failure
- [ ] Production incident

### Test Case to Verify Bug:
```python
def test_bug_[id]():
    """Test that reproduces the bug"""
    # Test code here
    assert False  # Bug exists
```

### Test Case for Fix Verification:
```python
def test_bug_[id]_fixed():
    """Test that verifies the fix"""
    # Test code here
    assert True  # Bug is fixed
```

## Proposed Fix Strategy

### Approach:
[High-level approach to fixing]

### Files to Modify:
- [file1.py]
- [file2.py]

### Breaking Changes:
- [ ] Yes - [Describe]
- [ ] No

### Dependencies Required:
- [New packages if needed]

### Estimated Effort:
- Time: [X hours]
- Complexity: [Low/Medium/High]
- Risk: [Low/Medium/High]

## References

- Related Issues: [GitHub issue links]
- Related PRs: [Pull request links]
- Documentation: [Relevant docs]
- Similar Bugs: [Bug IDs]
- External References: [Links to articles, CVEs, etc.]

## Metadata

- **Status:** OPEN
- **Assignee:** Unassigned
- **Labels:** [bug, security, performance, etc.]
- **Milestone:** [Release version]
- **Created:** [Date]
- **Updated:** [Date]
```

---

### 2.2 Generate Kiro Bug Fix Specs

For **each bug category** with discovered bugs, generate a Kiro spec set:

#### Directory Structure:
```
.kiro/
├── bugs/
│   ├── authentication-security/
│   │   ├── requirements.md
│   │   ├── design.md
│   │   ├── tasks.md
│   │   └── bugs/
│   │       ├── BUG-001.md
│   │       ├── BUG-002.md
│   │       └── BUG-003.md
│   ├── database-issues/
│   │   ├── requirements.md
│   │   ├── design.md
│   │   ├── tasks.md
│   │   └── bugs/
│   │       ├── BUG-010.md
│   │       └── BUG-011.md
│   └── api-integration/
│       ├── requirements.md
│       ├── design.md
│       ├── tasks.md
│       └── bugs/
│           └── BUG-020.md
└── bug-summary.md
```

#### requirements.md Template (Bug Fix):

```markdown
# Requirements: [Bug Category] Fixes

## Overview
Address all identified bugs in the [category] category to improve [aspect] of the LinkShield Backend API.

## Bugs to Fix

### BUG-[ID]: [Title]
**Severity:** [Level]
**Priority:** [Level]
**Description:** [Brief description]
**Impact:** [Impact summary]

[Repeat for all bugs in category]

## Functional Requirements

### FR-1: Fix [Bug Type]
- All [bug type] bugs must be resolved
- No new bugs introduced during fixes
- Existing functionality must remain intact
- Tests must be added for all fixes

### FR-2: Improve [Aspect]
- [Specific improvement needed]
- [Metric to achieve]

## Non-Functional Requirements

### NFR-1: Security
- All CRITICAL and HIGH security bugs fixed
- Security testing performed post-fix
- No information leakage
- Proper authentication/authorization enforced

### NFR-2: Performance
- No performance degradation from fixes
- Performance improvements where possible
- Database queries optimized

### NFR-3: Maintainability
- Code quality improved
- Documentation updated
- Tests added for all fixes

## Success Criteria
- [ ] All bugs in category resolved
- [ ] All tests passing
- [ ] Security audit passed
- [ ] Performance benchmarks met
- [ ] Code review approved
- [ ] No regressions introduced

## Testing Requirements
- Unit tests for each bug fix
- Integration tests for multi-component bugs
- Security testing for security bugs
- Performance testing for performance bugs
- Regression testing for all areas

## Documentation Requirements
- Update API documentation
- Update code comments
- Create debugging guide
- Document architectural decisions
```

#### design.md Template (Bug Fix):

```markdown
# Design: [Bug Category] Fixes

## Bug Analysis Summary

### Category Overview
**Total Bugs:** [N]
**Critical:** [N]
**High:** [N]
**Medium:** [N]
**Low:** [N]

### Root Cause Analysis
**Common Patterns:**
1. [Pattern 1] - [N bugs]
2. [Pattern 2] - [N bugs]

**Systemic Issues:**
- [Issue affecting multiple areas]

## Fix Architecture

### Strategy
**Approach:** [Describe overall approach]

**Principles:**
1. Fix root cause, not symptoms
2. Maintain backward compatibility where possible
3. Add comprehensive testing
4. Improve code quality

### Component Modifications

#### Component: [Component Name]

**Current Issues:**
- BUG-[ID]: [Description]
- BUG-[ID]: [Description]

**Proposed Changes:**

**File:** `src/[path]/[file].py`

**Before:**
```python
def problematic_function():
    # Buggy code
    pass
```

**After:**
```python
def fixed_function():
    # Fixed code with improvements
    pass
```

**Rationale:**
[Why this fix approach]

**Side Effects:**
- [Any breaking changes]
- [Components affected]

**Testing:**
- [Test cases needed]

### Data Model Changes

**Current Schema:**
```python
class Model:
    field1: Type  # BUG: Missing constraint
```

**Fixed Schema:**
```python
class Model:
    field1: Type = Field(..., constraint)  # Fixed
```

**Migration:**
```python
# Alembic migration code
```

### Security Enhancements

**Authentication Flow:**
```
[Current Flow with vulnerabilities marked]
     ↓
[Fixed Flow with security checks]
```

**Rate Limiting:**
[How rate limiting bugs are fixed]

### Error Handling Strategy

**Current:**
- Inconsistent error handling
- Information leakage

**Fixed:**
- Centralized error handling
- Secure error messages
- Proper logging

**Implementation:**
```python
class SecureErrorHandler:
    def handle_error(self, error):
        # Implementation
        pass
```

### Performance Optimizations

**Database Queries:**
- Add indexes: [List]
- Optimize queries: [List]
- Implement caching: [Where]

**API Calls:**
- Circuit breaker implementation
- Retry logic fixes
- Timeout handling

### Testing Strategy

**Unit Tests:**
- Test each bug fix individually
- Test edge cases
- Test error conditions

**Integration Tests:**
- Test component interactions
- Test authentication flow end-to-end
- Test rate limiting
- Test API integrations

**Security Tests:**
- Penetration testing scenarios
- Authentication bypass attempts
- Injection testing
- Rate limit bypass testing

### Rollback Plan

**If issues arise:**
1. [Rollback step 1]
2. [Rollback step 2]

**Feature flags:**
- Enable new code gradually
- Easy rollback mechanism

## Monitoring & Validation

**Metrics to Track:**
- Error rates
- Response times
- Authentication failures
- Rate limit hits

**Alerts:**
- [Alert condition 1]
- [Alert condition 2]

**Validation:**
- Security scan results
- Performance benchmarks
- Test coverage metrics
```

#### tasks.md Template (Bug Fix):

```markdown
# Tasks: [Bug Category] Fixes

## Prerequisites
- [ ] All bugs in category documented
- [ ] Fix strategies reviewed and approved
- [ ] Test environment set up
- [ ] Backup/rollback plan ready

## Phase 1: Critical Bug Fixes (P0)

### Task 1.1: Fix BUG-[ID] - [Title]
- [ ] Review bug details
- [ ] Write failing test case
- [ ] Implement fix
- [ ] Verify test passes
- [ ] Verify no regressions
- [ ] Update documentation

**File:** [filepath]
**Lines:** [line numbers]
**Estimated Time:** [X hours]
**Dependencies:** None
**Severity:** CRITICAL
**Priority:** P0

**Acceptance Criteria:**
- [ ] Bug no longer reproducible
- [ ] Test case passes
- [ ] Security scan passes
- [ ] Code review approved
- [ ] No new bugs introduced

**Testing Checklist:**
- [ ] Unit test added
- [ ] Integration test added (if applicable)
- [ ] Security test passed
- [ ] Performance impact measured
- [ ] Edge cases tested

**Rollback Plan:**
- Git commit: [hash]
- Rollback command: `git revert [hash]`

### Task 1.2: Fix BUG-[ID] - [Title]
[Same structure]

## Phase 2: High Priority Bugs (P1)

### Task 2.1: Fix BUG-[ID] - [Title]
[Same structure]

## Phase 3: Medium Priority Bugs (P2)

### Task 3.1: Fix BUG-[ID] - [Title]
[Same structure]

## Phase 4: Low Priority Bugs (P3)

### Task 4.1: Fix BUG-[ID] - [Title]
[Same structure]

## Phase 5: Verification & Testing

### Task 5.1: Comprehensive Testing
- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] Security testing complete
- [ ] Performance testing complete
- [ ] Load testing complete
- [ ] Regression testing complete

**Estimated Time:** [X hours]
**Dependencies:** All fixes complete

**Test Suites:**
```bash
# Run all tests
pytest tests/

# Run security tests
pytest tests/security/

# Run performance tests
pytest tests/performance/ --benchmark
```

### Task 5.2: Security Audit
- [ ] Run automated security scanners
- [ ] Manual penetration testing
- [ ] Code security review
- [ ] Dependency vulnerability scan
- [ ] Configuration security check

**Tools:**
- `bandit src/`
- `safety check`
- `pip-audit`

### Task 5.3: Performance Benchmarking
- [ ] Baseline metrics collected
- [ ] Post-fix metrics collected
- [ ] Comparison analysis
- [ ] Performance regression check

**Metrics:**
- Response time: [Target]
- Throughput: [Target]
- Error rate: [Target]
- CPU usage: [Target]
- Memory usage: [Target]

## Phase 6: Documentation & Deployment

### Task 6.1: Update Documentation
- [ ] API documentation updated
- [ ] Code comments added/updated
- [ ] Architecture docs updated
- [ ] Changelog updated
- [ ] Migration guide created

**Estimated Time:** [X hours]

### Task 6.2: Deployment Preparation
- [ ] Database migrations tested
- [ ] Deployment script tested
- [ ] Rollback script tested
- [ ] Monitoring configured
- [ ] Alerts configured

### Task 6.3: Staged Deployment
- [ ] Deploy to staging
- [ ] Smoke test on staging
- [ ] Deploy to production (canary)
- [ ] Monitor metrics
- [ ] Full production rollout

---

## Bug Fix Summary

| Bug ID | Title | Priority | Estimated | Status |
|--------|-------|----------|-----------|--------|
| BUG-001| [Title] | P0 | 2h | [ ] |
| BUG-002| [Title] | P0 | 3h | [ ] |
| BUG-003| [Title] | P1 | 4h | [ ] |

**Total Estimated Time:** [X hours]
**Critical Path:** P0 bugs → Testing → Deployment

## Risk Management

**High Risk Areas:**
1. [Area 1] - [Mitigation]
2. [Area 2] - [Mitigation]

**Contingency Plans:**
- If [scenario]: [Action]
- If [scenario]: [Action]
```

---

## Phase 3: Reporting & Summary

### 3.1 Bug Summary Report

**File: `.kiro/bug-summary.md`**

```markdown
# LinkShield Backend API - Bug Discovery Report

**Audit Date:** [Date]
**Auditor:** Automated Bug Discovery System
**Repository:** https://github.com/freelancing-solutions/linkshield_backend

## Executive Summary

**Total Bugs Discovered:** [N]
**Critical:** [N] - Immediate attention required
**High:** [N] - Fix in current sprint
**Medium:** [N] - Fix in next sprint
**Low:** [N] - Backlog

**Most Affected Areas:**
1. [Component] - [N bugs]
2. [Component] - [N bugs]
3. [Component] - [N bugs]

**Top Risk Categories:**
1. [Category] - [N CRITICAL bugs]
2. [Category] - [N HIGH bugs]

## Bug Category Breakdown

### Authentication & Security: [N bugs]
**CRITICAL:** [N]
**HIGH:** [N]
**MEDIUM:** [N]
**LOW:** [N]

**Highlights:**
- BUG-[ID]: [Most severe bug]
- BUG-[ID]: [Second most severe]

**Fix Estimation:** [X hours]
**Spec Location:** `.kiro/bugs/authentication-security/`

### Database Issues: [N bugs]
[Same structure]

### API Integration: [N bugs]
[Same structure]

## Critical Bugs Requiring Immediate Attention

### 1. BUG-[ID]: [Title]
**Severity:** CRITICAL
**File:** [filepath]
**Impact:** [Description]
**Exploit Risk:** HIGH
**Fix Complexity:** [Level]

### 2. BUG-[ID]: [Title]
[Same structure]

## Systemic Issues

### Pattern 1: [Pattern Name]
**Occurrences:** [N]
**Root Cause:** [Description]
**Fix Strategy:** [Approach]
**Affected Files:** [List]

### Pattern 2: [Pattern Name]
[Same structure]

## Code Quality Metrics

**Files Audited:** [N]
**Lines of Code Analyzed:** [N]
**Bug Density:** [Bugs per 1000 LOC]

**Quality Issues:**
- Missing error handling: [N instances]
- Missing type hints: [N instances]
- Missing docstrings: [N instances]
- Code duplication: [N instances]
- Complexity issues: [N functions]

## Testing Gaps

**Critical Paths Without Tests:**
1. [Path 1]
2. [Path 2]

**Missing Test Types:**
- Security tests: [N areas]
- Integration tests: [N areas]
- Performance tests: [N areas]

## Recommended Action Plan

### Immediate (This Week):
1. Fix all CRITICAL bugs
2. Deploy security patches
3. Add monitoring for vulnerable areas

### Short Term (This Sprint):
1. Fix all HIGH priority bugs
2. Add comprehensive tests
3. Implement missing security controls

### Medium Term (Next Sprint):
1. Fix MEDIUM priority bugs
2. Address systemic issues
3. Improve code quality

### Long Term (Backlog):
1. Fix LOW priority bugs
2. Refactor problematic areas
3. Technical debt reduction

## Risk Assessment

**Security Risk:** [HIGH/MEDIUM/LOW]
- [N] exploitable vulnerabilities
- [N] authentication/authorization issues
- [N] data exposure risks

**Stability Risk:** [HIGH/MEDIUM/LOW]
- [N] crash-inducing bugs
- [N] data corruption risks
- [N] race conditions

**Performance Risk:** [HIGH/MEDIUM/LOW]
- [N] performance-impacting bugs
- [N] resource leak issues
- [N] scalability concerns

## Effort Estimation

**Total Fix Effort:** [X hours]
- P0 (Critical): [X hours]
- P1 (High): [X hours]
- P2 (Medium): [X hours]
- P3 (Low): [X hours]

**Required Resources:**
- Backend developers: [N]
- Security specialist: [Y/N]
- Database expert: [Y/N]

**Timeline:**
- Week 1: Critical bugs
- Week 2-3: High priority
- Week 4+: Medium/Low priority

## Conclusion

[Summary of findings and recommendations]

## Appendices

### A. All Bugs by ID
[Complete list with links to bug files]

### B. Bugs by File
[Organized by file location]

### C. Bugs by Category
[Organized by bug category]
```

---

## Discovery Protocol Rules

### 🔴 MANDATORY REQUIREMENTS:

1. **NEVER skip any file** - Audit every Python file
2. **NEVER assume code is correct** - Verify every assumption
3. **NEVER fix bugs during discovery** - Only document
4. **ALWAYS create detailed bug reports** - Follow template exactly
5. **ALWAYS classify by severity** - Use consistent criteria
6. **ALWAYS generate Kiro specs** - For each bug category
7. **ALWAYS provide evidence** - Code snippets, line numbers
8. **ALWAYS assess impact** - Security, functional, business
9. **ALWAYS estimate fix effort** - Realistic time estimates
10. **ALWAYS maintain objectivity** - Facts over opinions

### 🟢 BEST PRACTICES:

1. **Start with high-risk areas** - Authentication, security first
2. **Look for patterns** - Systemic issues across codebase
3. **Consider edge cases** - Not just happy path
4. **Think like an attacker** - Security mindset
5. **Check error paths** - Exception handling
6. **Verify async correctness** - Race conditions, await usage
7. **Review database queries** - N+1, injection, performance
8. **Test integration points** - External services, APIs
9. **Examine configuration** - Environment variables, secrets
10. **Document everything** - Over-document rather than under

### 🟡 SEVERITY CRITERIA:

**CRITICAL (P0):**
- Security vulnerabilities allowing unauthorized access
- Data loss or corruption bugs
- Service crash or unavailability
- Authentication/authorization bypass
- Exploitable injection vulnerabilities

**HIGH (P1):**
- Security issues with high impact but low exploitability
- Significant functional failures
- Performance issues affecting all users
- Race conditions causing data inconsistency
- Missing critical error handling

**MEDIUM (P2):**
- Bugs affecting specific scenarios
- Performance issues affecting some users
- Code quality issues with potential impact
- Missing validation in non-critical paths
- Recoverable errors with poor UX

**LOW (P3):**
- Minor functional issues
- Code quality improvements
- Documentation gaps
- Minor performance optimizations
- Edge case bugs with minimal impact

---

## Communication Protocol

### Starting Discovery:

```
## Bug Discovery Audit Started

**Repository:** linkshield_backend
**Audit Date:** [Date]
**Scope:** Complete codebase

**Audit Plan:**
1. Setup and environment verification
2. Directory-by-directory audit
3. Bug classification and documentation
4. Kiro spec generation
5. Summary report creation

**Estimated Duration:** [X hours]

Beginning with: src/config/
```

### During Discovery:

```
## Auditing: src/authentication/auth_service.py

**Status:** [X/Y functions analyzed]

**Bugs Found So Far:**
- CRITICAL: [N]
- HIGH: [N]
- MEDIUM: [N]
- LOW: [N]

**Notable Findings:**
- BUG-[ID]: [Brief description]

Continuing...
```

### Bug Discovery:

```
## 🐛 BUG DISCOVERED: BUG-[ID]

**Severity:** CRITICAL
**Category:** Authentication & Security
**File:** src/authentication/auth_service.py:45

**Issue:** [One-line description]

**Evidence:**
```python
[Code snippet]
```

**Impact:** [Brief impact]

Full details documented in: .kiro/bugs/authentication-security/bugs/BUG-[ID].md
```

### Completing Directory:

```
## Completed: src/authentication/

**Files Audited:** [N]
**Bugs Found:** [N]
- CRITICAL: [N]
- HIGH: [N]
- MEDIUM: [N]
- LOW: [N]

**Top Issues:**
1. BUG-[ID]: [Description]
2. BUG-[ID]: [Description]

**Next:** src/security/
```

### Completing Audit:

```
## Bug Discovery Audit Complete

**Total Bugs:** [N]
**CRITICAL:** [N]
**HIGH:** [N]
**MEDIUM:** [N]
**LOW:** [N]

**Kiro Specs Generated:** [N categories]

**Top Priorities:**
1. [Bug category] - [N CRITICAL bugs]
2. [Bug category] - [N CRITICAL bugs]

**Summary Report:** .kiro/bug-summary.md

**Recommended Next Steps:**
1. Review all CRITICAL bugs
2. Prioritize fix order
3. Begin implementation following Kiro specs

Ready to proceed with fixes? (Requires separate debugging mission)
```

---

## Deliverables

Upon completion of bug discovery, you will have generated:

1. **Bug Reports:** Individual `.md` files for each bug
2. **Kiro Specs:** requirements.md, design.md, tasks.md for each bug category
3. **Bug Summary:** Comprehensive overview with metrics
4. **Fix Roadmap:** Prioritized action plan

All organized in `.kiro/bugs/` directory structure.

---

## Remember

This is **discovery only**. Your job is to find and document bugs systematically. Be thorough. Be precise. Be objective. The debugging phase will come later, guided by the Kiro specs you generate now.

**Leave no stone unturned. Every bug found now is one less production incident later.**