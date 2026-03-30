# Sunbird RC Core - Comprehensive Code Review

**Date:** 2026-03-30
**Scope:** Full codebase security, architecture, and code quality review
**Repository:** sunbird-rc-core (Healthcare Provider Registry)

---

## Executive Summary

This review identified **50+ issues** across the Sunbird RC Core codebase spanning security vulnerabilities, code quality problems, infrastructure misconfigurations, and architectural concerns. The most critical findings involve **authentication bypasses**, **hardcoded secrets**, **SSRF vectors**, **injection vulnerabilities**, and **containers running as root with deprecated base images**.

| Severity | Count |
|----------|-------|
| CRITICAL | 12 |
| HIGH     | 25 |
| MEDIUM   | 18 |
| LOW      | 8 |

---

## 1. CRITICAL Security Vulnerabilities

### 1.1 Authentication Disabled by Default
**File:** `java/registry/src/main/resources/application.yml:224`
```yaml
authentication_enabled: false
```
Authentication is OFF by default. Any deployment that does not explicitly set this to `true` runs completely unauthenticated.

**File:** `java/registry/src/main/java/dev/sunbirdrc/registry/config/GenericConfiguration.java:208-228`
The authorization filter and interceptor beans are **entirely commented out**, meaning all endpoints are accessible without authentication regardless of configuration flags.

### 1.2 Hardcoded Secrets in Docker Compose and Application Config
**File:** `docker-compose.yml`
- Line 24: Postgres password: `postgres`
- Lines 59-60: Keycloak admin: `admin`/`admin`
- Line 40: SSO client secret: `0358fa30-6014-4192-9551-7c61b15b774c`
- Lines 108-109: MinIO credentials: `admin`/`12345678`

**File:** `java/registry/src/main/resources/application.yml`
- Line 217: Default client secret: `client_secret`
- Line 220: Default user password: `abcd@123`
- Lines 136-138: Default DB credentials: `postgres`/`postgres`

### 1.3 IDOR - Insecure Direct Object Reference
**File:** `RegistryEntityController.java:531-550`
The `getEntityForAttestation` endpoint reads entity data with an empty userId (`""`) and has **no authentication or authorization check**. Any caller can read any entity's attestation properties by guessing the entityId.

### 1.4 Authorization Bypass via Empty userId
**File:** `RegistryHelper.java:281-284`
```java
private boolean isOwner(JsonNode entity, String userId, String entityName) {
    return userId != null && (!entity.has(osOwner) || entity.get(osOwner).toString().contains(userId));
}
```
When `userId = ""`, Java's `String.contains("")` **always returns true**, so the ownership check passes for everyone. Multiple methods pass `""` as userId (lines 402, 489, 537), creating a systemic authorization bypass.

### 1.5 Unauthenticated Admin Endpoints
**File:** `RegistryEntityController.java:574-626`
- `/api/v1/system/{property}/{propertyId}` (updateProperty)
- `updateAttestationProperty`

These endpoints have **no authentication or authorization** and can update any property in the registry.

### 1.6 Commented-Out Authorization Check
**File:** `RegistryHelper.java:268-271`
An ownership check was **commented out** with a TODO. The `readEntity` method allows reading any entity even if the caller is not the owner.

### 1.7 JSON Injection in Search Queries
**File:** `RegistryHelper.java:897-906, 949-961`
Search queries are constructed via **string concatenation** with `entityName` and `userId` values. A crafted `entityName` like `foo", "evil": "true` would corrupt the JSON query structure.

### 1.8 Keycloak Public Key Returns Null on Failure
**File:** `KeyCloakServiceImpl.java:56-65`
`toPublicKey` returns `null` on error. A null signing key passed to token verification could **bypass signature validation** depending on the library's null-handling behavior.

### 1.9 CSRF Disabled
**File:** `SecurityConfig.java:54`
```java
http.csrf().disable()
```
CSRF protection is entirely disabled for all state-modifying endpoints.

### 1.10 Overly Permissive Security URL Patterns
**File:** `SecurityConfig.java:57-61`
```java
"/**/*.json"           // Any .json endpoint
"/**/attestation/**"   // Any attestation path
"/**/search"           // Any search endpoint
```
Double-wildcard patterns permit unauthenticated access to unintended endpoints.

### 1.11 Silent Partial Encryption
**File:** `PrivateField.java:127-129`
`EncryptionException` is swallowed mid-processing with `e.printStackTrace()`. Entities can be stored with **mixed plaintext/ciphertext fields** without any indication of failure.

### 1.12 Non-Thread-Safe HashMap in DefinitionsManager
**File:** `DefinitionsManager.java:25`
`definitionMap` is a plain `HashMap` mutated by `appendNewDefinition` and `removeDefinition` at runtime while concurrent readers access it. This causes `ConcurrentModificationException` or silent data corruption.

---

## 2. HIGH Severity Issues

### 2.1 SSRF Vulnerabilities (4 vectors)

| Location | Vector |
|----------|--------|
| `RegistryEntityController.java:409-430` | `Template` HTTP header URL fetched when `externalTemplatesEnabled=true` |
| `certificate-signer/signerController.js:9` | `credentialTemplate` URL from request body fetched without validation |
| `certificate-api/certificate_controller.js:209` | `templateUrl` fetched via `axios.get()` with no allowlist |
| `SignatureServiceImpl.java:116` | `keyId` concatenated into URL without encoding, enabling path traversal |

### 2.2 Handlebars Template Injection (2 services)
**Files:** `signerService.js:22,31` and `certificate_controller.js:229`
User-supplied data is passed directly into `Handlebars.compile()` and template execution. Known Handlebars prototype pollution CVEs (CVE-2021-23369, CVE-2021-23383) apply. Templates come from external URLs.

### 2.3 Chromium --no-sandbox with Untrusted Content
**File:** `certificate-api/certificate_controller.js:24,252`
Chromium runs with `--no-sandbox` and renders certificate HTML via `page.setContent(certificate)`. This is an **XSS-to-RCE** path. Combined with containers running as root, any Chromium exploit gains full container access.

### 2.4 Docker Containers Running as Root
**Files:** `Dockerfile` and `java/registry/Dockerfile`
Neither Dockerfile has a `USER` directive. Both use deprecated OpenJDK 8 Alpine base images with known CVEs.

### 2.5 Unpinned Docker Image Tags
**File:** `docker-compose.yml`
- `postgres` (no tag)
- `dockerhub/ndear-keycloak` (no tag)
- `quay.io/minio/minio` (no tag)
- `confluentinc/cp-kafka:latest`
- `confluentinc/cp-zookeeper:latest`

### 2.6 All Infrastructure Ports Exposed
**File:** `docker-compose.yml`
Elasticsearch (9200), Postgres (5432), Kafka (9092), Zookeeper (2181), MinIO (9000), Keycloak management (9990) are all bound to `0.0.0.0` with no authentication on most services.

### 2.7 Kafka PLAINTEXT Without Authentication
**File:** `docker-compose.yml:141`
Kafka listeners use PLAINTEXT protocol. Messages containing entity data travel unencrypted. Any network observer can read or inject messages on `create_entity` and `post_create_entity` topics.

### 2.8 CORS Wildcard Default
**File:** `application.yml:31`
```yaml
allowedOrigin: ${cors_allowedOrigin:*}
```
Default allows ALL origins for cross-origin requests.

### 2.9 Path Traversal in FileStorageService
**File:** `FileStorageService.java:90-99`
- `getDirectoryPath` splits URI on `/v1/` and uses the remainder as object path. `../../` sequences can traverse outside intended directories.
- `getFileName` appends `file.getOriginalFilename()` without sanitization. Path separators in filenames can escape the intended directory.
- No file type or size validation on uploads.

### 2.10 PII Logged at INFO Level
**File:** `KeycloakAdminUtil.java:67`
```java
logger.info("Creating user with mobile_number : " + userName)
```
Phone numbers logged in production. Also in `signerService.js:29` (full credential data logged) and `certificate_controller.js:173,193` (full request body logged).

### 2.11 Sensitive Crypto Data in Debug Logs
**File:** `EncryptionServiceImpl.java:78,102,131`
Plaintext and ciphertext values logged at DEBUG level. If debug logging is enabled in production, this leaks all encrypted field values.

### 2.12 No Authentication on Claim Endpoints
**File:** `ClaimsController.java:63-76`
The `save` endpoint (`POST /api/v1/claims`) and `attestClaims` have no authorization checks. Claims can be created and attested by any caller.

### 2.13 JWT Token Parsed Twice - Second Time Unsigned
**File:** `AuthorizationFilter.java:97-102`
After verifying JWT signature, the code manually Base64-decodes the payload separately. This anti-pattern discards the verified claims object and re-parses the raw token.

### 2.14 DefinitionsManager Mutates Internal Lists
**File:** `DefinitionsManager.java:150`
```java
internalFields.addAll(privateFields)
```
`getExcludingFields` permanently mutates the definition's internal field list by appending private fields. Every subsequent call accumulates duplicates.

### 2.15 Shared Default Password for All Users
**File:** `KeycloakAdminUtil.java:114-118`
When `setDefaultPassword` is enabled, all newly created Keycloak users receive the same password (`this.defaultPassword`).

---

## 3. MEDIUM Severity Issues

### 3.1 Error Handling Anti-Patterns

| File | Issue |
|------|-------|
| `RegistryEntityController.java:403,546,591` | `e.printStackTrace()` instead of logger |
| `RegistryClaimsController.java:69,83,87,181,203` | `e.printStackTrace()` throughout |
| `RegistryHelper.java:556-558` | File upload failures silently swallowed |
| `SchemaLoader.java:48` | `e.printStackTrace()` instead of logger |
| `GenericConfiguration.java:348-350` | `e.printStackTrace()` instead of logger |
| `FileStorageService.java:85,114,153` | `e.printStackTrace()` instead of logger |

### 3.2 NullPointerException Risks

| File | Issue |
|------|-------|
| `RegistryServiceImpl.java:218` | `tx.close()` in finally when `tx` may be null |
| `EncryptionServiceImpl.java:164` | `response.getBody().equalsIgnoreCase("UP")` - NPE if body null |
| `SignatureServiceImpl.java:41` | Same null body pattern |
| `RegistryClaimsController.java:100` | `requestBody.get("action")` may return null |
| `SchemaLoader.java:43-44` | No null check on search results |

### 3.3 HTTP Status Code Inconsistency
**File:** `RegistryController.java`
All endpoints return `HttpStatus.OK` (200) even on failure. Clients must parse response bodies to detect errors. Other controllers use 500 or 404 inconsistently.

### 3.4 Exception Messages Returned to Clients
Multiple endpoints set `e.getMessage()` in API responses, potentially leaking internal details (SQL errors, class names, stack frames).

### 3.5 No Input Size Limits
`@RequestBody JsonNode` has no size constraints across all controllers, enabling denial-of-service via large payloads.

### 3.6 No Rate Limiting
Search and read endpoints have no rate limiting, enabling enumeration attacks and data exfiltration.

### 3.7 Search Limit Too High
**File:** `application.yml:79`
`search_limit: 2000` allows large result sets. Combined with no rate limiting, this enables bulk data extraction.

### 3.8 Claims Authorization Based on Request Body
**File:** `ClaimService.java:71-73`
The `attestorNode` used for authorization is extracted from the request body (client-controlled) rather than server-side session/token data.

### 3.9 Infinite Recursion in FileStorageService
**File:** `FileStorageService.java:42-47`
If `isBucketExists()` returns false and `createNewBucket()` fails silently, `save()` calls itself recursively with no depth limit.

### 3.10 Resource Leak - MinIO InputStream
**File:** `FileStorageService.java:134-139`
`InputStream` from `minioClient.getObject()` is never closed, leaking connections. Also, `IOUtils.toByteArray()` reads entire files into memory.

---

## 4. LOW Severity Issues

### 4.1 Code Quality / Anti-Patterns

| Issue | Location |
|-------|----------|
| **God class** | `RegistryHelper.java` (981 lines, 50+ methods handling CRUD, auth, attestation, signing, notifications, file uploads, search) |
| **DAO not injected** | `RegistryServiceImpl.java:145,209,259` - `new RegistryDaoImpl(...)` defeats DI and testability |
| **Public fields** | `PrivateField.java:20,22`, `RegistryDaoImpl.java:19`, `NativeSearchService.java:64`, `AbstractController.java:46` |
| **Logger not final** | Multiple files: `RegistryServiceImpl`, `EncryptionServiceImpl`, etc. |
| **Typos in code** | `EncryptionServiceImpl`: "enryption", "dcryption"; `ClaimRequestClient`: "risen" vs "raised"; `ClaimsController`: `riseAttestation` vs `raiseAttestation`; `InvalidArguementException` (typo) |
| **Dead code** | `RegistryServiceImpl.java:291-303` - commented-out re-signing logic; `KeycloakAdminUtil.addUserToGroup()` never called |
| **Broken method** | `RegistryHelper.findAttestationPolicyByEntityAndCreatedBy:948` - calls search but returns `Collections.emptyList()` |
| **Stopwatch bugs** | `RegistryEntityController.java:86` - `watch.start()` called twice; line 239 - `watch.stop()` without matching start |

### 4.2 Deprecated Dependencies
- OpenJDK 8 Alpine (deprecated Docker image, JDK 8 past EOL)
- `frolvlad/alpine-java:jdk8-slim` (third-party, unvetted image)
- `Jwts.parser().setSigningKey()` API deprecated in modern jjwt
- `org.apache.commons.collections.map.HashedMap` (deprecated class in DefinitionsManager)

### 4.3 N+1 Query Pattern
**File:** `RegistryHelper.java:728`
`fetchFromDBUsingEsResponse` performs one database read per search result in a loop.

### 4.4 Missing Caching
**File:** `RegistryHelper.java:889`
`getAttestationPolicies` performs a search query on every call with a TODO comment about adding cache.

---

## 5. Architecture Concerns

### 5.1 Inconsistent Authorization Model
Some endpoints check ownership, some check roles, some check both, and some check nothing. There is no centralized authorization framework (e.g., Spring Security `@PreAuthorize`). Authorization logic is scattered across controllers, helpers, and services.

### 5.2 Async ES Indexing Without Reconciliation
**File:** `RegistryServiceImpl.java:353`
Elasticsearch indexing is `@Async` and fires after commit. If async indexing fails, the database and search index become silently out of sync with no retry or reconciliation mechanism.

### 5.3 Webhook Events Not Authenticated
**File:** `WebhookService.java`
No HMAC signature, API key, or other authentication is sent with webhook events. Receiving endpoints cannot verify authenticity, enabling spoofing.

### 5.4 No Graceful Degradation
- Encryption service failure silently produces mixed plaintext/ciphertext entities
- Search service partial failures are silently swallowed
- Delete operations succeed silently even when the target vertex is null

---

## 6. Prioritized Recommendations

### Immediate (P0 - Security Critical)
1. **Enable authentication by default** - change `authentication_enabled` to `true` and uncomment the authorization filter in `GenericConfiguration.java`
2. **Externalize all secrets** using Docker secrets, Vault, or environment variable injection - remove every hardcoded credential
3. **Fix the `isOwner` bypass** - replace `String.contains()` with exact match; never pass empty string as userId
4. **Add authorization to unauthenticated endpoints** - `updateProperty`, `updateAttestationProperty`, `getEntityForAttestation`, claim endpoints
5. **Fix JSON injection** - use ObjectMapper to build search queries instead of string concatenation
6. **Implement URL allowlisting** for template fetching in both JS services to prevent SSRF
7. **Enable Chromium sandbox** or run Puppeteer in a dedicated sandboxed container
8. **Fix DefinitionsManager thread safety** - use `ConcurrentHashMap` and immutable list copies

### Short-term (P1 - High Priority)
9. **Pin all Docker image tags** to specific versions/digests
10. **Add `USER` directives** to Dockerfiles to run as non-root
11. **Upgrade base images** from OpenJDK 8 to a supported LTS version (e.g., Eclipse Temurin 17/21)
12. **Remove host port bindings** for infrastructure services or bind to `127.0.0.1`
13. **Enable Kafka TLS and SASL authentication**
14. **Set CORS `allowedOrigin`** to specific domains
15. **Add input validation** - file size/type limits, search limit caps, entity name whitelisting
16. **Fix `PrivateField` exception handling** - propagate `EncryptionException` instead of swallowing
17. **Sanitize file names and paths** in `FileStorageService` to prevent path traversal

### Medium-term (P2 - Code Quality)
18. **Decompose `RegistryHelper`** God class into focused services (AuthorizationService, AttestationService, etc.)
19. **Inject DAOs via Spring DI** instead of `new RegistryDaoImpl()`
20. **Standardize error handling** - use proper logging instead of `printStackTrace()`, return appropriate HTTP status codes
21. **Add rate limiting** to search and read endpoints
22. **Implement webhook signing** (HMAC) for event authenticity
23. **Add ES reconciliation** mechanism for async indexing failures
24. **Fix all NullPointerException risks** documented above
25. **Remove dead code** and fix typos in exception/class names

---

*Review conducted against commit `1860abb` on branch `main`.*
