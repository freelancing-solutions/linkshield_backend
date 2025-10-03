**Agentic Coder Prompt: API Documentation Update**

**Objective:**  
Update the API documentation to accurately reflect all current endpoints, parameters, request/response examples, and error codes. Ensure documentation is consistent, comprehensive, and aligns with the implemented API routes.

**Scope & Context:**  
- **API Routes Location:** `src/routes/` (review all route files to extract endpoint definitions)  
- **Existing Documentation:** `docs/api/` (update existing Markdown/AsciiDoc files; maintain current structure unless improvements are needed)  
- **Key Deliverables:**  
  1. **Endpoint Catalog:** List all active routes with methods (GET/POST/PUT/DELETE)  
  2. **Parameter Tables:** Document path/query/body parameters (include types, constraints, defaults)  
  3. **Request/Response Examples:** Add realistic payload/response examples (JSON)  
  4. **Error Coverage:** Document common HTTP status codes and error payloads  
  5. **Authentication:** Specify required auth methods per endpoint (if any)  

**Workflow Instructions:**  
1. **Code Analysis:**  
   - Parse `src/routes/` to identify all endpoint handlers and their method signatures  
   - Extract JSDoc/TSDoc comments if available for additional context  

2. **Documentation Audit:**  
   - Compare existing `docs/api/` files against discovered endpoints  
   - Flag outdated endpoints, parameters, or examples for revision  
   - Identify gaps where new endpoints lack documentation  

3. **Content Generation:**  
   - Maintain consistent formatting with existing documentation  
   - Use clear section headers and table structures for parameters  
   - Include code fences with language specification (e.g., ```json)  
   - Add deprecation notices for legacy endpoints if found in code comments  

4. **Validation Checks:**  
   - Ensure all path parameters match route definitions exactly  
   - Verify response examples match actual API return structures  
   - Cross-reference authentication requirements with security middleware  

**Success Criteria:**  
- [ ] Zero unregistered endpoints in implementation  
- [ ] All parameters documented with constraints/examples  
- [ ] Response schemas match actual API behavior  
- [ ] Error scenarios covered for each endpoint  
- [ ] Documentation passes `markdownlint`/formatting checks  

**Notes:**  
- Preserve existing documentation style and frontmatter where applicable  
- Flag any route handlers with unclear purpose for product owner review  
- Auto-generate where possible, but prioritize human-readable content  

**Output Destination:**  
Updated files in `docs/api/` with commit message: "docs(api): Synchronize documentation with current route implementations"  

Proceed when ready. Ask for clarification if route structures or documentation expectations are unclear.