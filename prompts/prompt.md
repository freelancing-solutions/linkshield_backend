I have the following verification comments after thorough review and exploration of the codebase. Implement the comments by following the instructions in the comments verbatim.

---
## Comment 1: BackgroundEmailService module referenced but missing, causing ImportError on startup.

Implement the missing `BackgroundEmailService` to match controller usage.

- Create file: `src/services/background_email_service.py`
- Implement class `BackgroundEmailService` with:
  - `__init__(self, email_service: EmailService)`
  - `queue_verification_email(self, email: str, first_name: str, token: str) -> None`
  - `queue_password_reset_email(self, email: str, first_name: str, token: str) -> None`
  - Internally use `asyncio.create_task` to call async helpers that use `EmailService.create_*` and `EmailService.send_email()`.
- Ensure imports in `src/services/depends.py`, `src/routes/user.py`, and `src/controllers/user_controller.py` resolve successfully.

### Referred Files
- e:\projects\linkshield_backend\src\services\depends.py
- e:\projects\linkshield_backend\src\routes\user.py
- e:\projects\linkshield_backend\src\controllers\user_controller.py
---
## Comment 2: DI design: service cannot access request-scoped BackgroundTasks; choose scheduling strategy.

Adopt a scheduling approach that fits the current DI:

- Prefer Option A now: keep `BackgroundEmailService.queue_*` signature as-is and schedule with `asyncio.create_task`.
- If choosing Option B later, update `UserController` to pass `background_tasks` into service methods and modify service to call `background_tasks.add_task(...)`.
- Add docstrings explaining the chosen approach to avoid confusion.

### Referred Files
- e:\projects\linkshield_backend\src\services\depends.py
- e:\projects\linkshield_backend\src\controllers\user_controller.py
- e:\projects\linkshield_backend\src\routes\user.py
---
## Comment 3: SMTP sending is synchronous; run blocking I/O in a thread for non-blocking background execution.

Update `EmailService._send_via_smtp` in `src/services/email_service.py` to offload blocking SMTP operations using `asyncio.to_thread` as per the example. Validate with a test send to ensure behavior is unchanged.

### Referred Files
- e:\projects\linkshield_backend\src\services\email_service.py
---


