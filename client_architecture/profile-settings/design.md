Design: Profile & Account Settings

UI
- Profile page: display email, full_name, company, role, subscription, usage_stats.
- Preferences section: timezone, language, email_notifications, marketing_consent.
- Edit controls: inline editable fields or modal form.
- Change Password modal: current/new/confirm fields with strength meter.

Data Flow
- GET /profile → populate view.
- PUT /profile → update fields, optimistic UI.
- POST /change-password → validate and show success.

Components
- ProfileOverview, PreferencesForm, ChangePasswordModal, UsageStatsCards.

State
- Form state with validation; query cache for profile; optimistic update handling.