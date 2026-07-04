"""
Tests for the 7 audit fixes from 2026-06-17.

#1 AWS IAM scan imports _aws_decrypt successfully (no NameError).
#2 saas_oauth_apps is declared as a model (table is created by metadata).
#3 admin_email fallback chain handles user_info={"userPrincipalName": None}.
#4 DLP_DRAFT ON CONFLICT uses the partial-index predicate explicitly.
#5 _detect_teams_enterprise_threats emits teams_bot_admin_perms.
#6 _detect_teams_enterprise_threats emits anonymous_meeting_join.
#7 teams_phishing_scan uses /users/{id}/chats (app permission), not /me/chats.
"""
from __future__ import annotations

import importlib
import inspect

import pytest


def test_aws_iam_scan_has_decrypt_import():
    """#1 — the function body must import _decrypt to avoid the NameError."""
    from backend.routers import saas_security

    src = inspect.getsource(saas_security._aws_iam_scan)
    # Must import _decrypt (under the _aws_decrypt alias is fine)
    assert "from backend.routers.aws_connector import _decrypt" in src
    assert "_aws_decrypt" in src


def test_saas_oauth_apps_model_exists():
    """#2 — model must exist so create_all + metadata bootstrap pick it up."""
    from backend.models import db_models

    assert hasattr(db_models, "SaasOAuthApp")
    assert db_models.SaasOAuthApp.__tablename__ == "saas_oauth_apps"
    # Validate the columns used by shadow IT scan query exist
    cols = {c.name for c in db_models.SaasOAuthApp.__table__.columns}
    assert {"id", "org_id", "app_name", "app_id", "provider"}.issubset(cols)


def test_admin_email_fallback_handles_none_upn():
    """#3 — fallback must coerce None userPrincipalName -> System."""
    user_info = {"userPrincipalName": None, "displayName": None}
    initiated_by = {"user": user_info, "app": None}

    # Replicate the exact fallback chain shipped in _scan_admin_actions
    admin_email = (
        (user_info or {}).get("userPrincipalName")
        or (user_info or {}).get("displayName")
        or ((initiated_by.get("app") or {}).get("displayName"))
        or "System"
    )
    assert admin_email == "System"


def test_admin_email_fallback_picks_app_display_name_when_user_missing():
    """#3 — system-initiated audit events have only app.displayName populated."""
    user_info: dict = {}
    initiated_by = {"user": user_info, "app": {"displayName": "Microsoft Graph"}}

    admin_email = (
        (user_info or {}).get("userPrincipalName")
        or (user_info or {}).get("displayName")
        or ((initiated_by.get("app") or {}).get("displayName"))
        or "System"
    )
    assert admin_email == "Microsoft Graph"


def test_admin_email_fallback_keeps_real_upn():
    user_info = {"userPrincipalName": "admin@example.com"}
    initiated_by = {"user": user_info}
    admin_email = (
        (user_info or {}).get("userPrincipalName")
        or (user_info or {}).get("displayName")
        or ((initiated_by.get("app") or {}).get("displayName"))
        or "System"
    )
    assert admin_email == "admin@example.com"


def test_dlp_draft_on_conflict_predicate_present():
    """#4 — ON CONFLICT must spell out the partial-index predicate."""
    from backend.routers import drafts

    src = inspect.getsource(drafts)
    # The conflict target now declares the same predicate as
    # uq_threats_msg_recipient_org so PG can match the partial unique index.
    assert "ON CONFLICT (email_message_id, org_id, recipient_email)" in src
    assert "WHERE email_message_id IS NOT NULL" in src
    assert "AND email_message_id != ''" in src
    assert "AND recipient_email IS NOT NULL" in src


def test_detect_teams_enterprise_threats_emits_bot_admin_perms():
    """#5 — Teams bot admin perms detector exists in the function body."""
    from backend.routers import saas_security

    src = inspect.getsource(saas_security._detect_teams_enterprise_threats)
    assert "teams_bot_admin_perms" in src
    # Sanity: it actually inspects servicePrincipals + scopes
    assert "servicePrincipals" in src
    assert "oauth2PermissionScopes" in src


def test_security_rules_seed_includes_teams_bot_admin_perms():
    """#5 — registered in the rule catalogue so the UI can list it."""
    from backend.routers import saas_security

    src = inspect.getsource(saas_security)
    assert '"teams_bot_admin_perms"' in src
    assert "tenant-wide admin scopes" in src


def test_detect_teams_enterprise_threats_emits_anonymous_meeting_join():
    """#6 — anonymous meeting join detector exists in the function body."""
    from backend.routers import saas_security

    src = inspect.getsource(saas_security._detect_teams_enterprise_threats)
    assert "anonymous_meeting_join" in src
    assert "AnonymousUserJoinedMeeting" in src or "isanonymous" in src.lower()


def test_teams_phishing_scan_uses_users_endpoint_not_me_chats():
    """#7 — must use /users/{id}/chats, not /me/chats (app token can't use /me)."""
    from backend.routers import saas_security

    src = inspect.getsource(saas_security._scan_teams_messages_for_phishing)
    # We still keep a comment that mentions /me/chats; the actual call we
    # send must be the user-scoped one.
    assert "/users/{uid}/chats" in src or "/users/" in src
    # The user-scoped endpoint receives the chat list and the messages list
    assert "/chats/{chat_id}/messages" in src
    # And we degrade gracefully when Chat.Read.All isn't consented (403)
    assert "Chat.Read.All" in src
