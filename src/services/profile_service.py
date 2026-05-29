"""Minimal profile resource loader for Cedar entity assembly."""


def get_profile_or_404(profile_id: str) -> dict:
    return {"uuid": profile_id}
